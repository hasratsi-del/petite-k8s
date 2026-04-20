//! Autoscaler: evaluates pod metrics and recommends scale actions.

use std::collections::HashMap;
use std::time::Instant;

use bollard::{exec::CreateExecOptions, Docker};
use futures_util::StreamExt;
use tracing::{debug, info};

use crate::manifest::PodSpec;
use crate::node_pool::NodePool;
use crate::registry::ServiceRegistry;

/// State tracked per pod for autoscaling decisions.
pub struct AutoscaleState {
    pub current_replicas: u32,
    pub last_scale_up: Instant,
    pub last_scale_down: Instant,
}

impl AutoscaleState {
    pub fn new(current_replicas: u32) -> Self {
        // Initialize with a very old instant so cooldowns don't block initial scaling
        let epoch = Instant::now();
        Self {
            current_replicas,
            last_scale_up: epoch,
            last_scale_down: epoch,
        }
    }
}

/// Actions the autoscaler can recommend.
#[derive(Debug, Clone)]
pub enum ScaleAction {
    ScaleUp { pod: String, old_count: u32, new_count: u32 },
    ScaleDown { pod: String, old_count: u32, new_count: u32 },
}

/// Main autoscaler struct.
pub struct Autoscaler {
    state: HashMap<String, AutoscaleState>,
}

impl Autoscaler {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
    }

    /// Initialize or update state for a pod from its manifest spec.
    pub fn init_pod(&mut self, pod: &PodSpec) {
        self.state
            .entry(pod.name.clone())
            .or_insert_with(|| AutoscaleState::new(pod.replicas));
    }

    /// Evaluate all autoscalable pods and return recommended actions.
    pub async fn evaluate(
        &mut self,
        pool: &NodePool,
        manifest_pods: &[PodSpec],
        registry: &ServiceRegistry,
        _cluster: &str,
    ) -> Vec<ScaleAction> {
        let mut actions = Vec::new();

        for pod in manifest_pods {
            let autoscale = match &pod.autoscale {
                Some(a) => a,
                None => continue,
            };

            let state = self.state.entry(pod.name.clone()).or_insert_with(|| AutoscaleState::new(pod.replicas));

            let current_replicas = state.current_replicas;
            let target_rps = autoscale.target_rps as f64;
            let max_replicas = autoscale.max_replicas;
            let min_replicas = pod.replicas; // manifest minimum
            let scale_up_cooldown = autoscale.scale_up_cooldown;
            let scale_down_cooldown = autoscale.scale_down_cooldown;

            // Fetch metrics from all running replicas via docker exec.
            let mut total_rps = 0.0f64;
            let mut fetched = 0u32;

            if let Some(replicas) = registry.entries.get(&pod.name) {
                for replica in replicas {
                    // Use the Docker client for the node this replica is on.
                    let docker = pool
                        .get(&replica.node_name)
                        .map(|e| &e.docker)
                        .unwrap_or_else(|| pool.primary());
                    if let Some(rps) = fetch_metrics_via_exec(docker, &replica.container_name).await {
                        total_rps += rps;
                        fetched += 1;
                    }
                }
            }

            if fetched == 0 {
                debug!("No metrics fetched for pod '{}', skipping autoscale evaluation", pod.name);
                continue;
            }

            let now = Instant::now();

            // Scale up check
            if total_rps > target_rps * current_replicas as f64 * 1.2
                && current_replicas < max_replicas
                && now.duration_since(state.last_scale_up).as_secs() >= scale_up_cooldown
            {
                let new_count = (current_replicas + 1).min(max_replicas);
                info!(
                    "Autoscaler: scale UP pod '{}' {} -> {} (total_rps={:.2}, target={})",
                    pod.name, current_replicas, new_count, total_rps, target_rps
                );
                // Update state AFTER recording old_count so the handler has both.
                state.current_replicas = new_count;
                state.last_scale_up = now;
                actions.push(ScaleAction::ScaleUp {
                    pod: pod.name.clone(),
                    old_count: current_replicas,
                    new_count,
                });
            }
            // Scale down check
            else if total_rps < target_rps * current_replicas as f64 * 0.5
                && current_replicas > min_replicas
                && now.duration_since(state.last_scale_down).as_secs() >= scale_down_cooldown
            {
                let new_count = (current_replicas - 1).max(min_replicas);
                info!(
                    "Autoscaler: scale DOWN pod '{}' {} -> {} (total_rps={:.2}, target={})",
                    pod.name, current_replicas, new_count, total_rps, target_rps
                );
                // Update state AFTER recording old_count so the handler has both.
                state.current_replicas = new_count;
                state.last_scale_down = now;
                actions.push(ScaleAction::ScaleDown {
                    pod: pod.name.clone(),
                    old_count: current_replicas,
                    new_count,
                });
            }
        }

        actions
    }

    /// Get current replica count for a pod.
    pub fn current_replicas(&self, pod_name: &str) -> Option<u32> {
        self.state.get(pod_name).map(|s| s.current_replicas)
    }
}

/// Run `echo_server --metrics` inside the container via docker exec, capture
/// its stdout (the JSON body), and parse `requests_per_second`.
///
/// Works on macOS Docker Desktop because the exec runs inside the container
/// where 127.0.0.1 always resolves — no host→container TCP needed.
async fn fetch_metrics_via_exec(docker: &Docker, container_name: &str) -> Option<f64> {
    let exec = docker
        .create_exec(
            container_name,
            CreateExecOptions {
                cmd: Some(vec!["echo_server", "--metrics"]),
                attach_stdout: Some(true),
                attach_stderr: Some(false),
                ..Default::default()
            },
        )
        .await
        .ok()?;

    let mut stdout_bytes = Vec::new();
    match docker.start_exec(&exec.id, None).await.ok()? {
        bollard::exec::StartExecResults::Attached { mut output, .. } => {
            while let Some(chunk) = output.next().await {
                if let Ok(bollard::container::LogOutput::StdOut { message }) = chunk {
                    stdout_bytes.extend_from_slice(&message);
                }
            }
        }
        bollard::exec::StartExecResults::Detached => return None,
    }

    let body = String::from_utf8_lossy(&stdout_bytes);
    if body.is_empty() {
        debug!("fetch_metrics_via_exec: empty stdout from {}", container_name);
        return None;
    }
    parse_rps_from_json(&body)
}

fn parse_rps_from_json(json: &str) -> Option<f64> {
    // Simple manual parse: find "requests_per_second": <number>
    let key = "\"requests_per_second\"";
    let pos = json.find(key)?;
    let after_key = &json[pos + key.len()..];
    // Find the colon
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    // Read digits/decimal
    let end = after_colon
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-' && c != 'e' && c != 'E' && c != '+')
        .unwrap_or(after_colon.len());
    let num_str = &after_colon[..end];
    num_str.parse::<f64>().ok()
}