use anyhow::Result;
use bollard::{exec::CreateExecOptions, Docker};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::signal;
use tracing::{debug, error, info, warn};
use std::sync::{Arc, Mutex};

use crate::{
    autoscaler::{Autoscaler, ScaleAction},
    dns::{generate_corefile, generate_zone_file},
    docker::{self, BackboneSpec},
    manifest::{FirewallMode, Manifest},
    node_pool::{host_port_for, NodePool},
    proxy::{compute_port_table, generate_proxy_config, minimal_proxy_config},
    registry::ServiceRegistry,
};

// ── Health check ─────────────────────────────────────────────────────────────

/// Poll a container's health by running `echo_server --health-check` inside it
/// via docker exec.  Works on macOS Docker Desktop because the exec runs inside
/// the container (127.0.0.1 always resolves), not from the macOS host.
///
/// Returns `true` once the probe exits with code 0, or `false` on timeout.
pub async fn wait_for_healthy(
    docker: &Docker,
    container_name: &str,
    timeout: Duration,
    interval: Duration,
) -> bool {
    let start = tokio::time::Instant::now();

    while start.elapsed() < timeout {
        tokio::time::sleep(interval).await;

        let exec = match docker
            .create_exec(
                container_name,
                CreateExecOptions {
                    cmd: Some(vec!["echo_server", "--health-check"]),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(e) => e,
            Err(_) => continue,
        };

        match docker.start_exec(&exec.id, None).await {
            Ok(bollard::exec::StartExecResults::Attached { mut output, .. }) => {
                while output.next().await.is_some() {}
            }
            Ok(bollard::exec::StartExecResults::Detached) => {}
            Err(_) => continue,
        }

        if let Ok(info) = docker.inspect_exec(&exec.id).await {
            if info.exit_code == Some(0) {
                return true;
            }
        }
    }

    false
}

// ── Image distribution ────────────────────────────────────────────────────────

/// Ship a locally-built Docker image to a remote node via `docker save | ssh docker load`.
/// No-op if `public_ip` is empty (single-node mode).
fn ship_image_to_node(image: &str, public_ip: &str, node_name: &str) -> Result<()> {
    if public_ip.is_empty() {
        return Ok(());
    }
    info!("Shipping image '{}' to {} ({})…", image, node_name, public_ip);

    let mut save = Command::new("docker")
        .args(["save", image])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let save_stdout = save.stdout.take().expect("piped stdout");

    let ssh_dest = format!("ubuntu@{}", public_ip);
    let status = Command::new("ssh")
        .args([
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15",
            &ssh_dest,
            "docker", "load",
        ])
        .stdin(save_stdout)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    save.wait().ok();

    if status.success() {
        info!("Image '{}' ready on {}", image, node_name);
        Ok(())
    } else {
        anyhow::bail!("Failed to ship image '{}' to {} ({})", image, node_name, public_ip)
    }
}

/// Ensure `image` is present on the node's Docker daemon.
/// If `inspect_image` returns 404, re-ships via SSH.
/// No-op when `public_ip` is empty (single-node / local Docker).
async fn ensure_image_on_node(
    node_docker: &Docker,
    image: &str,
    public_ip: &str,
    node_name: &str,
) -> Result<()> {
    if node_docker.inspect_image(image).await.is_ok() {
        return Ok(());
    }
    info!("Image '{}' not found on '{}'; shipping now…", image, node_name);
    ship_image_to_node(image, public_ip, node_name)
}

// ── Backbone IP allocation ────────────────────────────────────────────────────

/// Assign a backbone IP for a container given the subnet index.
pub fn assign_backbone_ip(
    subnet_name: &str,
    subnets: &[crate::manifest::Subnet],
    counters: &mut Vec<u8>,
) -> String {
    let idx = subnets
        .iter()
        .position(|s| s.name == subnet_name)
        .unwrap_or(0);

    while counters.len() <= idx {
        counters.push(2);
    }

    let host = counters[idx];
    counters[idx] = counters[idx].wrapping_add(1);

    format!("10.200.{}.{}", idx, host)
}

// ── Cluster startup ───────────────────────────────────────────────────────────

/// Start the cluster: create networks, launch pods and proxy, then run the reconciliation loop.
pub async fn run_daemon(manifest: Manifest) -> Result<()> {
    // ── Build NodePool ────────────────────────────────────────────────────────
    let pool = if manifest.cluster.nodes.is_empty() {
        NodePool::single(Docker::connect_with_local_defaults()?)
    } else {
        NodePool::multi(&manifest.cluster.nodes)?
    };
    let docker = pool.primary();
    let cluster = &manifest.cluster.name;
    let start_time = std::time::Instant::now();

    let dashboard_state = Arc::new(Mutex::new(
        crate::dashboard::empty_status(&manifest.cluster.name)
    ));

    let dash_state = dashboard_state.clone();
    tokio::spawn(async move {
        crate::dashboard::serve_dashboard(dash_state, 3030).await;
    });


    info!("Starting mini-k8s cluster: {}", cluster);
    if pool.is_multi() {
        info!(
            "Multi-node mode: {} nodes ({})",
            pool.len(),
            pool.entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", ")
        );
    }

    let use_iptables = manifest.cluster.firewall_mode == FirewallMode::Iptables;
    let use_dns = manifest.dns.as_ref().map(|d| d.enabled).unwrap_or(false);
    let mut backbone_counters: Vec<u8> = vec![2u8; manifest.subnets.len()];

    // ── Step 0 (multi-node): ship image to every node ─────────────────────────
    if pool.is_multi() {
        // Collect all unique images across pods.
        let images: std::collections::HashSet<&str> =
            manifest.pods.iter().map(|p| p.image.as_str()).collect();

        for image in &images {
            for entry in &pool.entries {
                if let Err(e) = ship_image_to_node(image, &entry.public_ip, &entry.name) {
                    warn!("Image pre-ship to '{}' failed (will retry on demand): {}", entry.name, e);
                }
            }
        }
    }

    // ── Step 1: Create networks (on every node in multi-node mode) ────────────
    info!("Creating {} network(s)…", manifest.subnets.len());
    for subnet in &manifest.subnets {
        if pool.is_multi() {
            for entry in &pool.entries {
                docker::create_network(&entry.docker, cluster, subnet).await?;
            }
        } else {
            docker::create_network(docker, cluster, subnet).await?;
        }
    }

    let backbone_network_name = format!("{}-backbone", cluster);
    if use_iptables {
        for entry in &pool.entries {
            docker::create_backbone_network(&entry.docker, cluster).await?;
        }
        info!("Backbone network '{}' ready on all nodes.", backbone_network_name);
    }
    info!("All networks ready.");

    // ── Step 2: Build initial (empty) registry ────────────────────────────────
    let mut registry = ServiceRegistry::new();

    // ── Step 3: Start proxy with a minimal config (on primary / node-1) ───────
    info!("Starting proxy container (minimal config)…");
    let all_network_names: Vec<String> = manifest
        .proxy
        .subnets
        .iter()
        .map(|s| format!("{}-{}", cluster, s))
        .collect();

    docker::create_proxy_container(
        docker,
        cluster,
        &manifest.proxy,
        &all_network_names,
        &minimal_proxy_config(),
    )
    .await?;

    // ── Step 3.5: Refresh registry to capture proxy IPs ──────────────────────
    registry.refresh(&pool, &manifest).await?;

    // ── Step 4: Start all pod containers (phase 1 — proxy IPs only) ──────────
    let total_replicas: u32 = manifest.pods.iter().map(|p| p.replicas).sum();
    info!(
        "Starting {} pod container(s) across {} pod spec(s) (phase 1)…",
        total_replicas,
        manifest.pods.len()
    );

    let mut pod_backbone_ips: HashMap<String, String> = HashMap::new();

    for (pod_idx, pod) in manifest.pods.iter().enumerate() {
        let network_name = format!("{}-{}", cluster, pod.subnet);
        for i in 0..pod.replicas {
            let node_entry = pool.node_for_replica(i);
            let node_docker = &node_entry.docker;
            let hp = pool.is_multi().then(|| host_port_for(pod_idx, i));
            let nn = pool.is_multi().then(|| node_entry.name.as_str());

            if let Err(e) = ensure_image_on_node(node_docker, &pod.image, &node_entry.public_ip, &node_entry.name).await {
                error!("Cannot ensure image on '{}': {}", node_entry.name, e);
                continue;
            }

            let env = registry.build_env_for_pod_v2(
                pod,
                i,
                &manifest.firewall,
                &manifest.pods,
                &manifest.subnets,
                &node_entry.name,
            );

            if use_iptables {
                let backbone_ip =
                    assign_backbone_ip(&pod.subnet, &manifest.subnets, &mut backbone_counters);
                let container_name = format!("{}-{}-{}", cluster, pod.name, i);
                pod_backbone_ips.insert(container_name, backbone_ip.clone());

                let backbone = Some(BackboneSpec {
                    network_name: backbone_network_name.clone(),
                    static_ip: backbone_ip,
                });
                if let Err(e) = docker::create_and_start_container_v2(
                    node_docker, cluster, pod, i, &network_name, env, backbone, &[], hp, nn,
                )
                .await
                {
                    error!("Failed to start {}-{}-{}: {}", cluster, pod.name, i, e);
                }
            } else {
                if let Err(e) = docker::create_and_start_container(
                    node_docker, cluster, pod, i, &network_name, env, hp, nn,
                )
                .await
                {
                    error!("Failed to start {}-{}-{}: {}", cluster, pod.name, i, e);
                }
            }
        }
    }

    // ── Step 5: Refresh registry with real IPs ────────────────────────────────
    registry.refresh(&pool, &manifest).await?;

    // ── Step 5.5: Apply iptables rules (primary node only) ───────────────────
    if use_iptables {
        info!("Applying iptables firewall rules…");
        let rules: Vec<(String, String)> = manifest
            .firewall
            .iter()
            .map(|rule| {
                let from_idx = manifest
                    .subnets
                    .iter()
                    .position(|s| s.name == rule.deny.from)
                    .unwrap_or(0);
                let to_idx = manifest
                    .subnets
                    .iter()
                    .position(|s| s.name == rule.deny.to)
                    .unwrap_or(0);
                (
                    format!("10.200.{}.0/24", from_idx),
                    format!("10.200.{}.0/24", to_idx),
                )
            })
            .collect();

        let rule_refs: Vec<(&str, &str)> =
            rules.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        if let Err(e) = docker::apply_iptables_rules(docker, cluster, &rule_refs).await {
            warn!("Failed to apply iptables rules: {}", e);
        }
    }

    // ── Step 5.6: Start DNS container if enabled ──────────────────────────────
    let mut dns_backbone_ip: Option<String> = None;
    if use_iptables && use_dns {
        if let Some(dns_spec) = &manifest.dns {
            let dns_ip = "10.200.255.2".to_string();
            dns_backbone_ip = Some(dns_ip.clone());

            let zone = generate_zone_file(cluster, &registry, &manifest.pods);
            let corefile = generate_corefile(cluster);

            match docker::create_dns_container(
                docker,
                cluster,
                &backbone_network_name,
                Some(&dns_ip),
                &zone,
                &corefile,
                &dns_spec.image,
            )
            .await
            {
                Ok(_) => info!("DNS container started with backbone IP {}", dns_ip),
                Err(e) => warn!("Failed to start DNS container: {}", e),
            }

            registry.refresh(&pool, &manifest).await?;
        }
    }

    // ── Step 6: Regenerate proxy config and reload ────────────────────────────
    let proxy_config =
        generate_proxy_config(&registry, &manifest.firewall, &manifest.pods, &manifest.subnets);
    info!(
        "Generated proxy config with {} route(s); reloading nginx…",
        proxy_config.matches("listen").count()
    );
    if let Err(e) = docker::reload_proxy(docker, cluster, &proxy_config).await {
        warn!("Initial proxy config reload failed (will retry): {}", e);
    }

    // ── Step 6.5: Re-launch pods with complete env vars (phase 2) ────────────
    info!(
        "Re-launching {} container(s) with complete service-discovery env vars (phase 2)…",
        total_replicas
    );
    for (pod_idx, pod) in manifest.pods.iter().enumerate() {
        let network_name = format!("{}-{}", cluster, pod.subnet);
        for i in 0..pod.replicas {
            let node_entry = pool.node_for_replica(i);
            let node_docker = &node_entry.docker;
            let hp = pool.is_multi().then(|| host_port_for(pod_idx, i));
            let nn = pool.is_multi().then(|| node_entry.name.as_str());

            if let Err(e) = ensure_image_on_node(node_docker, &pod.image, &node_entry.public_ip, &node_entry.name).await {
                error!("Cannot ensure image on '{}': {}", node_entry.name, e);
                continue;
            }

            let env = registry.build_env_for_pod_v2(
                pod,
                i,
                &manifest.firewall,
                &manifest.pods,
                &manifest.subnets,
                &node_entry.name,
            );

            if use_iptables {
                let container_name = format!("{}-{}-{}", cluster, pod.name, i);
                let backbone_ip = pod_backbone_ips
                    .get(&container_name)
                    .cloned()
                    .unwrap_or_else(|| {
                        assign_backbone_ip(&pod.subnet, &manifest.subnets, &mut backbone_counters)
                    });
                let dns_servers: Vec<String> =
                    dns_backbone_ip.iter().cloned().collect();
                let backbone = Some(BackboneSpec {
                    network_name: backbone_network_name.clone(),
                    static_ip: backbone_ip,
                });
                if let Err(e) = docker::create_and_start_container_v2(
                    node_docker, cluster, pod, i, &network_name, env, backbone, &dns_servers, hp, nn,
                )
                .await
                {
                    error!("Failed to re-launch {}-{}-{}: {}", cluster, pod.name, i, e);
                }
            } else {
                if let Err(e) = docker::create_and_start_container(
                    node_docker, cluster, pod, i, &network_name, env, hp, nn,
                )
                .await
                {
                    error!("Failed to re-launch {}-{}-{}: {}", cluster, pod.name, i, e);
                }
            }
        }
    }

    // ── Step 6.6: Final registry refresh and proxy reload ─────────────────────
    registry.refresh(&pool, &manifest).await?;
    let final_config =
        generate_proxy_config(&registry, &manifest.firewall, &manifest.pods, &manifest.subnets);
    info!(
        "Final proxy config has {} route(s); reloading nginx…",
        final_config.matches("listen").count()
    );
    if let Err(e) = docker::reload_proxy(docker, cluster, &final_config).await {
        warn!("Final proxy config reload failed: {}", e);
    }

    // ── Step 7: Reconciliation loop ───────────────────────────────────────────
    info!("Cluster '{}' is up. Entering reconciliation loop (5s).", cluster);

    let mut autoscaler = Autoscaler::new();
    for pod in &manifest.pods {
        autoscaler.init_pod(pod);
    }

    let mut interval = tokio::time::interval(Duration::from_secs(5));

    loop {
    tokio::select! {
        _ = interval.tick() => {
            if let Err(e) = reconcile(
                &pool,
                &manifest,
                &mut registry,
                &mut autoscaler,
                use_iptables,
                &backbone_network_name,
                &dns_backbone_ip,
                &mut backbone_counters,
            ).await {
                error!("Reconciliation error: {}", e);
            }

            // update dashboard after every reconcile
            let status = crate::dashboard::build_status(
                &manifest,
                &registry,
                start_time.elapsed().as_secs(),
            );
            *dashboard_state.lock().unwrap() = status;
        }
            _ = signal::ctrl_c() => {
                info!("Received Ctrl-C, shutting down. Run `mini-k8s down` to remove resources.");
                break;
            }
        }
    }

    Ok(())
}

// ── Reconciliation ────────────────────────────────────────────────────────────

/// One reconciliation pass: ensure all desired containers are running; restart any that aren't.
#[allow(clippy::too_many_arguments)]
async fn reconcile(
    pool: &NodePool,
    manifest: &Manifest,
    registry: &mut ServiceRegistry,
    autoscaler: &mut Autoscaler,
    use_iptables: bool,
    backbone_network_name: &str,
    dns_backbone_ip: &Option<String>,
    backbone_counters: &mut Vec<u8>,
) -> Result<()> {
    let cluster = &manifest.cluster.name;
    let docker = pool.primary();
    debug!("Reconciliation tick: scanning cluster '{}'…", cluster);

    // Collect running containers from ALL nodes.
    let mut running = Vec::new();
    for entry in &pool.entries {
        let node_containers = docker::list_cluster_containers(&entry.docker, cluster).await?;
        running.extend(node_containers);
    }

    let mut any_restarted = false;
    let mut missing_count = 0u32;

    // ── Check pods ────────────────────────────────────────────────────────────
    for (pod_idx, pod) in manifest.pods.iter().enumerate() {
        let network_name = format!("{}-{}", cluster, pod.subnet);

        let desired_replicas = autoscaler
            .current_replicas(&pod.name)
            .unwrap_or(pod.replicas);

        for i in 0..desired_replicas {
            let expected_name = format!("{}-{}-{}", cluster, pod.name, i);
            let is_running = running
                .iter()
                .any(|c| c.name == expected_name && c.is_running());

            if !is_running {
                missing_count += 1;
                warn!("Pod '{}' is not running — restarting.", expected_name);

                let node_entry = pool.node_for_replica(i);
                let node_docker = &node_entry.docker;
                let hp = pool.is_multi().then(|| host_port_for(pod_idx, i));
                let nn = pool.is_multi().then(|| node_entry.name.as_str());

                if let Err(e) = ensure_image_on_node(node_docker, &pod.image, &node_entry.public_ip, &node_entry.name).await {
                    error!("Cannot ensure image on '{}' for restart: {}", node_entry.name, e);
                    continue;
                }

                let _ = docker::remove_container(node_docker, &expected_name).await;

                let env = registry.build_env_for_pod_v2(
                    pod,
                    i,
                    &manifest.firewall,
                    &manifest.pods,
                    &manifest.subnets,
                    &node_entry.name,
                );

                let restart_result = if use_iptables {
                    let backbone_ip =
                        assign_backbone_ip(&pod.subnet, &manifest.subnets, backbone_counters);
                    let dns_servers: Vec<String> = dns_backbone_ip.iter().cloned().collect();
                    let backbone = Some(BackboneSpec {
                        network_name: backbone_network_name.to_string(),
                        static_ip: backbone_ip,
                    });
                    docker::create_and_start_container_v2(
                        node_docker, cluster, pod, i, &network_name, env, backbone, &dns_servers,
                        hp, nn,
                    )
                    .await
                } else {
                    docker::create_and_start_container(
                        node_docker, cluster, pod, i, &network_name, env, hp, nn,
                    )
                    .await
                };

                match restart_result {
                    Ok(_) => {
                        info!("Restarted '{}'.", expected_name);
                        any_restarted = true;

                        let healthy = wait_for_healthy(
                            node_docker,
                            &expected_name,
                            Duration::from_secs(10),
                            Duration::from_millis(500),
                        )
                        .await;
                        if healthy {
                            info!("'{}' passed health check after restart.", expected_name);
                        } else {
                            warn!("'{}' did not become healthy within timeout.", expected_name);
                        }
                    }
                    Err(e) => {
                        error!("Failed to restart '{}': {}", expected_name, e);
                    }
                }
            }
        }
    }

    // ── Check proxy ───────────────────────────────────────────────────────────
    let proxy_name = format!("{}-proxy", cluster);
    let proxy_running = running
        .iter()
        .any(|c| c.name == proxy_name && c.is_running());

    if !proxy_running {
        warn!("Proxy '{}' is not running — restarting.", proxy_name);

        let all_network_names: Vec<String> = manifest
            .proxy
            .subnets
            .iter()
            .map(|s| format!("{}-{}", cluster, s))
            .collect();

        let proxy_config = generate_proxy_config(
            registry,
            &manifest.firewall,
            &manifest.pods,
            &manifest.subnets,
        );

        match docker::create_proxy_container(
            docker,
            cluster,
            &manifest.proxy,
            &all_network_names,
            &proxy_config,
        )
        .await
        {
            Ok(_) => {
                info!("Restarted proxy.");
                any_restarted = true;
            }
            Err(e) => error!("Failed to restart proxy: {}", e),
        }
    }

    if missing_count == 0 {
        let total: u32 = manifest.pods.iter().map(|p| p.replicas).sum();
        debug!("All {} pod replica(s) + proxy healthy.", total + 1);
    }

    // ── Refresh registry ──────────────────────────────────────────────────────
    registry.refresh(pool, manifest).await?;

    if any_restarted {
        let proxy_config = generate_proxy_config(
            registry,
            &manifest.firewall,
            &manifest.pods,
            &manifest.subnets,
        );
        if let Err(e) = docker::reload_proxy(docker, cluster, &proxy_config).await {
            warn!("Failed to reload proxy after restart: {}", e);
        }
    }

    // ── Autoscaler evaluation ─────────────────────────────────────────────────
    let scale_actions = autoscaler
        .evaluate(pool, &manifest.pods, registry, cluster)
        .await;

    for action in scale_actions {
        match action {
            ScaleAction::ScaleUp { pod: pod_name, old_count, new_count } => {
                if let Some(pod_spec) = manifest.pods.iter().find(|p| p.name == pod_name) {
                    let pod_idx = manifest.pods.iter().position(|p| p.name == pod_name).unwrap_or(0);
                    for i in old_count..new_count {
                        let network_name = format!("{}-{}", cluster, pod_spec.subnet);
                        let node_entry = pool.node_for_replica(i);
                        let node_docker = &node_entry.docker;
                        let hp = pool.is_multi().then(|| host_port_for(pod_idx, i));
                        let nn = pool.is_multi().then(|| node_entry.name.as_str());

                        if let Err(e) = ensure_image_on_node(node_docker, &pod_spec.image, &node_entry.public_ip, &node_entry.name).await {
                            error!("Cannot ensure image on '{}' for scale-up: {}", node_entry.name, e);
                            continue;
                        }

                        let env = registry.build_env_for_pod_v2(
                            pod_spec,
                            i,
                            &manifest.firewall,
                            &manifest.pods,
                            &manifest.subnets,
                            &node_entry.name,
                        );
                        let result = if use_iptables {
                            let backbone_ip = assign_backbone_ip(
                                &pod_spec.subnet,
                                &manifest.subnets,
                                backbone_counters,
                            );
                            let dns_servers: Vec<String> =
                                dns_backbone_ip.iter().cloned().collect();
                            let backbone = Some(BackboneSpec {
                                network_name: backbone_network_name.to_string(),
                                static_ip: backbone_ip,
                            });
                            docker::create_and_start_container_v2(
                                node_docker, cluster, pod_spec, i, &network_name, env, backbone,
                                &dns_servers, hp, nn,
                            )
                            .await
                        } else {
                            docker::create_and_start_container(
                                node_docker, cluster, pod_spec, i, &network_name, env, hp, nn,
                            )
                            .await
                        };
                        match result {
                            Ok(_) => info!("Scale-up: started {}-{}-{}", cluster, pod_name, i),
                            Err(e) => error!(
                                "Scale-up failed for {}-{}-{}: {}",
                                cluster, pod_name, i, e
                            ),
                        }
                    }
                }
            }
            ScaleAction::ScaleDown { pod: pod_name, old_count, new_count } => {
                for i in new_count..old_count {
                    let container_name = format!("{}-{}-{}", cluster, pod_name, i);
                    let node_docker = &pool.node_for_replica(i).docker;
                    if let Err(e) =
                        docker::remove_container(node_docker, &container_name).await
                    {
                        error!("Scale-down: failed to remove {}: {}", container_name, e);
                    } else {
                        info!("Scale-down: removed {}", container_name);
                        any_restarted = true; // trigger proxy reload below
                    }
                }
            }
        }
    }

    // Reload proxy if any scale-down removed containers (to drop them from upstreams).
    if any_restarted {
        registry.refresh(pool, manifest).await?;
        let proxy_config = generate_proxy_config(
            registry,
            &manifest.firewall,
            &manifest.pods,
            &manifest.subnets,
        );
        if let Err(e) = docker::reload_proxy(docker, cluster, &proxy_config).await {
            warn!("Failed to reload proxy after scale change: {}", e);
        }
    }

    Ok(())
}

// ── Teardown ──────────────────────────────────────────────────────────────────

/// Tear down the cluster: remove all containers and networks on all nodes.
pub async fn teardown(manifest: &Manifest) -> Result<()> {
    let pool = if manifest.cluster.nodes.is_empty() {
        NodePool::single(Docker::connect_with_local_defaults()?)
    } else {
        NodePool::multi(&manifest.cluster.nodes)?
    };
    let cluster = &manifest.cluster.name;

    info!("Tearing down cluster '{}'.", cluster);

    for entry in &pool.entries {
        let containers = docker::list_cluster_containers(&entry.docker, cluster).await?;
        for container in &containers {
            docker::remove_container(&entry.docker, &container.name).await?;
        }
        if !containers.is_empty() {
            info!("Removed {} container(s) from '{}'.", containers.len(), entry.name);
        }
    }

    // Remove networks from all nodes.
    for subnet in &manifest.subnets {
        let network_name = format!("{}-{}", cluster, subnet.name);
        if pool.is_multi() {
            for entry in &pool.entries {
                docker::remove_network(&entry.docker, &network_name).await?;
            }
        } else {
            docker::remove_network(pool.primary(), &network_name).await?;
        }
    }
    info!("Removed {} network(s).", manifest.subnets.len());

    let backbone_network_name = format!("{}-backbone", cluster);
    for entry in &pool.entries {
        docker::remove_network(&entry.docker, &backbone_network_name).await?;
    }

    info!("Teardown complete.");
    Ok(())
}

// ── Status ────────────────────────────────────────────────────────────────────

/// Print a status table of all cluster containers.
pub async fn status(manifest: &Manifest) -> Result<()> {
    let pool = if manifest.cluster.nodes.is_empty() {
        NodePool::single(Docker::connect_with_local_defaults()?)
    } else {
        NodePool::multi(&manifest.cluster.nodes)?
    };
    let cluster = &manifest.cluster.name;

    // Collect containers from all nodes.
    let mut containers = Vec::new();
    for entry in &pool.entries {
        let node_containers = docker::list_cluster_containers(&entry.docker, cluster).await?;
        containers.extend(node_containers);
    }

    let by_name: HashMap<String, &docker::ContainerInfo> =
        containers.iter().map(|c| (c.name.clone(), c)).collect();

    let port_table = compute_port_table(&manifest.subnets, &manifest.pods, &manifest.firewall);

    let node_col = if pool.is_multi() { 10 } else { 0 };
    println!(
        "{:<36} {:<12} {:<14} {:<18} {:<node_col$} {}",
        "CONTAINER", "STATE", "SUBNET", "IP", if pool.is_multi() { "NODE" } else { "" }, "PROXY PORTS (src→port)",
        node_col = node_col,
    );
    println!("{}", "─".repeat(if pool.is_multi() { 105 } else { 95 }));

    for pod in &manifest.pods {
        for i in 0..pod.replicas {
            let cname = format!("{}-{}-{}", cluster, pod.name, i);
            let (state, ip, node_label) = match by_name.get(&cname) {
                Some(c) => {
                    let ip = ServiceRegistry::get_ip_on_subnet(&c.networks, &pod.subnet)
                        .cloned()
                        .unwrap_or_else(|| "-".to_string());
                    let node = c.labels.get("mini-k8s.node").cloned().unwrap_or_default();
                    (c.state.clone(), ip, node)
                }
                None => ("missing".to_string(), "-".to_string(), "-".to_string()),
            };

            let mut proxy_ports: Vec<String> = manifest
                .subnets
                .iter()
                .filter(|s| s.name != pod.subnet)
                .filter_map(|src| {
                    let key = (src.name.clone(), pod.name.clone(), i);
                    port_table.get(&key).map(|&p| format!("{}→:{}", src.name, p))
                })
                .collect();
            proxy_ports.sort();
            let proxy_info = if proxy_ports.is_empty() {
                "-".to_string()
            } else {
                proxy_ports.join("  ")
            };

            if pool.is_multi() {
                println!(
                    "{:<36} {:<12} {:<14} {:<18} {:<node_col$} {}",
                    cname, state, pod.subnet, ip, node_label, proxy_info,
                    node_col = node_col,
                );
            } else {
                println!(
                    "{:<36} {:<12} {:<14} {:<18} {}",
                    cname, state, pod.subnet, ip, proxy_info
                );
            }
        }
    }

    println!("{}", "─".repeat(if pool.is_multi() { 105 } else { 95 }));
    let proxy_name = format!("{}-proxy", cluster);
    let (proxy_state, proxy_ips) = match by_name.get(&proxy_name) {
        Some(c) => {
            let mut ips: Vec<String> = c
                .networks
                .iter()
                .map(|(net, ip)| format!("{}={}", net, ip))
                .collect();
            ips.sort();
            (c.state.clone(), ips.join("  "))
        }
        None => ("missing".to_string(), "-".to_string()),
    };
    println!(
        "{:<36} {:<12} {:<14} {}",
        proxy_name, proxy_state, "(all subnets)", proxy_ips
    );

    Ok(())
}