//! Client-side service discovery and replica load balancing.
//!
//! [`ServiceMesh`] reads `MINI_K8S_*` environment variables injected by
//! the orchestrator daemon and provides two routing strategies:
//!
//! - **Round-robin** ([`ServiceMesh::resolve`]): cycles across healthy replicas.
//! - **Latency-aware** ([`ServiceMesh::resolve_fastest`]): picks the replica
//!   with the lowest exponential moving average latency.
//!
//! After each request, call [`ServiceMesh::report`] to feed latency and
//! success/failure back into the health state.  A replica is marked
//! unhealthy after 3 consecutive failures and automatically recovers
//! when a future request succeeds.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

// EMA: new = old * (1 - α) + sample * α  where α = 0.3
const EMA_WEIGHT_OLD: u64 = 7; // 0.7 * 10
const EMA_WEIGHT_NEW: u64 = 3; // 0.3 * 10
const EMA_DENOM: u64 = 10;

/// Per-replica connection information and health counters.
pub struct ReplicaEndpoint {
    pub replica_index: u32,
    /// The address to connect to. Either a direct pod IP:80 (same subnet)
    /// or a proxy IP:port (cross-subnet, permitted by firewall).
    pub addr: SocketAddr,
    /// True when the route goes through the nginx proxy.
    pub via_proxy: bool,
    /// Exponential moving average of request latency in milliseconds.
    pub avg_latency_ms: AtomicU64,
    /// Resets to 0 on any successful request.  ≥ 3 → unhealthy.
    pub consecutive_failures: AtomicU32,
    pub total_requests: AtomicU64,
    pub total_failures: AtomicU64,
}

impl ReplicaEndpoint {
    fn new(replica_index: u32, addr: SocketAddr, via_proxy: bool) -> Self {
        Self {
            replica_index,
            addr,
            via_proxy,
            avg_latency_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
        }
    }

    /// A replica is healthy when it has fewer than 3 consecutive failures.
    pub fn is_healthy(&self) -> bool {
        self.consecutive_failures.load(Ordering::Relaxed) < 3
    }
}

/// A point-in-time snapshot of a single replica's health stats.
#[derive(Debug)]
pub struct RouteStatus {
    pub pod_name: String,
    pub replica_index: u32,
    pub addr: SocketAddr,
    pub via_proxy: bool,
    pub avg_latency_ms: u64,
    pub consecutive_failures: u32,
    pub total_requests: u64,
    pub total_failures: u64,
    pub healthy: bool,
}

/// Service mesh: routes requests to pod replicas with health tracking.
///
/// # Thread safety
/// All mutable state uses atomics so `resolve`, `report`, and `status`
/// can be called concurrently from any thread without locks.
pub struct ServiceMesh {
    /// pod_name → ordered list of replica endpoints.
    routes: HashMap<String, Vec<ReplicaEndpoint>>,
    /// Per-pod round-robin cursor.
    rr_counters: HashMap<String, AtomicUsize>,
    /// Proxy IP on this pod's subnet (the `MINI_K8S_PROXY` env var).
    pub proxy_addr: Option<String>,
    /// Our own identity (`MINI_K8S_SELF`, e.g., "pod-a-0").
    pub self_id: String,
}

impl ServiceMesh {
    /// Build the mesh by reading all `MINI_K8S_*` environment variables.
    ///
    /// Variables recognised:
    /// - `MINI_K8S_SELF`               — our own identity
    /// - `MINI_K8S_PROXY`              — proxy IP on our subnet
    /// - `MINI_K8S_POD_A_0=ip`         — direct IP for pod-a replica 0 (port 80)
    /// - `MINI_K8S_POD_A_0_VIA_PROXY=ip:port` — proxy-routed addr for pod-a replica 0
    /// - `MINI_K8S_POD_A_REPLICAS=N`   — ignored (only used by the daemon)
    pub fn from_env() -> Self {
        let self_id =
            std::env::var("MINI_K8S_SELF").unwrap_or_else(|_| "unknown".to_string());
        let proxy_addr = std::env::var("MINI_K8S_PROXY").ok();

        let mut routes: HashMap<String, Vec<ReplicaEndpoint>> = HashMap::new();

        for (key, val) in std::env::vars() {
            let Some(rest) = key.strip_prefix("MINI_K8S_") else {
                continue;
            };

            // Skip non-pod vars.
            if matches!(rest, "SELF" | "PROXY") || rest.ends_with("_REPLICAS") {
                continue;
            }

            // Decide whether this is a VIA_PROXY entry or a direct IP.
            let (pod_env_key, replica_str, via_proxy, addr_str) =
                if let Some(base) = rest.strip_suffix("_VIA_PROXY") {
                    match split_pod_replica(base) {
                        Some((pk, ri)) => (pk, ri, true, val),
                        None => continue,
                    }
                } else {
                    match split_pod_replica(rest) {
                        Some((pk, ri)) => {
                            // val is either a bare IP (single-node) or IP:port (cross-node).
                            let addr_str = if val.contains(':') {
                                val
                            } else {
                                format!("{}:80", val)
                            };
                            (pk, ri, false, addr_str)
                        }
                        None => continue,
                    }
                };

            let replica_index: u32 = match replica_str.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            let addr = match SocketAddr::from_str(&addr_str) {
                Ok(a) => a,
                Err(_) => continue,
            };

            let pod_name = env_key_to_pod_name(&pod_env_key);
            let replicas = routes.entry(pod_name).or_default();

            // Deduplicate: keep at most one entry per (replica_index, via_proxy) pair.
            let already_present = replicas
                .iter()
                .any(|r| r.replica_index == replica_index && r.via_proxy == via_proxy);
            if !already_present {
                replicas.push(ReplicaEndpoint::new(replica_index, addr, via_proxy));
            }
        }

        // Sort replicas by index for deterministic ordering.
        for replicas in routes.values_mut() {
            replicas.sort_by_key(|r| r.replica_index);
        }

        let mut rr_counters = HashMap::new();
        for pod_name in routes.keys() {
            rr_counters.insert(pod_name.clone(), AtomicUsize::new(0));
        }

        Self {
            routes,
            rr_counters,
            proxy_addr,
            self_id,
        }
    }

    /// Build the mesh by resolving pod names via DNS (cluster.local domain).
    ///
    /// For each pod name, resolves `{pod_name}.cluster.local:80` to get all IPs.
    /// No via_proxy — DNS-discovered endpoints are always direct.
    pub fn from_dns(pod_names: &[&str]) -> Self {
        let self_id =
            std::env::var("MINI_K8S_SELF").unwrap_or_else(|_| "unknown".to_string());
        let proxy_addr = std::env::var("MINI_K8S_PROXY").ok();

        let mut routes: HashMap<String, Vec<ReplicaEndpoint>> = HashMap::new();

        for &pod_name in pod_names {
            let hostname = format!("{}.cluster.local:80", pod_name);
            match hostname.to_socket_addrs() {
                Ok(addrs) => {
                    let endpoints: Vec<ReplicaEndpoint> = addrs
                        .enumerate()
                        .map(|(i, addr)| ReplicaEndpoint::new(i as u32, addr, false))
                        .collect();
                    if !endpoints.is_empty() {
                        routes.insert(pod_name.to_string(), endpoints);
                    }
                }
                Err(_) => {
                    // DNS resolution failed — pod not available
                }
            }
        }

        let mut rr_counters = HashMap::new();
        for pod_name in routes.keys() {
            rr_counters.insert(pod_name.clone(), AtomicUsize::new(0));
        }

        Self {
            routes,
            rr_counters,
            proxy_addr,
            self_id,
        }
    }

    /// Re-resolve all pod names via DNS and update routes.
    pub fn refresh_from_dns(&mut self) {
        let pod_names: Vec<String> = self.routes.keys().cloned().collect();

        for pod_name in &pod_names {
            let hostname = format!("{}.cluster.local:80", pod_name);
            match hostname.to_socket_addrs() {
                Ok(addrs) => {
                    let endpoints: Vec<ReplicaEndpoint> = addrs
                        .enumerate()
                        .map(|(i, addr)| ReplicaEndpoint::new(i as u32, addr, false))
                        .collect();
                    if !endpoints.is_empty() {
                        self.routes.insert(pod_name.clone(), endpoints);
                        self.rr_counters
                            .entry(pod_name.clone())
                            .or_insert_with(|| AtomicUsize::new(0));
                    }
                }
                Err(_) => {}
            }
        }
    }

    /// Round-robin across healthy replicas for `pod_name`.
    ///
    /// Returns `None` if the pod is unknown or all replicas are unhealthy.
    pub fn resolve(&self, pod_name: &str) -> Option<SocketAddr> {
        let replicas = self.routes.get(pod_name)?;
        let healthy: Vec<&ReplicaEndpoint> =
            replicas.iter().filter(|r| r.is_healthy()).collect();
        if healthy.is_empty() {
            return None;
        }
        let counter = self.rr_counters.get(pod_name)?;
        let idx = counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
        Some(healthy[idx].addr)
    }

    /// Latency-aware: pick the healthy replica with the lowest average latency.
    ///
    /// Replicas with no recorded latency (avg = 0) are ranked as medium-priority
    /// so initial traffic spreads naturally before measurements accumulate.
    pub fn resolve_fastest(&self, pod_name: &str) -> Option<SocketAddr> {
        let replicas = self.routes.get(pod_name)?;
        replicas
            .iter()
            .filter(|r| r.is_healthy())
            .min_by_key(|r| {
                let lat = r.avg_latency_ms.load(Ordering::Relaxed);
                // Untested replicas (0 ms) get a synthetic 50ms so they're tried
                // but don't unfairly beat already-fast tested replicas.
                if lat == 0 { 50 } else { lat }
            })
            .map(|r| r.addr)
    }

    /// Record the outcome of a request for health and latency tracking.
    ///
    /// - On success: resets `consecutive_failures`, updates the EMA latency.
    /// - On failure: increments `consecutive_failures` and `total_failures`.
    /// - Always: increments `total_requests`.
    pub fn report(&self, pod_name: &str, addr: SocketAddr, latency_ms: u64, success: bool) {
        let replicas = match self.routes.get(pod_name) {
            Some(r) => r,
            None => return,
        };
        let replica = match replicas.iter().find(|r| r.addr == addr) {
            Some(r) => r,
            None => return,
        };

        replica.total_requests.fetch_add(1, Ordering::Relaxed);

        if success {
            replica.consecutive_failures.store(0, Ordering::Relaxed);
            let old = replica.avg_latency_ms.load(Ordering::Relaxed);
            let new_avg = if old == 0 {
                latency_ms
            } else {
                (old * EMA_WEIGHT_OLD + latency_ms * EMA_WEIGHT_NEW) / EMA_DENOM
            };
            replica.avg_latency_ms.store(new_avg, Ordering::Relaxed);
        } else {
            replica.total_failures.fetch_add(1, Ordering::Relaxed);
            replica.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Snapshot of all route health for display purposes.
    pub fn status(&self) -> Vec<RouteStatus> {
        let mut pod_names: Vec<&String> = self.routes.keys().collect();
        pod_names.sort();
        let mut out = Vec::new();
        for pod_name in pod_names {
            for r in &self.routes[pod_name] {
                out.push(RouteStatus {
                    pod_name: pod_name.clone(),
                    replica_index: r.replica_index,
                    addr: r.addr,
                    via_proxy: r.via_proxy,
                    avg_latency_ms: r.avg_latency_ms.load(Ordering::Relaxed),
                    consecutive_failures: r.consecutive_failures.load(Ordering::Relaxed),
                    total_requests: r.total_requests.load(Ordering::Relaxed),
                    total_failures: r.total_failures.load(Ordering::Relaxed),
                    healthy: r.is_healthy(),
                });
            }
        }
        out
    }

    /// Sorted list of all reachable pod names.
    pub fn pods(&self) -> Vec<String> {
        let mut names: Vec<String> = self.routes.keys().cloned().collect();
        names.sort();
        names
    }

    /// Replicas for a given pod, or `None` if the pod is not reachable.
    pub fn replicas(&self, pod_name: &str) -> Option<&[ReplicaEndpoint]> {
        self.routes.get(pod_name).map(|v| v.as_slice())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Split `"POD_A_0"` into `("POD_A", "0")` by splitting at the last `_`
/// where the suffix is a numeric replica index.
fn split_pod_replica(s: &str) -> Option<(String, String)> {
    let pos = s.rfind('_')?;
    let suffix = &s[pos + 1..];
    if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
        Some((s[..pos].to_string(), suffix.to_string()))
    } else {
        None
    }
}

/// Convert an env-key pod name back to a pod name.
/// `"POD_A"` → `"pod-a"`, `"POD_LONG_NAME"` → `"pod-long-name"`.
fn env_key_to_pod_name(key: &str) -> String {
    key.to_lowercase().replace('_', "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_simple() {
        assert_eq!(
            split_pod_replica("POD_A_0"),
            Some(("POD_A".into(), "0".into()))
        );
    }

    #[test]
    fn split_hyphenated_pod() {
        assert_eq!(
            split_pod_replica("POD_LONG_NAME_3"),
            Some(("POD_LONG_NAME".into(), "3".into()))
        );
    }

    #[test]
    fn split_replicas_suffix_not_numeric() {
        // "POD_A_REPLICAS" — suffix is not numeric, should return None
        assert_eq!(split_pod_replica("POD_A_REPLICAS"), None);
    }

    #[test]
    fn env_key_round_trip() {
        assert_eq!(env_key_to_pod_name("POD_A"), "pod-a");
        assert_eq!(env_key_to_pod_name("POD_LONG_NAME"), "pod-long-name");
    }
}