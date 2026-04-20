use std::collections::HashMap;

use crate::{
    firewall::can_communicate_directly,
    manifest::{FirewallRule, PodSpec, Subnet},
    registry::ServiceRegistry,
};

/// The base port for dynamically assigned proxy listen ports.
pub const PROXY_BASE_PORT: u16 = 9000;

/// Key into the port table: (source_subnet_name, target_pod_name, target_replica_index).
///
/// A single port serves exactly one (source subnet → target pod replica) path.  This lets the
/// nginx config precisely exclude any path blocked by a deny rule, and lets env-var generation
/// look up the right port for the caller's own subnet.
pub type PortKey = (String, String, u32);

/// Compute the global port table.
///
/// For every ordered pair (source_subnet, target_pod_replica) where:
///   - source_subnet != target_pod.subnet  (different subnets need the proxy)
///   - no deny rule from source_subnet to target_pod.subnet  (allowed path)
///
/// assign a deterministic listen port.  The iteration order is:
///   source subnets (manifest order) × pods (manifest order) × replicas (ascending)
///
/// This is the single source of truth consumed by both `compute_proxy_routes` (nginx config)
/// and `build_env_for_pod_v2` (env vars).  As long as callers use the same (all_subnets,
/// all_pods, firewall_rules) slice from the manifest, ports are always consistent.
pub fn compute_port_table(
    all_subnets: &[Subnet],
    all_pods: &[PodSpec],
    firewall_rules: &[FirewallRule],
) -> HashMap<PortKey, u16> {
    let mut table = HashMap::new();
    let mut port = PROXY_BASE_PORT;

    for source_subnet in all_subnets {
        for target_pod in all_pods {
            // Same subnet — pods communicate directly, no proxy needed.
            if source_subnet.name == target_pod.subnet {
                continue;
            }
            // Deny rule exists — this path is blocked even through the proxy.
            if !can_communicate_directly(
                &source_subnet.name,
                &target_pod.subnet,
                firewall_rules,
            ) {
                continue;
            }
            for ri in 0..target_pod.replicas {
                table.insert(
                    (source_subnet.name.clone(), target_pod.name.clone(), ri),
                    port,
                );
                port += 1;
            }
        }
    }

    table
}

/// Describes a single proxy route: listen on `listen_port`, forward to `upstream_ip:upstream_port`.
#[derive(Debug, Clone)]
pub struct ProxyRoute {
    /// Unique nginx upstream name — incorporates source subnet to avoid collisions.
    pub upstream_name: String,
    pub listen_port: u16,
    pub upstream_ip: String,
    pub upstream_port: u16,
}

/// Compute all live proxy routes from the current port table and registry state.
///
/// Iterates the port table and resolves each target pod replica's actual IP from the registry.
/// If a replica isn't running yet its port slot is reserved but no route block is emitted
/// (nginx would fail to start if an upstream has no servers).
pub fn compute_proxy_routes(
    registry: &ServiceRegistry,
    all_subnets: &[Subnet],
    all_pods: &[PodSpec],
    firewall_rules: &[FirewallRule],
) -> Vec<ProxyRoute> {
    let port_table = compute_port_table(all_subnets, all_pods, firewall_rules);
    let mut routes = Vec::new();

    // Emit routes in deterministic port order.
    let mut sorted: Vec<(&PortKey, &u16)> = port_table.iter().collect();
    sorted.sort_by_key(|(_, &port)| port);

    for ((source_subnet, pod_name, ri), &listen_port) in sorted {
        // Find the pod spec to know its own subnet.
        let target_pod = match all_pods.iter().find(|p| &p.name == pod_name) {
            Some(p) => p,
            None => continue,
        };

        // Single-node: Docker IP on the pod's subnet, port 80.
        // Multi-node: node private IP + published host port.
        if let Some((ip, port)) =
            registry.upstream_for(pod_name, *ri, &target_pod.subnet)
        {
            let upstream_name = format!("{source_subnet}--{pod_name}-{ri}");
            routes.push(ProxyRoute {
                upstream_name,
                listen_port,
                upstream_ip: ip,
                upstream_port: port,
            });
        }
    }

    routes
}

/// Generate a full nginx.conf for TCP stream proxying.
pub fn generate_proxy_config(
    registry: &ServiceRegistry,
    firewall_rules: &[FirewallRule],
    all_pods: &[PodSpec],
    all_subnets: &[Subnet],
) -> String {
    let routes = compute_proxy_routes(registry, all_subnets, all_pods, firewall_rules);

    if routes.is_empty() {
        return minimal_proxy_config();
    }

    let mut config = String::from(
        "worker_processes 1;\nevents { worker_connections 1024; }\n\nstream {\n",
    );

    for route in &routes {
        config.push_str(&format!(
            "    upstream {} {{\n        server {}:{};\n    }}\n\n",
            route.upstream_name, route.upstream_ip, route.upstream_port
        ));
        config.push_str(&format!(
            "    server {{\n        listen {};\n        proxy_pass {};\n    }}\n\n",
            route.listen_port, route.upstream_name
        ));
    }

    config.push_str("}\n");
    config
}

/// Minimal nginx config with no routes (used before pods are up).
pub fn minimal_proxy_config() -> String {
    "worker_processes 1;\nevents { worker_connections 1024; }\n\
     # No stream routes yet — will be reloaded once pods are running\n"
        .to_string()
}