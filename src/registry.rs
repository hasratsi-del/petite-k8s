use anyhow::Result;
use std::collections::HashMap;
use tracing::debug;

use crate::{
    docker,
    firewall::can_communicate_directly,
    manifest::{FirewallRule, Manifest, PodSpec, Subnet},
    node_pool::NodePool,
    proxy::compute_port_table,
};

/// Per-replica information stored in the registry.
#[derive(Debug, Clone)]
pub struct ReplicaInfo {
    pub replica_index: u32,
    pub container_name: String,
    /// Keys are full Docker network names (e.g. "exa-local-subnet-1").
    pub ips: HashMap<String, String>,
    /// Which node this container runs on ("local" in single-node mode).
    pub node_name: String,
    /// Host-published port on the node (0 in single-node mode).
    pub host_port: u16,
}

/// Maps pod_name -> list of ReplicaInfo.
#[derive(Debug, Default, Clone)]
pub struct ServiceRegistry {
    pub entries: HashMap<String, Vec<ReplicaInfo>>,
    /// The proxy's IPs: full Docker network name -> IP.
    pub proxy_ips: HashMap<String, String>,
    /// Backbone IPs keyed by container name.
    pub backbone_ips: HashMap<String, String>,
    /// DNS container's backbone IP.
    pub dns_ip: Option<String>,
    /// node_name → private IP, populated in multi-node mode.
    pub node_private_ips: HashMap<String, String>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild the registry by inspecting running containers on every node in the pool.
    pub async fn refresh(&mut self, pool: &NodePool, manifest: &Manifest) -> Result<()> {
        let cluster = &manifest.cluster.name;

        self.entries.clear();
        self.proxy_ips.clear();
        self.backbone_ips.clear();
        self.dns_ip = None;
        self.node_private_ips.clear();

        let proxy_name = format!("{}-proxy", cluster);
        let dns_name = format!("{}-dns", cluster);

        for entry in &pool.entries {
            let containers =
                docker::list_cluster_containers(&entry.docker, cluster).await?;

            for container in &containers {
                if !container.is_running() {
                    continue;
                }

                for (net_name, ip) in &container.networks {
                    if net_name.ends_with("backbone") {
                        self.backbone_ips.insert(container.name.clone(), ip.clone());
                    }
                }

                if container.name == proxy_name {
                    self.proxy_ips = container.networks.clone();
                    debug!("Proxy IPs: {:?}", self.proxy_ips);
                    continue;
                }

                if container.name == dns_name {
                    for (net_name, ip) in &container.networks {
                        if net_name.ends_with("backbone") {
                            self.dns_ip = Some(ip.clone());
                        }
                    }
                    continue;
                }

                let pod_label = container.labels.get("mini-k8s.pod").cloned();
                let replica_label = container.labels.get("mini-k8s.replica").cloned();
                let node_label = container
                    .labels
                    .get("mini-k8s.node")
                    .cloned()
                    .unwrap_or_else(|| entry.name.clone());
                let host_port = container
                    .labels
                    .get("mini-k8s.host-port")
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(0);

                match (pod_label.as_deref(), replica_label) {
                    (Some(pod_name), Some(replica_str)) => {
                        let replica_index: u32 = replica_str.parse().unwrap_or(0);
                        let info = ReplicaInfo {
                            replica_index,
                            container_name: container.name.clone(),
                            ips: container.networks.clone(),
                            node_name: node_label,
                            host_port,
                        };
                        self.entries
                            .entry(pod_name.to_string())
                            .or_default()
                            .push(info);
                    }
                    _ => {
                        // Ignore containers that don't look like application pods.
                    }
                }
            }

            // Record private IP for this node.
            if !entry.private_ip.is_empty() {
                self.node_private_ips
                    .insert(entry.name.clone(), entry.private_ip.clone());
            }
        }

        // Sort replica lists by index for deterministic ordering.
        for replicas in self.entries.values_mut() {
            replicas.sort_by_key(|r| r.replica_index);
        }

        Ok(())
    }

    /// Get the first IP a container has on any network whose name ends with the given subnet name.
    pub fn get_ip_on_subnet<'a>(
        networks: &'a HashMap<String, String>,
        subnet_name: &str,
    ) -> Option<&'a String> {
        networks
            .iter()
            .find(|(net_name, _)| net_name.ends_with(subnet_name))
            .map(|(_, ip)| ip)
    }

    /// Return the (ip, port) the proxy should use to reach a specific replica.
    ///
    /// Multi-node: `node_private_ip:host_port`
    /// Single-node: container's Docker IP on its own subnet, port 80
    pub fn upstream_for(
        &self,
        pod_name: &str,
        replica_index: u32,
        pod_subnet: &str,
    ) -> Option<(String, u16)> {
        let replica = self
            .entries
            .get(pod_name)?
            .iter()
            .find(|r| r.replica_index == replica_index)?;

        if replica.host_port > 0 {
            // Multi-node: route via the node's private IP + published host port.
            let private_ip = self.node_private_ips.get(&replica.node_name)?;
            Some((private_ip.clone(), replica.host_port))
        } else {
            // Single-node: direct Docker container IP on the pod's own subnet.
            let ip = Self::get_ip_on_subnet(&replica.ips, pod_subnet)
                .cloned()
                .or_else(|| replica.ips.values().find(|ip| !ip.is_empty()).cloned())?;
            Some((ip, 80))
        }
    }

    /// Build the environment variable list for a specific pod replica.
    ///
    /// Rules:
    /// - Same subnet, same node  → direct bridge IP (`MINI_K8S_POD_A_0=<ip>`)
    /// - Same subnet, diff node  → `node_private_ip:host_port` (bridge IP unreachable cross-node)
    /// - Different subnet, no deny rule → proxy route (`MINI_K8S_POD_C_0_VIA_PROXY=<proxy-ip>:<port>`)
    /// - Different subnet, deny rule → no env var (path is blocked, even through the proxy)
    ///
    /// `current_node` is the node name of the pod replica being configured ("local" in single-node).
    pub fn build_env_for_pod_v2(
        &self,
        pod: &PodSpec,
        replica_index: u32,
        firewall_rules: &[FirewallRule],
        all_pods: &[PodSpec],
        all_subnets: &[Subnet],
        current_node: &str,
    ) -> Vec<String> {
        let mut env = Vec::new();

        env.push(format!("MINI_K8S_SELF={}-{}", pod.name, replica_index));

        // Proxy IP on this pod's subnet.
        if let Some(proxy_ip) = Self::get_ip_on_subnet(&self.proxy_ips, &pod.subnet) {
            env.push(format!("MINI_K8S_PROXY={}", proxy_ip));
        }

        // Port table keyed by (source_subnet, target_pod, target_replica).
        let port_table = compute_port_table(all_subnets, all_pods, firewall_rules);

        for other_pod in all_pods {
            let var_prefix = format!("MINI_K8S_{}", env_key(&other_pod.name));

            // Same subnet.
            if pod.subnet == other_pod.subnet {
                let replica_count = self
                    .entries
                    .get(&other_pod.name)
                    .map(|r| r.len())
                    .unwrap_or(other_pod.replicas as usize);
                env.push(format!("{}_REPLICAS={}", var_prefix, replica_count));

                if let Some(replicas) = self.entries.get(&other_pod.name) {
                    for replica in replicas {
                        let ri = replica.replica_index;
                        if replica.host_port > 0 && replica.node_name != current_node {
                            // Cross-node: bridge IP is unreachable; use node private IP + host port.
                            if let Some(private_ip) =
                                self.node_private_ips.get(&replica.node_name)
                            {
                                env.push(format!(
                                    "{}_{}={}:{}",
                                    var_prefix, ri, private_ip, replica.host_port
                                ));
                            }
                        } else {
                            // Same node (or single-node): direct bridge IP.
                            let ip_opt =
                                Self::get_ip_on_subnet(&replica.ips, &other_pod.subnet)
                                    .cloned()
                                    .or_else(|| {
                                        replica.ips.values().find(|ip| !ip.is_empty()).cloned()
                                    });
                            if let Some(ip) = ip_opt {
                                env.push(format!("{}_{}={}", var_prefix, ri, ip));
                            }
                        }
                    }
                }
                continue;
            }

            // Different subnet — check firewall.
            let can_reach =
                can_communicate_directly(&pod.subnet, &other_pod.subnet, firewall_rules);

            if !can_reach {
                continue;
            }

            let replica_count = self
                .entries
                .get(&other_pod.name)
                .map(|r| r.len())
                .unwrap_or(other_pod.replicas as usize);
            env.push(format!("{}_REPLICAS={}", var_prefix, replica_count));

            if let Some(replicas) = self.entries.get(&other_pod.name) {
                for replica in replicas {
                    let ri = replica.replica_index;
                    let key = (pod.subnet.clone(), other_pod.name.clone(), ri);
                    if let Some(&port) = port_table.get(&key) {
                        if let Some(proxy_ip) =
                            Self::get_ip_on_subnet(&self.proxy_ips, &pod.subnet)
                        {
                            env.push(format!(
                                "{}_{}_VIA_PROXY={}:{}",
                                var_prefix, ri, proxy_ip, port
                            ));
                        } else {
                            env.push(format!(
                                "{}_{}_VIA_PROXY=<proxy-pending>:{}",
                                var_prefix, ri, port
                            ));
                        }
                    }
                }
            }
        }

        env
    }
}

/// Convert a name to env-var-safe uppercase key (e.g. "pod-a" → "POD_A").
fn env_key(name: &str) -> String {
    name.replace('-', "_").to_uppercase()
}