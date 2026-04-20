use anyhow::{bail, Result};
use serde::Deserialize;
use std::collections::HashSet;
///YAML file → load_manifest() →
//  validate() → Manifest struct 
// → rest of the program uses it. Everything else in the project 
// — docker.rs, daemon.rs, proxy.rs — 
// receives a &Manifest and reads from it.

#[derive(Debug, Deserialize, Clone)]
pub struct Manifest {
    pub cluster: ClusterConfig,
    pub subnets: Vec<Subnet>,
    pub pods: Vec<PodSpec>,
    pub firewall: Vec<FirewallRule>,
    pub proxy: ProxySpec,
    pub dns: Option<DnsSpec>,
}

#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallMode {
    #[default]
    Topology,
    Iptables,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Node {
    pub name: String,
    /// Public IP used by the daemon (running on your Mac) to reach this node's Docker TCP API.
    pub public_ip: String,
    /// Private (VPC) IP used for container-to-container and proxy-to-container routing.
    pub private_ip: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClusterConfig {
    pub name: String,
    #[serde(default)]
    pub firewall_mode: FirewallMode,
    /// When non-empty, activates multi-node scheduling.
    #[serde(default)]
    pub nodes: Vec<Node>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Subnet {
    pub name: String,
    pub cidr: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AutoscaleSpec {
    pub max_replicas: u32,
    pub target_rps: u32,
    #[serde(default = "default_scale_up_cooldown")]
    pub scale_up_cooldown: u64,
    #[serde(default = "default_scale_down_cooldown")]
    pub scale_down_cooldown: u64,
}

fn default_scale_up_cooldown() -> u64 {
    15
}
fn default_scale_down_cooldown() -> u64 {
    60
}

#[derive(Debug, Deserialize, Clone)]
pub struct PodSpec {
    pub name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    pub subnet: String,
    pub replicas: u32,
    pub ports: Option<Vec<PortMapping>>,
    pub autoscale: Option<AutoscaleSpec>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: Option<u16>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FirewallRule {
    pub deny: FirewallDeny,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FirewallDeny {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxySpec {
    pub image: String,
    pub subnets: Vec<String>,
    pub listen_port: Option<u16>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsSpec {
    pub enabled: bool,
    pub image: String,
}

pub fn load_manifest(path: &str) -> Result<Manifest> {
    let contents = std::fs::read_to_string(path)?;
    let manifest: Manifest = serde_yaml::from_str(&contents)?;
    validate(&manifest)?;
    Ok(manifest)
}

fn validate(manifest: &Manifest) -> Result<()> {
    let subnet_names: HashSet<&str> = manifest.subnets.iter().map(|s| s.name.as_str()).collect();

    // Validate pod subnet references
    for pod in &manifest.pods {
        if !subnet_names.contains(pod.subnet.as_str()) {
            bail!(
                "Pod '{}' references unknown subnet '{}'",
                pod.name,
                pod.subnet
            );
        }
    }

    // Validate firewall subnet references
    for rule in &manifest.firewall {
        if !subnet_names.contains(rule.deny.from.as_str()) {
            bail!(
                "Firewall rule references unknown subnet '{}'",
                rule.deny.from
            );
        }
        if !subnet_names.contains(rule.deny.to.as_str()) {
            bail!(
                "Firewall rule references unknown subnet '{}'",
                rule.deny.to
            );
        }
    }

    // Validate proxy subnet references
    for subnet_name in &manifest.proxy.subnets {
        if !subnet_names.contains(subnet_name.as_str()) {
            bail!(
                "Proxy references unknown subnet '{}'",
                subnet_name
            );
        }
    }

    Ok(())
}