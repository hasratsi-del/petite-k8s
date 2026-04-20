//! NodePool: manages one Docker client per cluster node.
//!
//! In single-node mode (manifest has no `nodes:` list) it wraps the local
//! Unix socket.  In multi-node mode it opens a TCP bollard connection to each
//! node's Docker daemon (port 2375) using the node's public IP.
//!
//! All container-creation and scheduling code goes through NodePool so the
//! rest of the daemon is topology-agnostic.

use anyhow::{Context, Result};
use bollard::Docker;
use std::collections::HashMap;

use crate::manifest::Node;

/// Per-node state held by the pool.
pub struct NodeEntry {
    pub name: String,
    /// Private (VPC) IP for container-to-container and proxy-upstream routing.
    /// Empty in single-node mode.
    pub private_ip: String,
    /// Public IP used to ship the Docker image via SSH.
    pub public_ip: String,
    pub docker: Docker,
}

/// Holds one Docker client per cluster node.
pub struct NodePool {
    pub entries: Vec<NodeEntry>,
    by_name: HashMap<String, usize>,
}

impl NodePool {
    /// Single-node: wrap the local Docker daemon.
    pub fn single(docker: Docker) -> Self {
        let mut by_name = HashMap::new();
        by_name.insert("local".to_string(), 0);
        Self {
            entries: vec![NodeEntry {
                name: "local".to_string(),
                private_ip: String::new(),
                public_ip: String::new(),
                docker,
            }],
            by_name,
        }
    }

    /// Multi-node: open a TCP bollard connection to each node's :2375.
    pub fn multi(nodes: &[Node]) -> Result<Self> {
        let mut entries = Vec::new();
        let mut by_name = HashMap::new();
        for (i, node) in nodes.iter().enumerate() {
            let addr = format!("http://{}:2375", node.public_ip);
            let docker =
                Docker::connect_with_http(&addr, 120, bollard::API_DEFAULT_VERSION)
                    .with_context(|| {
                        format!("Cannot connect to Docker on node '{}' ({})", node.name, addr)
                    })?;
            entries.push(NodeEntry {
                name: node.name.clone(),
                private_ip: node.private_ip.clone(),
                public_ip: node.public_ip.clone(),
                docker,
            });
            by_name.insert(node.name.clone(), i);
        }
        Ok(Self { entries, by_name })
    }

    /// True when managing more than one node.
    pub fn is_multi(&self) -> bool {
        self.entries.len() > 1
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Primary node (node-1 / local) — proxy and DNS always run here.
    pub fn primary(&self) -> &Docker {
        &self.entries[0].docker
    }

    /// Round-robin scheduling: replica_index % num_nodes.
    pub fn node_for_replica(&self, replica_index: u32) -> &NodeEntry {
        &self.entries[replica_index as usize % self.entries.len()]
    }

    pub fn get(&self, name: &str) -> Option<&NodeEntry> {
        self.by_name.get(name).map(|&i| &self.entries[i])
    }

    #[allow(dead_code)]
    pub fn client_for_replica(&self, replica_index: u32) -> &Docker {
        &self.node_for_replica(replica_index).docker
    }
}

/// Deterministic host port for a container in multi-node mode.
///
/// `pod_index` = position in the manifest pods list.
/// Formula: 10000 + pod_index * 100 + replica_index
/// Each pod gets 100 port slots (supports up to 100 replicas).
pub fn host_port_for(pod_index: usize, replica_index: u32) -> u16 {
    10_000 + (pod_index as u16) * 100 + replica_index as u16
}