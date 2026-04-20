use anyhow::{Context, Result};
use bytes;
use bollard::{
    container::{
        Config, CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
        StartContainerOptions, WaitContainerOptions,
    },
    image::CreateImageOptions,
    models::{EndpointIpamConfig, EndpointSettings, HostConfig, Ipam, IpamConfig, PortBinding},
    network::{ConnectNetworkOptions, CreateNetworkOptions, ListNetworksOptions},
    Docker,
};
use futures_util::StreamExt;
use std::collections::HashMap;
use tracing::{info, warn};

use crate::manifest::{PodSpec, ProxySpec, Subnet};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub state: String,
    pub labels: HashMap<String, String>,
    pub networks: HashMap<String, String>, // network_name -> IP
}

impl ContainerInfo {
    pub fn is_running(&self) -> bool {
        self.state == "running"
    }
}

/// Backbone spec for attaching containers to the backbone network.
#[derive(Debug, Clone)]
pub struct BackboneSpec {
    pub network_name: String,
    pub static_ip: String,
}

/// Create a Docker bridge network for a subnet. Idempotent.
pub async fn create_network(docker: &Docker, cluster: &str, subnet: &Subnet) -> Result<String> {
    let network_name = format!("{}-{}", cluster, subnet.name);

    // Check if network already exists
    let filters = HashMap::from([("name".to_string(), vec![network_name.clone()])]);
    let networks = docker
        .list_networks(Some(ListNetworksOptions { filters }))
        .await
        .context("Failed to list networks")?;

    for net in &networks {
        if net.name.as_deref() == Some(&network_name) {
            let id = net.id.clone().unwrap_or_default();
            info!("Network '{}' already exists ({})", network_name, id);
            return Ok(id);
        }
    }

    let ipam_config = IpamConfig {
        subnet: Some(subnet.cidr.clone()),
        ..Default::default()
    };

    let create_opts = CreateNetworkOptions {
        name: network_name.clone(),
        driver: "bridge".to_string(),
        ipam: Ipam {
            config: Some(vec![ipam_config]),
            ..Default::default()
        },
        labels: HashMap::from([
            ("mini-k8s.cluster".to_string(), cluster.to_string()),
            ("mini-k8s.subnet".to_string(), subnet.name.clone()),
        ]),
        ..Default::default()
    };

    let response = docker
        .create_network(create_opts)
        .await
        .context(format!("Failed to create network '{}'", network_name))?;

    let id = response.id;
    info!("Created network '{}' ({})", network_name, id);
    Ok(id)
}

/// Create the backbone network for a cluster. Idempotent.
pub async fn create_backbone_network(docker: &Docker, cluster: &str) -> Result<String> {
    let network_name = format!("{}-backbone", cluster);
    let cidr = "10.200.0.0/16".to_string();

    // Check if network already exists
    let filters = HashMap::from([("name".to_string(), vec![network_name.clone()])]);
    let networks = docker
        .list_networks(Some(ListNetworksOptions { filters }))
        .await
        .context("Failed to list networks")?;

    for net in &networks {
        if net.name.as_deref() == Some(&network_name) {
            let id = net.id.clone().unwrap_or_default();
            info!("Backbone network '{}' already exists ({})", network_name, id);
            return Ok(id);
        }
    }

    let ipam_config = IpamConfig {
        subnet: Some(cidr),
        ..Default::default()
    };

    let create_opts = CreateNetworkOptions {
        name: network_name.clone(),
        driver: "bridge".to_string(),
        ipam: Ipam {
            config: Some(vec![ipam_config]),
            ..Default::default()
        },
        labels: HashMap::from([
            ("mini-k8s.cluster".to_string(), cluster.to_string()),
            ("mini-k8s.backbone".to_string(), "true".to_string()),
        ]),
        ..Default::default()
    };

    let response = docker
        .create_network(create_opts)
        .await
        .context(format!("Failed to create backbone network '{}'", network_name))?;

    let id = response.id;
    info!("Created backbone network '{}' ({})", network_name, id);
    Ok(id)
}

/// Connect a container to the backbone network with a static IP.
pub async fn connect_to_backbone(
    docker: &Docker,
    container_id_or_name: &str,
    backbone_network_name: &str,
    static_ip: &str,
) -> Result<()> {
    docker
        .connect_network(
            backbone_network_name,
            ConnectNetworkOptions {
                container: container_id_or_name,
                endpoint_config: EndpointSettings {
                    ipam_config: Some(EndpointIpamConfig {
                        ipv4_address: Some(static_ip.to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            },
        )
        .await
        .context(format!(
            "Failed to connect '{}' to backbone network '{}' with IP {}",
            container_id_or_name, backbone_network_name, static_ip
        ))?;
    info!(
        "Connected '{}' to backbone network '{}' with IP {}",
        container_id_or_name, backbone_network_name, static_ip
    );
    Ok(())
}

/// Apply iptables DROP rules via a short-lived privileged alpine container.
/// Each rule is (from_cidr, to_cidr).
pub async fn apply_iptables_rules(
    docker: &Docker,
    cluster: &str,
    rules: &[(&str, &str)],
) -> Result<()> {
    if rules.is_empty() {
        return Ok(());
    }

    let container_name = format!("{}-iptables-apply-{}", cluster, uuid_short());

    // Build iptables commands — both directions
    let mut cmds = Vec::new();
    for (from, to) in rules {
        // Forward direction
        cmds.push(format!(
            "iptables -C DOCKER-USER -s {from} -d {to} -j DROP 2>/dev/null || iptables -I DOCKER-USER -s {from} -d {to} -j DROP",
            from = from,
            to = to
        ));
        // Reverse direction
        cmds.push(format!(
            "iptables -C DOCKER-USER -s {to} -d {from} -j DROP 2>/dev/null || iptables -I DOCKER-USER -s {to} -d {from} -j DROP",
            from = from,
            to = to
        ));
    }
    let shell_cmd = cmds.join(" && ");

    pull_image(docker, "alpine:latest").await?;

    let config = Config {
        image: Some("alpine:latest"),
        cmd: Some(vec!["sh", "-c", &shell_cmd]),
        host_config: Some(HostConfig {
            network_mode: Some("host".to_string()),
            privileged: Some(true),
            cap_add: Some(vec!["NET_ADMIN".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let options = CreateContainerOptions {
        name: container_name.as_str(),
        platform: None,
    };

    let response = docker
        .create_container(Some(options), config)
        .await
        .context("Failed to create iptables container")?;

    docker
        .start_container(&response.id, None::<StartContainerOptions<String>>)
        .await
        .context("Failed to start iptables container")?;

    // Wait for the container to finish
    let mut wait_stream = docker.wait_container(&response.id, None::<WaitContainerOptions<String>>);
    while let Some(_) = wait_stream.next().await {}

    // Remove the container
    let _ = remove_container(docker, &container_name).await;

    info!("Applied {} iptables rule(s)", rules.len());
    Ok(())
}

/// Remove iptables DROP rules via a short-lived privileged alpine container.
#[allow(dead_code)]
pub async fn remove_iptables_rules(
    docker: &Docker,
    cluster: &str,
    rules: &[(&str, &str)],
) -> Result<()> {
    if rules.is_empty() {
        return Ok(());
    }

    let container_name = format!("{}-iptables-remove-{}", cluster, uuid_short());

    let mut cmds = Vec::new();
    for (from, to) in rules {
        cmds.push(format!(
            "iptables -D DOCKER-USER -s {from} -d {to} -j DROP 2>/dev/null || true",
            from = from,
            to = to
        ));
        cmds.push(format!(
            "iptables -D DOCKER-USER -s {to} -d {from} -j DROP 2>/dev/null || true",
            from = from,
            to = to
        ));
    }
    let shell_cmd = cmds.join(" && ");

    pull_image(docker, "alpine:latest").await?;

    let config = Config {
        image: Some("alpine:latest"),
        cmd: Some(vec!["sh", "-c", &shell_cmd]),
        host_config: Some(HostConfig {
            network_mode: Some("host".to_string()),
            privileged: Some(true),
            cap_add: Some(vec!["NET_ADMIN".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let options = CreateContainerOptions {
        name: container_name.as_str(),
        platform: None,
    };

    let response = docker
        .create_container(Some(options), config)
        .await
        .context("Failed to create iptables removal container")?;

    docker
        .start_container(&response.id, None::<StartContainerOptions<String>>)
        .await
        .context("Failed to start iptables removal container")?;

    let mut wait_stream = docker.wait_container(&response.id, None::<WaitContainerOptions<String>>);
    while let Some(_) = wait_stream.next().await {}

    let _ = remove_container(docker, &container_name).await;

    info!("Removed {} iptables rule(s)", rules.len());
    Ok(())
}

/// Create and start the DNS (CoreDNS) container on the backbone network.
pub async fn create_dns_container(
    docker: &Docker,
    cluster: &str,
    backbone_network: &str,
    dns_ip: Option<&str>,
    zone_content: &str,
    corefile_content: &str,
    image: &str,
) -> Result<String> {
    let container_name = format!("{}-dns", cluster);

    pull_image(docker, image).await?;
    let _ = remove_container(docker, &container_name).await;

    // Write zone and corefile to temp paths
    let zone_path = format!("/tmp/mini-k8s-{}.zone", cluster);
    let corefile_path = format!("/tmp/mini-k8s-{}.Corefile", cluster);
    std::fs::write(&zone_path, zone_content).context("Failed to write DNS zone file")?;
    std::fs::write(&corefile_path, corefile_content).context("Failed to write Corefile")?;

    let labels = HashMap::from([
        ("mini-k8s.cluster".to_string(), cluster.to_string()),
        ("mini-k8s.pod".to_string(), "dns".to_string()),
    ]);

    let mut endpoint_config = EndpointSettings {
        ..Default::default()
    };

    if let Some(ip) = dns_ip {
        endpoint_config.ipam_config = Some(EndpointIpamConfig {
            ipv4_address: Some(ip.to_string()),
            ..Default::default()
        });
    }

    let config = Config {
        image: Some(image),
        labels: Some(
            labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
        ),
        networking_config: Some(bollard::container::NetworkingConfig {
            endpoints_config: HashMap::from([(backbone_network, endpoint_config)]),
        }),
        host_config: Some(HostConfig {
            binds: Some(vec![
                format!("{}:/etc/coredns/cluster.zone:ro", zone_path),
                format!("{}:/etc/coredns/Corefile:ro", corefile_path),
            ]),
            ..Default::default()
        }),
        cmd: Some(vec!["-conf", "/etc/coredns/Corefile"]),
        ..Default::default()
    };

    let options = CreateContainerOptions {
        name: container_name.as_str(),
        platform: None,
    };

    let response = docker
        .create_container(Some(options), config)
        .await
        .context(format!("Failed to create DNS container '{}'", container_name))?;

    docker
        .start_container(&response.id, None::<StartContainerOptions<String>>)
        .await
        .context(format!("Failed to start DNS container '{}'", container_name))?;

    info!("Started DNS container '{}' ({})", container_name, response.id);
    Ok(response.id)
}

/// Remove a Docker network by name.
pub async fn remove_network(docker: &Docker, name: &str) -> Result<()> {
    match docker.remove_network(name).await {
        Ok(_) => {
            info!("Removed network '{}'", name);
            Ok(())
        }
        Err(e) => {
            warn!("Failed to remove network '{}': {}", name, e);
            Ok(()) // Non-fatal
        }
    }
}

/// Pull an image if it isn't already present locally.
///
/// Checks `inspect_image` first so locally-built images (e.g. `mini-k8s-demo:latest`)
/// are never pushed to a registry lookup. Only contacts the registry when the image
/// is genuinely absent from the local Docker daemon.
pub async fn pull_image(docker: &Docker, image: &str) -> Result<()> {
    // Fast path: image already exists locally — nothing to do.
    if docker.inspect_image(image).await.is_ok() {
        info!("Image '{}' already present locally, skipping pull.", image);
        return Ok(());
    }

    info!("Pulling image '{}'...", image);
    let mut stream = docker.create_image(
        Some(CreateImageOptions {
            from_image: image,
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(item) = stream.next().await {
        match item {
            Ok(_) => {}
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to pull image '{}': {}", image, e));
            }
        }
    }
    info!("Image '{}' ready.", image);
    Ok(())
}

/// Create and start a pod container. Idempotent by name.
///
/// `host_port` — when `Some`, binds container port 80 to this host port (multi-node).
/// `node_name` — when `Some`, stored as label `mini-k8s.node` for registry tracking.
pub async fn create_and_start_container(
    docker: &Docker,
    cluster: &str,
    pod: &PodSpec,
    replica_index: u32,
    network_name: &str,
    env_vars: Vec<String>,
    host_port: Option<u16>,
    node_name: Option<&str>,
) -> Result<String> {
    let container_name = format!("{}-{}-{}", cluster, pod.name, replica_index);

    // Ensure the image is available locally before creating the container.
    pull_image(docker, &pod.image).await?;

    // Remove existing container with same name if any (dead/stopped)
    let _ = remove_container(docker, &container_name).await;

    let mut labels = HashMap::from([
        ("mini-k8s.cluster".to_string(), cluster.to_string()),
        ("mini-k8s.pod".to_string(), pod.name.clone()),
        ("mini-k8s.replica".to_string(), replica_index.to_string()),
        ("mini-k8s.subnet".to_string(), pod.subnet.clone()),
    ]);
    if let Some(nn) = node_name {
        labels.insert("mini-k8s.node".to_string(), nn.to_string());
    }
    if let Some(hp) = host_port {
        labels.insert("mini-k8s.host-port".to_string(), hp.to_string());
    }

    let cmd: Option<Vec<&str>> = pod
        .command
        .as_ref()
        .map(|c| c.iter().map(|s| s.as_str()).collect());

    let env_strs: Vec<&str> = env_vars.iter().map(|s| s.as_str()).collect();

    // Pre-compute port key strings so they outlive the Config borrow.
    let port_keys: Vec<String> = pod
        .ports
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|p| format!("{}/tcp", p.container_port))
        .collect();

    let exposed_ports: HashMap<&str, HashMap<(), ()>> = port_keys
        .iter()
        .map(|k| (k.as_str(), HashMap::new()))
        .collect();

    let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = pod
        .ports
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|p| {
            let key = format!("{}/tcp", p.container_port);
            let binding = p.host_port.map(|hp| {
                vec![PortBinding {
                    host_ip: Some("0.0.0.0".to_string()),
                    host_port: Some(hp.to_string()),
                }]
            });
            (key, binding)
        })
        .collect();

    // Multi-node: publish container port 80 on the requested host port.
    if let Some(hp) = host_port {
        port_bindings.insert(
            "80/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some(hp.to_string()),
            }]),
        );
    }

    let config = Config {
        image: Some(pod.image.as_str()),
        cmd,
        env: Some(env_strs),
        labels: Some(
            labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
        ),
        networking_config: Some(bollard::container::NetworkingConfig {
            endpoints_config: HashMap::from([(
                network_name,
                EndpointSettings {
                    ..Default::default()
                },
            )]),
        }),
        host_config: Some(HostConfig {
            port_bindings: Some(port_bindings),
            ..Default::default()
        }),
        exposed_ports: Some(exposed_ports),
        ..Default::default()
    };

    let options = CreateContainerOptions {
        name: container_name.as_str(),
        platform: None,
    };

    let response = docker
        .create_container(Some(options), config)
        .await
        .context(format!("Failed to create container '{}'", container_name))?;

    docker
        .start_container(&response.id, None::<StartContainerOptions<String>>)
        .await
        .context(format!("Failed to start container '{}'", container_name))?;

    info!("Started container '{}' ({})", container_name, response.id);
    Ok(response.id)
}

/// Create and start a pod container with optional backbone network and DNS configuration.
///
/// `host_port` — when `Some`, binds container port 80 to this host port (multi-node).
/// `node_name` — when `Some`, stored as label `mini-k8s.node` for registry tracking.
pub async fn create_and_start_container_v2(
    docker: &Docker,
    cluster: &str,
    pod: &PodSpec,
    replica_index: u32,
    network_name: &str,
    env_vars: Vec<String>,
    backbone: Option<BackboneSpec>,
    dns_servers: &[String],
    host_port: Option<u16>,
    node_name: Option<&str>,
) -> Result<String> {
    let container_name = format!("{}-{}-{}", cluster, pod.name, replica_index);

    pull_image(docker, &pod.image).await?;
    let _ = remove_container(docker, &container_name).await;

    let mut labels = HashMap::from([
        ("mini-k8s.cluster".to_string(), cluster.to_string()),
        ("mini-k8s.pod".to_string(), pod.name.clone()),
        ("mini-k8s.replica".to_string(), replica_index.to_string()),
        ("mini-k8s.subnet".to_string(), pod.subnet.clone()),
    ]);
    if let Some(nn) = node_name {
        labels.insert("mini-k8s.node".to_string(), nn.to_string());
    }
    if let Some(hp) = host_port {
        labels.insert("mini-k8s.host-port".to_string(), hp.to_string());
    }

    let cmd: Option<Vec<&str>> = pod
        .command
        .as_ref()
        .map(|c| c.iter().map(|s| s.as_str()).collect());

    let env_strs: Vec<&str> = env_vars.iter().map(|s| s.as_str()).collect();

    let port_keys: Vec<String> = pod
        .ports
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|p| format!("{}/tcp", p.container_port))
        .collect();

    let exposed_ports: HashMap<&str, HashMap<(), ()>> = port_keys
        .iter()
        .map(|k| (k.as_str(), HashMap::new()))
        .collect();

    let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = pod
        .ports
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|p| {
            let key = format!("{}/tcp", p.container_port);
            let binding = p.host_port.map(|hp| {
                vec![PortBinding {
                    host_ip: Some("0.0.0.0".to_string()),
                    host_port: Some(hp.to_string()),
                }]
            });
            (key, binding)
        })
        .collect();

    if let Some(hp) = host_port {
        port_bindings.insert(
            "80/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some(hp.to_string()),
            }]),
        );
    }

    let dns_list: Option<Vec<String>> = if dns_servers.is_empty() {
        None
    } else {
        Some(dns_servers.to_vec())
    };

    let dns_search: Option<Vec<String>> = if dns_servers.is_empty() {
        None
    } else {
        Some(vec!["cluster.local".to_string()])
    };

    let config = Config {
        image: Some(pod.image.as_str()),
        cmd,
        env: Some(env_strs),
        labels: Some(
            labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
        ),
        networking_config: Some(bollard::container::NetworkingConfig {
            endpoints_config: HashMap::from([(
                network_name,
                EndpointSettings {
                    ..Default::default()
                },
            )]),
        }),
        host_config: Some(HostConfig {
            port_bindings: Some(port_bindings),
            dns: dns_list,
            dns_search,
            ..Default::default()
        }),
        exposed_ports: Some(exposed_ports),
        ..Default::default()
    };

    let options = CreateContainerOptions {
        name: container_name.as_str(),
        platform: None,
    };

    let response = docker
        .create_container(Some(options), config)
        .await
        .context(format!("Failed to create container '{}'", container_name))?;

    docker
        .start_container(&response.id, None::<StartContainerOptions<String>>)
        .await
        .context(format!("Failed to start container '{}'", container_name))?;

    info!("Started container '{}' ({})", container_name, response.id);

    // Connect to backbone network with static IP if specified
    if let Some(bb) = backbone {
        connect_to_backbone(docker, &response.id, &bb.network_name, &bb.static_ip).await?;
    }

    Ok(response.id)
}


/// List all containers belonging to this cluster.
pub async fn list_cluster_containers(docker: &Docker, cluster: &str) -> Result<Vec<ContainerInfo>> {
    let filters = HashMap::from([(
        "label".to_string(),
        vec![format!("mini-k8s.cluster={}", cluster)],
    )]);

    let containers = docker
        .list_containers(Some(ListContainersOptions::<String> {
            all: true,
            filters,
            ..Default::default()
        }))
        .await
        .context("Failed to list containers")?;

    let mut result = Vec::new();
    for c in containers {
        let name = c
            .names
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or_default()
            .trim_start_matches('/')
            .to_string();

        let networks = c
            .network_settings
            .and_then(|ns| ns.networks)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(net_name, ep)| ep.ip_address.map(|ip| (net_name, ip)))
            .filter(|(_, ip)| !ip.is_empty())
            .collect();

        result.push(ContainerInfo {
            id: c.id.unwrap_or_default(),
            name,
            state: c.state.unwrap_or_default(),
            labels: c.labels.unwrap_or_default(),
            networks,
        });
    }

    Ok(result)
}

/// Force-remove a container by name, ignoring "not found" errors.
pub async fn remove_container(docker: &Docker, name: &str) -> Result<()> {
    let opts = RemoveContainerOptions {
        force: true,
        ..Default::default()
    };
    match docker.remove_container(name, Some(opts)).await {
        Ok(_) => {
            info!("Removed container '{}'", name);
        }
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => {
            // Container not found — that's fine
        }
        Err(e) => {
            warn!("Failed to remove container '{}': {}", name, e);
        }
    }
    Ok(())
}

/// Get a container's IP on a specific network.
#[allow(dead_code)]
pub async fn get_container_ip(
    docker: &Docker,
    container_id: &str,
    network_name: &str,
) -> Result<String> {
    let info = docker
        .inspect_container(container_id, None)
        .await
        .context(format!("Failed to inspect container '{}'", container_id))?;

    let ip = info
        .network_settings
        .and_then(|ns| ns.networks)
        .and_then(|nets| nets.get(network_name).cloned())
        .and_then(|ep| ep.ip_address)
        .filter(|ip| !ip.is_empty())
        .context(format!(
            "No IP found for container '{}' on network '{}'",
            container_id, network_name
        ))?;

    Ok(ip)
}

/// Get a container's IP by inspecting it; finds the network whose name ends with the given suffix.
#[allow(dead_code)]
pub async fn get_container_ip_by_subnet_suffix(
    docker: &Docker,
    container_name: &str,
    subnet_suffix: &str,
) -> Option<String> {
    let info = docker.inspect_container(container_name, None).await.ok()?;
    let networks = info.network_settings?.networks?;
    for (net_name, ep) in &networks {
        if net_name.ends_with(subnet_suffix) {
            if let Some(ip) = &ep.ip_address {
                if !ip.is_empty() {
                    return Some(ip.clone());
                }
            }
        }
    }
    None
}

/// Build an in-memory tar archive containing a single file.
fn make_tar_archive(filename: &str, content: &[u8]) -> Result<Vec<u8>> {
    let mut ar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    ar.append_data(&mut header, filename, content)
        .context("Failed to build tar archive")?;
    ar.finish().context("Failed to finalise tar archive")?;
    ar.into_inner().context("Failed to get tar bytes")
}

/// Upload `content` as `/etc/nginx/nginx.conf` inside a running container,
/// then exec `nginx -s reload`.
async fn upload_nginx_config(docker: &Docker, container_name: &str, content: &str) -> Result<()> {
    let tar_bytes = make_tar_archive("nginx.conf", content.as_bytes())?;

    docker
        .upload_to_container(
            container_name,
            Some(bollard::container::UploadToContainerOptions {
                path: "/etc/nginx".to_string(),
                ..Default::default()
            }),
            bytes::Bytes::from(tar_bytes),
        )
        .await
        .context(format!(
            "Failed to upload nginx config to container '{}'",
            container_name
        ))?;

    // Reload nginx so the new config takes effect
    let exec = docker
        .create_exec(
            container_name,
            bollard::exec::CreateExecOptions {
                cmd: Some(vec!["nginx", "-s", "reload"]),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                ..Default::default()
            },
        )
        .await
        .context("Failed to create exec for nginx reload")?;

    docker
        .start_exec(&exec.id, None)
        .await
        .context("Failed to start exec for nginx reload")?;

    Ok(())
}

/// Create and start the proxy container connected to all listed networks.
/// The nginx config is injected via `put_archive` after the container starts,
/// so no bind-mount is needed — works for both local and remote Docker.
pub async fn create_proxy_container(
    docker: &Docker,
    cluster: &str,
    proxy_spec: &ProxySpec,
    network_names: &[String],
    config_content: &str,
) -> Result<String> {
    let container_name = format!("{}-proxy", cluster);

    pull_image(docker, &proxy_spec.image).await?;
    let _ = remove_container(docker, &container_name).await;

    let labels = HashMap::from([
        ("mini-k8s.cluster".to_string(), cluster.to_string()),
        ("mini-k8s.pod".to_string(), "proxy".to_string()),
    ]);

    let listen_port = proxy_spec.listen_port.unwrap_or(8080);

    let first_network = network_names
        .first()
        .map(|s| s.as_str())
        .unwrap_or_default();

    let config = Config {
        image: Some(proxy_spec.image.as_str()),
        labels: Some(
            labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
        ),
        networking_config: Some(bollard::container::NetworkingConfig {
            endpoints_config: HashMap::from([(
                first_network,
                EndpointSettings {
                    ..Default::default()
                },
            )]),
        }),
        host_config: Some(HostConfig {
            port_bindings: Some(HashMap::from([(
                format!("{}/tcp", listen_port),
                Some(vec![PortBinding {
                    host_ip: Some("0.0.0.0".to_string()),
                    host_port: Some(listen_port.to_string()),
                }]),
            )])),
            ..Default::default()
        }),
        ..Default::default()
    };

    let options = CreateContainerOptions {
        name: container_name.as_str(),
        platform: None,
    };

    let response = docker
        .create_container(Some(options), config)
        .await
        .context(format!(
            "Failed to create proxy container '{}'",
            container_name
        ))?;

    // Connect to additional networks before starting
    for network_name in network_names.iter().skip(1) {
        docker
            .connect_network(
                network_name,
                ConnectNetworkOptions {
                    container: response.id.as_str(),
                    endpoint_config: EndpointSettings {
                        ..Default::default()
                    },
                },
            )
            .await
            .context(format!(
                "Failed to connect proxy to network '{}'",
                network_name
            ))?;
        info!("Connected proxy to additional network '{}'", network_name);
    }

    docker
        .start_container(&response.id, None::<StartContainerOptions<String>>)
        .await
        .context(format!(
            "Failed to start proxy container '{}'",
            container_name
        ))?;

    info!(
        "Started proxy container '{}' ({})",
        container_name, response.id
    );

    // Inject the nginx config and reload (no bind-mount needed)
    upload_nginx_config(docker, &container_name, config_content).await?;
    info!("Nginx config injected into proxy container '{}'", container_name);

    Ok(response.id)
}

/// Reload nginx config inside a running proxy container.
/// Uploads the new config via `put_archive` then execs `nginx -s reload`.
pub async fn reload_proxy(docker: &Docker, cluster: &str, new_config: &str) -> Result<()> {
    let container_name = format!("{}-proxy", cluster);
    upload_nginx_config(docker, &container_name, new_config).await?;
    info!("Reloaded nginx config in proxy container '{}'", container_name);
    Ok(())
}

/// Generate a short UUID-like suffix for ephemeral container names.
fn uuid_short() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:08x}", ts)
}