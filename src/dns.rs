//! DNS zone file and Corefile generation for CoreDNS.

use crate::manifest::PodSpec;
use crate::registry::ServiceRegistry;

/// Generate a DNS zone file for the cluster using backbone IPs.
pub fn generate_zone_file(cluster: &str, registry: &ServiceRegistry, all_pods: &[PodSpec]) -> String {
    let mut content = String::new();

    // SOA record
    content.push_str(&format!(
        "$ORIGIN cluster.local.\n\
         $TTL 5\n\
         @ IN SOA ns.cluster.local. admin.cluster.local. (\n\
           2024010100 ; serial\n\
           3600       ; refresh\n\
           900        ; retry\n\
           604800     ; expire\n\
           300        ; minimum\n\
         )\n\
         @ IN NS ns.cluster.local.\n\
         ns IN A 127.0.0.1\n\n"
    ));

    // A records for each replica by backbone IP
    for pod in all_pods {
        let replicas = registry.entries.get(&pod.name);
        if let Some(replicas) = replicas {
            let mut ips: Vec<String> = Vec::new();
            for replica in replicas {
                let cname = format!("{}-{}-{}", cluster, pod.name, replica.replica_index);
                if let Some(ip) = registry.backbone_ips.get(&cname) {
                    // Individual replica record: pod-a-0.cluster.local
                    content.push_str(&format!(
                        "{}-{} IN A {}\n",
                        pod.name, replica.replica_index, ip
                    ));
                    ips.push(ip.clone());
                }
            }
            // Pod-level record pointing to all replicas (round-robin)
            for ip in &ips {
                content.push_str(&format!("{} IN A {}\n", pod.name, ip));
            }
            content.push('\n');
        }
    }

    // DNS container record
    if let Some(dns_ip) = &registry.dns_ip {
        content.push_str(&format!("dns IN A {}\n", dns_ip));
    }

    content
}

/// Generate a Corefile for CoreDNS.
pub fn generate_corefile(_cluster: &str) -> String {
    format!(
        "cluster.local:53 {{\n\
         \tfile /etc/coredns/cluster.zone\n\
         \treload 5s\n\
         \tlog\n\
         \terrors\n\
         }}\n\
         .:53 {{\n\
         \tforward . 8.8.8.8\n\
         \tlog\n\
         \terrors\n\
         }}\n",
        // cluster used for potential future namespacing
    )
}