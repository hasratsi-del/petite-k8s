use axum::{routing::get, Router, Json};
use std::sync::{Arc, Mutex};
use serde::Serialize;
use crate::registry::ServiceRegistry;
use crate::manifest::Manifest;

#[derive(Serialize, Clone)]
pub struct PodStatus {
    pub name: String,
    pub replica_index: u32,
    pub container_name: String,
    pub ip: String,
    pub node: String,
    pub healthy: bool,
}

#[derive(Serialize, Clone)]
pub struct ClusterStatus {
    pub cluster_name: String,
    pub total_pods: usize,
    pub healthy_pods: usize,
    pub pods: Vec<PodStatus>,
    pub leader_node: String,
    pub uptime_seconds: u64,
}

pub type SharedState = Arc<Mutex<ClusterStatus>>;

pub fn empty_status(cluster_name: &str) -> ClusterStatus {
    ClusterStatus {
        cluster_name: cluster_name.to_string(),
        total_pods: 0,
        healthy_pods: 0,
        pods: vec![],
        leader_node: "none".to_string(),
        uptime_seconds: 0,
    }
}

pub fn build_status(manifest: &Manifest, registry: &ServiceRegistry, uptime: u64) -> ClusterStatus {
    let mut pods = Vec::new();

    for pod_spec in &manifest.pods {
        if let Some(replicas) = registry.entries.get(&pod_spec.name) {
            for replica in replicas {
                let ip = replica.ips.values()
                    .find(|ip| !ip.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());

                pods.push(PodStatus {
                    name: pod_spec.name.clone(),
                    replica_index: replica.replica_index,
                    container_name: replica.container_name.clone(),
                    ip,
                    node: replica.node_name.clone(),
                    healthy: true,
                });
            }
        }
    }

    let healthy = pods.iter().filter(|p| p.healthy).count();
    let total = pods.len();

    ClusterStatus {
        cluster_name: manifest.cluster.name.clone(),
        total_pods: total,
        healthy_pods: healthy,
        pods,
        leader_node: "local".to_string(),
        uptime_seconds: uptime,
    }
}

pub async fn serve_dashboard(state: SharedState, port: u16) {
    let app = Router::new()
        .route("/api/status", get({
            let state = state.clone();
            move || {
                let s = state.lock().unwrap().clone();
                async move { Json(s) }
            }
        }))
        .route("/", get(serve_html));

    let addr = format!("0.0.0.0:{}", port);
    println!("Dashboard running at http://localhost:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn serve_html() -> axum::response::Html<&'static str> {
    axum::response::Html(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mini-k8s dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; }
  .header { background: #1a1d27; border-bottom: 1px solid #2d3148; padding: 20px 32px; display: flex; align-items: center; gap: 12px; }
  .header h1 { font-size: 18px; font-weight: 600; color: #fff; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .container { max-width: 1100px; margin: 0 auto; padding: 32px; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: #1a1d27; border: 1px solid #2d3148; border-radius: 12px; padding: 20px; }
  .stat-label { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 8px; }
  .stat-value { font-size: 28px; font-weight: 600; color: #fff; }
  .stat-value.green { color: #22c55e; }
  .stat-value.blue { color: #60a5fa; }
  .pods-header { font-size: 14px; font-weight: 500; color: #94a3b8; margin-bottom: 12px; text-transform: uppercase; letter-spacing: .05em; }
  table { width: 100%; border-collapse: collapse; background: #1a1d27; border: 1px solid #2d3148; border-radius: 12px; overflow: hidden; }
  th { text-align: left; padding: 12px 16px; font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid #2d3148; }
  td { padding: 14px 16px; font-size: 14px; border-bottom: 1px solid #1e2133; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #1e2133; }
  .badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; border-radius: 99px; font-size: 12px; font-weight: 500; }
  .badge.healthy { background: #14532d; color: #22c55e; }
  .badge.unhealthy { background: #450a0a; color: #f87171; }
  .badge-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
  .ip { font-family: 'SF Mono', monospace; font-size: 12px; color: #60a5fa; }
  .container-name { font-family: 'SF Mono', monospace; font-size: 12px; color: #94a3b8; }
  .empty { text-align: center; padding: 48px; color: #475569; }
  .refresh { font-size: 12px; color: #475569; margin-top: 16px; text-align: right; }
</style>
</head>
<body>
<div class="header">
  <div class="dot"></div>
  <h1>mini-k8s dashboard</h1>
  <span style="margin-left:auto;font-size:13px;color:#475569" id="cluster-name"></span>
</div>
<div class="container">
  <div class="stats">
    <div class="stat-card">
      <div class="stat-label">Total pods</div>
      <div class="stat-value blue" id="total-pods">—</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Healthy</div>
      <div class="stat-value green" id="healthy-pods">—</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Uptime</div>
      <div class="stat-value" id="uptime">—</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Leader node</div>
      <div class="stat-value" style="font-size:18px" id="leader">—</div>
    </div>
  </div>

  <div class="pods-header">Running containers</div>
  <table>
    <thead>
      <tr>
        <th>Pod</th>
        <th>Replica</th>
        <th>Container</th>
        <th>IP</th>
        <th>Node</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody id="pods-table">
      <tr><td colspan="6" class="empty">Loading...</td></tr>
    </tbody>
  </table>
  <div class="refresh" id="last-refresh"></div>
</div>

<script>
async function refresh() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    document.getElementById('cluster-name').textContent = data.cluster_name;
    document.getElementById('total-pods').textContent = data.total_pods;
    document.getElementById('healthy-pods').textContent = data.healthy_pods;
    document.getElementById('leader').textContent = data.leader_node;

    const uptime = data.uptime_seconds;
    const h = Math.floor(uptime / 3600);
    const m = Math.floor((uptime % 3600) / 60);
    const s = uptime % 60;
    document.getElementById('uptime').textContent =
      h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;

    const tbody = document.getElementById('pods-table');
    if (data.pods.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No pods running</td></tr>';
      return;
    }

    tbody.innerHTML = data.pods.map(pod => `
      <tr>
        <td style="font-weight:500">${pod.name}</td>
        <td style="color:#94a3b8">${pod.replica_index}</td>
        <td class="container-name">${pod.container_name}</td>
        <td class="ip">${pod.ip}</td>
        <td style="color:#94a3b8">${pod.node}</td>
        <td>
          <span class="badge ${pod.healthy ? 'healthy' : 'unhealthy'}">
            <span class="badge-dot"></span>
            ${pod.healthy ? 'healthy' : 'unhealthy'}
          </span>
        </td>
      </tr>
    `).join('');

    document.getElementById('last-refresh').textContent =
      'Last updated: ' + new Date().toLocaleTimeString();
  } catch(e) {
    document.getElementById('last-refresh').textContent = 'Connection error — retrying...';
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"#;