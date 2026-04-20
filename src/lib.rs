/// Client-side service discovery and load-balancing library.
/// Used by pod binaries (echo_server, test_client) to route requests
/// across replicas by reading MINI_K8S_* environment variables.
pub mod client;