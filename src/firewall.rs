use crate::manifest::FirewallRule;
///manifest.rs        defines all the structs
   ///  ↓
///firewall.rs        imports FirewallRule, uses it to check denies
    /// ↓
///proxy.rs           imports FirewallRule + calls can_communicate_directly()
     //↓
///registry.rs        imports FirewallRule + calls can_communicate_directly()
    /// ↓
///daemon.rs          uses everything above to run the cluster
/// Returns true if pods in `from_subnet` can communicate directly with pods in `to_subnet`.
/// Returns false if a deny rule exists between them (must use proxy instead).
pub fn can_communicate_directly(
    from_subnet: &str,
    to_subnet: &str,
    firewall_rules: &[FirewallRule],
) -> bool {
    // Same subnet always communicates directly
    if from_subnet == to_subnet {
        return true;
    }

    // Check for any deny rule that blocks direct communication
    for rule in firewall_rules {
        if rule.deny.from == from_subnet && rule.deny.to == to_subnet {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{FirewallDeny, FirewallRule};
///crate        → this project (mini-k8s)
///::manifest   → the manifest.rs file
///::{...}      → specifically import these types from it
    fn rule(from: &str, to: &str) -> FirewallRule {
        FirewallRule {
            deny: FirewallDeny {
                from: from.to_string(),
                to: to.to_string(),
            },
        }
    }

    #[test]
    fn same_subnet_always_direct() {
        let rules = vec![rule("subnet-1", "subnet-2")];
        assert!(can_communicate_directly("subnet-1", "subnet-1", &rules));
    }

    #[test]
    fn blocked_by_deny_rule() {
        let rules = vec![rule("subnet-2", "subnet-3")];
        assert!(!can_communicate_directly("subnet-2", "subnet-3", &rules));
    }

    #[test]
    fn no_deny_rule_allows_direct() {
        let rules = vec![rule("subnet-2", "subnet-3")];
        assert!(can_communicate_directly("subnet-1", "subnet-3", &rules));
    }

    #[test]
    fn deny_is_directional() {
        let rules = vec![rule("subnet-2", "subnet-3")];
        // subnet-3 -> subnet-2 is NOT blocked by this rule (it's unidirectional)
        assert!(can_communicate_directly("subnet-3", "subnet-2", &rules));
    }
}