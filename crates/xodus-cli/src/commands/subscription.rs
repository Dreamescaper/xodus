//! Known PC Game Pass plan product IDs.
//!
//! Ported from domsvoboda/nexus-backend with credit. A child entitlement whose
//! `satisfiedByProductId` is one of these is subscription access, not ownership.

pub(super) const PLANS: &[&str] = &[
    "CFQ7TTC0KGQ8",
    "CFQ7TTC0KHS0",
    "CFQ7TTC0K5DJ",
    "CFQ7TTC0P85B",
    "CFQ7TTC0K6L8",
    "CFQ7TTC10QFD",
];

pub(super) fn is_plan(product_id: &str) -> bool {
    PLANS.contains(&product_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_pc_game_pass_plans_are_recognized() {
        assert!(is_plan("CFQ7TTC0KGQ8"));
        assert!(is_plan("CFQ7TTC10QFD"));
        assert!(!is_plan("9AAAAAAAAAAA"));
    }
}
