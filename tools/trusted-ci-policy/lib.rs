//! Offline consistency checks only: inputs are untrusted claims, not authenticated facts.
//! A consistent result is neither CI, approval, nor authorization to merge.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement<'a> {
    pub check: &'a str,
    pub issuer: &'a str,
    pub definition: &'a str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence<'a> {
    pub check: &'a str,
    pub issuer: &'a str,
    pub definition: &'a str,
    pub candidate: &'a str,
    pub run_id: u64,
    pub attempt: u32,
    pub success: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot<'a> {
    pub repository: u64,
    pub pull_request: u64,
    pub base: &'a str,
    pub head: &'a str,
    pub candidate: &'a str,
    pub tree: &'a str,
    pub parents: Vec<&'a str>,
    pub complete: bool,
    pub evidence: Vec<Evidence<'a>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy<'a> {
    pub repository: u64,
    pub pull_request: u64,
    pub base: &'a str,
    pub head: &'a str,
    pub candidate: &'a str,
    pub tree: &'a str,
    pub requirements: Vec<Requirement<'a>>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Blocked,
    EvidenceConsistent,
}
/// Compares caller-supplied claims. The caller must establish authenticity, completeness,
/// freshness, and isolation independently; this function cannot verify any of them.
pub fn evaluate(policy: &Policy<'_>, before: &Snapshot<'_>, after: &Snapshot<'_>) -> Outcome {
    fn sha(s: &str) -> bool {
        s.len() == 40
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && s.bytes().any(|b| b != b'0')
    }
    fn label(s: &str) -> bool {
        !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic())
    }
    if before != after
        || policy.repository == 0
        || before.repository != policy.repository
        || policy.pull_request == 0
        || before.pull_request != policy.pull_request
        || before.base != policy.base
        || before.head != policy.head
        || before.candidate != policy.candidate
        || before.tree != policy.tree
        || !before.complete
        || policy.requirements.is_empty()
        || policy.requirements.len() > 128
        || before.evidence.len() != policy.requirements.len()
        || !sha(before.base)
        || !sha(before.head)
        || !sha(before.candidate)
        || !sha(before.tree)
        || before.base == before.head
        || before.candidate == before.base
        || before.candidate == before.head
        || before.parents.as_slice() != [before.base, before.head]
    {
        return Outcome::Blocked;
    }
    for (i, requirement) in policy.requirements.iter().enumerate() {
        if !label(requirement.check)
            || !label(requirement.issuer)
            || !label(requirement.definition)
            || policy.requirements[..i]
                .iter()
                .any(|r| r.check == requirement.check)
        {
            return Outcome::Blocked;
        }
        let matches: Vec<_> = before
            .evidence
            .iter()
            .filter(|e| e.check == requirement.check)
            .collect();
        if matches.len() != 1 {
            return Outcome::Blocked;
        }
        let e = matches[0];
        if e.issuer != requirement.issuer
            || e.definition != requirement.definition
            || e.candidate != before.candidate
            || e.run_id == 0
            || e.attempt == 0
            || !e.success
        {
            return Outcome::Blocked;
        }
    }
    if before.evidence.iter().enumerate().any(|(i, e)| {
        before.evidence[..i]
            .iter()
            .any(|other| other.run_id == e.run_id)
    }) {
        return Outcome::Blocked;
    }
    Outcome::EvidenceConsistent
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: &str = "1111111111111111111111111111111111111111";
    const HEAD: &str = "2222222222222222222222222222222222222222";
    const MERGE: &str = "3333333333333333333333333333333333333333";
    const TREE: &str = "4444444444444444444444444444444444444444";
    fn fixture() -> (Policy<'static>, Snapshot<'static>) {
        (
            Policy {
                repository: 7,
                pull_request: 9,
                base: BASE,
                head: HEAD,
                candidate: MERGE,
                tree: TREE,
                requirements: vec![Requirement {
                    check: "build",
                    issuer: "trusted-app",
                    definition: "v1",
                }],
            },
            Snapshot {
                repository: 7,
                pull_request: 9,
                base: BASE,
                head: HEAD,
                candidate: MERGE,
                tree: TREE,
                parents: vec![BASE, HEAD],
                complete: true,
                evidence: vec![Evidence {
                    check: "build",
                    issuer: "trusted-app",
                    definition: "v1",
                    candidate: MERGE,
                    run_id: 10,
                    attempt: 1,
                    success: true,
                }],
            },
        )
    }
    #[test]
    fn complete_consistent_claims_are_not_an_approval() {
        let (p, s) = fixture();
        assert_eq!(evaluate(&p, &s, &s), Outcome::EvidenceConsistent);
    }
    #[test]
    fn rejects_missing_or_conflicting_evidence() {
        let (p, s) = fixture();
        let mut cases = vec![];
        let mut x = s.clone();
        x.complete = false;
        cases.push(x);
        let mut x = s.clone();
        x.evidence.clear();
        cases.push(x);
        let mut x = s.clone();
        x.evidence[0].issuer = "impostor";
        cases.push(x);
        let mut x = s.clone();
        x.evidence[0].definition = "v2";
        cases.push(x);
        let mut x = s.clone();
        x.evidence[0].candidate = HEAD;
        cases.push(x);
        let mut x = s.clone();
        x.evidence[0].success = false;
        cases.push(x);
        let mut x = s.clone();
        x.evidence[0].attempt = 0;
        cases.push(x);
        let mut x = s.clone();
        x.evidence.push(x.evidence[0].clone());
        cases.push(x);
        for x in cases {
            assert_eq!(evaluate(&p, &x, &x), Outcome::Blocked);
        }
    }
    #[test]
    fn rejects_invalid_identity_and_change_between_snapshots() {
        let (p, s) = fixture();
        let mut cases = vec![];
        let mut x = s.clone();
        x.repository = 8;
        cases.push(x);
        let mut x = s.clone();
        x.pull_request = 10;
        cases.push(x);
        let mut x = s.clone();
        x.head = TREE;
        x.parents[1] = TREE;
        cases.push(x);
        let mut x = s.clone();
        x.pull_request = 0;
        cases.push(x);
        let mut x = s.clone();
        x.base = "bad";
        cases.push(x);
        let mut x = s.clone();
        x.tree = "0000000000000000000000000000000000000000";
        cases.push(x);
        let mut x = s.clone();
        x.parents.reverse();
        cases.push(x);
        let mut x = s.clone();
        x.parents.clear();
        cases.push(x);
        for x in cases {
            assert_eq!(evaluate(&p, &x, &x), Outcome::Blocked);
            assert_eq!(evaluate(&p, &s, &x), Outcome::Blocked);
        }
        let mut changed = s.clone();
        changed.evidence[0].run_id += 1;
        assert_eq!(evaluate(&p, &s, &changed), Outcome::Blocked);
    }
    #[test]
    fn multiple_checks_require_distinct_complete_evidence() {
        let (mut p, mut s) = fixture();
        p.requirements.push(Requirement {
            check: "test",
            issuer: "trusted-app",
            definition: "v1",
        });
        assert_eq!(evaluate(&p, &s, &s), Outcome::Blocked);
        let mut second = s.evidence[0].clone();
        second.check = "test";
        second.run_id = 11;
        s.evidence.push(second);
        assert_eq!(evaluate(&p, &s, &s), Outcome::EvidenceConsistent);
        s.evidence[1].run_id = 10;
        assert_eq!(evaluate(&p, &s, &s), Outcome::Blocked);
    }
    #[test]
    fn same_workflow_run_with_distinct_checks_blocks_even_with_different_attempts() {
        let (mut policy, mut snapshot) = fixture();
        policy.requirements.push(Requirement {
            check: "test",
            issuer: "trusted-app",
            definition: "v1",
        });
        let mut test = snapshot.evidence[0].clone();
        test.check = "test";
        test.attempt = 2;
        snapshot.evidence.push(test);
        assert_eq!(evaluate(&policy, &snapshot, &snapshot), Outcome::Blocked);
    }

    #[test]
    fn repeated_attempt_claims_block_regardless_of_status_or_order() {
        let (policy, snapshot) = fixture();
        for later_success in [false, true] {
            let mut two_attempts = snapshot.clone();
            let mut later = two_attempts.evidence[0].clone();
            later.attempt = 2;
            later.success = later_success;
            two_attempts.evidence.push(later);
            assert_eq!(
                evaluate(&policy, &two_attempts, &two_attempts),
                Outcome::Blocked
            );
            two_attempts.evidence.reverse();
            assert_eq!(
                evaluate(&policy, &two_attempts, &two_attempts),
                Outcome::Blocked
            );
        }
        let mut later_only = snapshot.clone();
        later_only.evidence[0].attempt = 2;
        assert_eq!(
            evaluate(&policy, &later_only, &later_only),
            Outcome::EvidenceConsistent
        );
        assert_eq!(evaluate(&policy, &snapshot, &later_only), Outcome::Blocked);
    }

    #[test]
    fn success_plus_non_success_or_incomplete_collection_blocks() {
        let (mut policy, mut snapshot) = fixture();
        policy.requirements.push(Requirement {
            check: "test",
            issuer: "trusted-app",
            definition: "v1",
        });
        let mut second = snapshot.evidence[0].clone();
        second.check = "test";
        second.run_id = 11;
        second.success = false; // The model cannot distinguish pending from failure.
        snapshot.evidence.push(second);
        assert_eq!(evaluate(&policy, &snapshot, &snapshot), Outcome::Blocked);
        snapshot.evidence[1].success = true;
        snapshot.complete = false;
        assert_eq!(evaluate(&policy, &snapshot, &snapshot), Outcome::Blocked);
        snapshot.complete = true;
        assert_eq!(
            evaluate(&policy, &snapshot, &snapshot),
            Outcome::EvidenceConsistent
        );
    }

    #[test]
    fn duplicate_check_cannot_replace_a_missing_required_check() {
        let (mut policy, mut snapshot) = fixture();
        policy.requirements.push(Requirement {
            check: "test",
            issuer: "trusted-app",
            definition: "v1",
        });
        let mut conflicting = snapshot.evidence[0].clone();
        conflicting.run_id = 11;
        conflicting.attempt = 2;
        conflicting.success = false;
        snapshot.evidence.push(conflicting);
        assert_eq!(evaluate(&policy, &snapshot, &snapshot), Outcome::Blocked);
        snapshot.evidence[1].success = true;
        assert_eq!(evaluate(&policy, &snapshot, &snapshot), Outcome::Blocked);
    }

    #[test]
    fn claims_can_be_forged_and_are_not_authenticated() {
        let (p, mut s) = fixture();
        s.evidence[0].run_id = 12345;
        // Plausible values alone are not proof of their origin.
        assert_eq!(evaluate(&p, &s, &s), Outcome::EvidenceConsistent);
    }
    #[test]
    fn rejects_ambiguous_or_empty_policy() {
        let (mut p, s) = fixture();
        p.requirements.clear();
        assert_eq!(evaluate(&p, &s, &s), Outcome::Blocked);
        let (mut p, s) = fixture();
        p.requirements.push(p.requirements[0].clone());
        assert_eq!(evaluate(&p, &s, &s), Outcome::Blocked);
    }
}
