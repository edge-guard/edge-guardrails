//! The violation code space — one authoritative definition.
//!
//! # Why this module exists
//!
//! Three independent subsystems mint violation codes: the compiled-in
//! detectors, the proximity rule graph ([`crate::graph`]), and the
//! `policy.yaml` regex layer ([`crate::PolicyEngine`]). Each used to derive
//! codes with its own arithmetic, and the arithmetic overlapped:
//!
//! * a tenant rule with `id: 300` derived `200 + 300 = 500` — **the same code
//!   the engine emits when a detector panics and the scan fails closed**;
//! * a `policy.yaml` rule with `id: 1` derived `500 + 1 = 501`, and a tenant
//!   rule with `id: 301` also derived `501`;
//! * `413` (payload too large) sits inside the range a tenant rule with
//!   `id: 213` would have produced.
//!
//! The consequence is not cosmetic. A SIEM consuming the audit trail cannot
//! distinguish "a customer's rule blocked an attack" from "the engine broke
//! and failed closed" — which are the two verdicts that must never be
//! conflated, because one is a detection to investigate and the other is an
//! outage to page on. An attacker who can get a rule published with a chosen
//! id can also deliberately disguise their blocks as engine faults.
//!
//! # The space
//!
//! ```text
//!        0            no violation
//!        1 ..=    999 RESERVED - engine internals and the built-in baseline.
//!                     Not derivable from any operator-supplied id.
//!   10_000 ..= 19_999 tenant proximity rules   (10_000 + rule id)
//!   20_000 ..= 29_999 policy.yaml regex rules  (20_000 + rule id)
//! ```
//!
//! Operator rule ids are bounded to `1..=9_999`, which is what makes the
//! bands **structurally** disjoint rather than disjoint by convention: no id
//! an operator can write reaches out of its own band. See
//! [`classify`] for the inverse mapping a SIEM needs.
//!
//! # Compatibility
//!
//! Codes in the reserved band are **unchanged**: the built-in baseline rules
//! still report 201-213, PII still reports 301-304, and 413/500 are where
//! they were. Existing SIEM rules against built-in detections keep working.
//! Only the two operator-controlled ranges moved.

/// No violation.
pub const SAFE: u32 = 0;

// ---------------------------------------------------------------------------
// Reserved band: 1..=999
// ---------------------------------------------------------------------------

/// Nothing an operator can configure may produce a code at or below this.
pub const RESERVED_MAX: u32 = 999;

/// Prompt injection / roleplay / obfuscation, from the compiled-in detectors.
pub const INJECTION: u32 = 101;
/// A caller-supplied custom literal matched.
pub const CUSTOM_PATTERN: u32 = 103;
/// Grey-area prompt that the semantic tier could not be consulted about.
pub const GREY_NO_SEMANTIC: u32 = 150;
/// The semantic tier returned a verdict.
pub const SEMANTIC: u32 = 160;

/// Built-in baseline proximity rules derive `BUILTIN_RULE_BASE + id`.
pub const BUILTIN_RULE_BASE: u32 = 200;
/// Baseline ids are capped so the derived codes stay inside 201..=299 and can
/// never reach `PAYLOAD_TOO_LARGE` or `INTERNAL_ERROR`.
pub const BUILTIN_RULE_MAX_ID: u32 = 99;

pub const PII_CREDIT_CARD: u32 = 301;
pub const PII_AWS_KEY: u32 = 302;
pub const PII_EMAIL: u32 = 303;
pub const PII_NATIONAL_ID: u32 = 304;

/// Input exceeded the size guard and was refused without being analyzed.
pub const PAYLOAD_TOO_LARGE: u32 = 413;
/// A detector panicked; the scan failed closed. **Operational, not a
/// detection.** Isolating this from every operator-reachable code is the
/// primary reason this module exists.
pub const INTERNAL_ERROR: u32 = 500;

// ---------------------------------------------------------------------------
// Operator bands
// ---------------------------------------------------------------------------

/// Tenant-authored proximity rules.
pub const TENANT_RULE_BASE: u32 = 10_000;
/// `policy.yaml` regex rules.
pub const POLICY_RULE_BASE: u32 = 20_000;
/// Largest id an operator may give a rule, in either layer. Bounding this is
/// what keeps each band inside its own 10 000-wide window.
pub const MAX_OPERATOR_RULE_ID: u32 = 9_999;

/// Width of each operator band.
pub const OPERATOR_BAND_WIDTH: u32 = 10_000;

/// Code for a built-in baseline rule. `None` if the id is out of range, which
/// is a programming error in [`crate::graph::baseline_rules`] rather than
/// operator input.
#[inline]
pub const fn builtin_rule_code(id: u32) -> Option<u32> {
    if id == 0 || id > BUILTIN_RULE_MAX_ID {
        return None;
    }
    Some(BUILTIN_RULE_BASE + id)
}

/// Code for a tenant proximity rule. `None` if the id is out of range.
#[inline]
pub const fn tenant_rule_code(id: u32) -> Option<u32> {
    if id == 0 || id > MAX_OPERATOR_RULE_ID {
        return None;
    }
    Some(TENANT_RULE_BASE + id)
}

/// Code for a `policy.yaml` regex rule. `None` if the id is out of range.
#[inline]
pub const fn policy_rule_code(id: u32) -> Option<u32> {
    if id == 0 || id > MAX_OPERATOR_RULE_ID {
        return None;
    }
    Some(POLICY_RULE_BASE + id)
}

/// `true` when `code` is a legal explicit override for a tenant rule.
#[inline]
pub const fn is_tenant_code(code: u32) -> bool {
    code > TENANT_RULE_BASE && code <= TENANT_RULE_BASE + MAX_OPERATOR_RULE_ID
}

/// What produced a violation code.
///
/// This is the inverse mapping a SIEM needs: given a code off the wire, say
/// which subsystem emitted it and, for operator rules, recover the rule id
/// without consulting any configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeClass {
    /// No violation.
    Safe,
    /// An engine internal fault. Fail-closed, **page on this** - it is an
    /// availability signal, not a detection.
    EngineFault,
    /// A compiled-in detector or built-in baseline rule.
    Builtin,
    /// A tenant-authored proximity rule.
    TenantRule { id: u32 },
    /// A `policy.yaml` regex rule.
    PolicyRule { id: u32 },
    /// Not a code this version can mint. Treat as suspect.
    Unknown,
}

/// Classify a code coming off the wire.
pub const fn classify(code: u32) -> CodeClass {
    if code == SAFE {
        return CodeClass::Safe;
    }
    if code == INTERNAL_ERROR {
        return CodeClass::EngineFault;
    }
    if code <= RESERVED_MAX {
        return CodeClass::Builtin;
    }
    if code > TENANT_RULE_BASE && code <= TENANT_RULE_BASE + MAX_OPERATOR_RULE_ID {
        return CodeClass::TenantRule {
            id: code - TENANT_RULE_BASE,
        };
    }
    if code > POLICY_RULE_BASE && code <= POLICY_RULE_BASE + MAX_OPERATOR_RULE_ID {
        return CodeClass::PolicyRule {
            id: code - POLICY_RULE_BASE,
        };
    }
    CodeClass::Unknown
}

impl CodeClass {
    /// `true` when this code represents a security detection rather than an
    /// operational fault. The single predicate an alerting pipeline needs to
    /// split its two routes.
    pub const fn is_detection(self) -> bool {
        matches!(
            self,
            CodeClass::Builtin | CodeClass::TenantRule { .. } | CodeClass::PolicyRule { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code the engine can emit that is not an operator rule.
    const RESERVED: &[u32] = &[
        INJECTION,
        CUSTOM_PATTERN,
        GREY_NO_SEMANTIC,
        SEMANTIC,
        PII_CREDIT_CARD,
        PII_AWS_KEY,
        PII_EMAIL,
        PII_NATIONAL_ID,
        PAYLOAD_TOO_LARGE,
        INTERNAL_ERROR,
    ];

    // The proof the whole module exists for. Not a sample - every id an
    // operator can legally write, in both layers, against every reserved code
    // and against each other.
    #[test]
    fn no_operator_rule_id_can_ever_collide_with_a_reserved_code() {
        for id in 1..=MAX_OPERATOR_RULE_ID {
            let t = tenant_rule_code(id).expect("in-range id must produce a code");
            let p = policy_rule_code(id).expect("in-range id must produce a code");
            assert!(
                t > RESERVED_MAX,
                "tenant id {} produced reserved code {}",
                id,
                t
            );
            assert!(
                p > RESERVED_MAX,
                "policy id {} produced reserved code {}",
                id,
                p
            );
            for &r in RESERVED {
                assert_ne!(t, r, "tenant id {} collides with reserved {}", id, r);
                assert_ne!(p, r, "policy id {} collides with reserved {}", id, r);
            }
        }
    }

    #[test]
    fn the_two_operator_bands_never_intersect() {
        let tenant: std::collections::HashSet<u32> = (1..=MAX_OPERATOR_RULE_ID)
            .filter_map(tenant_rule_code)
            .collect();
        let policy: std::collections::HashSet<u32> = (1..=MAX_OPERATOR_RULE_ID)
            .filter_map(policy_rule_code)
            .collect();
        assert_eq!(tenant.len(), MAX_OPERATOR_RULE_ID as usize);
        assert_eq!(policy.len(), MAX_OPERATOR_RULE_ID as usize);
        assert!(
            tenant.is_disjoint(&policy),
            "a tenant rule and a policy rule can report the same code"
        );
    }

    #[test]
    fn built_in_baseline_codes_stay_clear_of_the_engine_codes() {
        for id in 1..=BUILTIN_RULE_MAX_ID {
            let c = builtin_rule_code(id).unwrap();
            assert!(
                (201..=299).contains(&c),
                "baseline id {} produced {}",
                id,
                c
            );
            assert_ne!(c, PAYLOAD_TOO_LARGE);
            assert_ne!(c, INTERNAL_ERROR);
            for &r in RESERVED {
                assert_ne!(c, r, "baseline id {} collides with reserved {}", id, r);
            }
        }
    }

    #[test]
    fn out_of_range_ids_produce_no_code_at_all() {
        assert_eq!(tenant_rule_code(0), None);
        assert_eq!(policy_rule_code(0), None);
        assert_eq!(tenant_rule_code(MAX_OPERATOR_RULE_ID + 1), None);
        assert_eq!(policy_rule_code(MAX_OPERATOR_RULE_ID + 1), None);
        assert_eq!(tenant_rule_code(u32::MAX), None);
        assert_eq!(builtin_rule_code(BUILTIN_RULE_MAX_ID + 1), None);
    }

    // The SIEM contract: a code off the wire resolves to exactly one producer,
    // and the rule id comes back without consulting any configuration.
    #[test]
    fn classification_round_trips_for_every_operator_rule() {
        for id in 1..=MAX_OPERATOR_RULE_ID {
            assert_eq!(
                classify(tenant_rule_code(id).unwrap()),
                CodeClass::TenantRule { id },
                "tenant id {} did not round-trip",
                id
            );
            assert_eq!(
                classify(policy_rule_code(id).unwrap()),
                CodeClass::PolicyRule { id },
                "policy id {} did not round-trip",
                id
            );
        }
    }

    #[test]
    fn an_engine_fault_is_never_mistaken_for_a_detection() {
        assert_eq!(classify(INTERNAL_ERROR), CodeClass::EngineFault);
        assert!(!classify(INTERNAL_ERROR).is_detection());
        // ...and nothing else classifies as a fault.
        for id in 1..=MAX_OPERATOR_RULE_ID {
            assert_ne!(
                classify(tenant_rule_code(id).unwrap()),
                CodeClass::EngineFault
            );
            assert_ne!(
                classify(policy_rule_code(id).unwrap()),
                CodeClass::EngineFault
            );
        }
        for id in 1..=BUILTIN_RULE_MAX_ID {
            assert_ne!(
                classify(builtin_rule_code(id).unwrap()),
                CodeClass::EngineFault
            );
        }
        for &r in RESERVED {
            if r != INTERNAL_ERROR {
                assert!(classify(r).is_detection() || r == GREY_NO_SEMANTIC || r == SEMANTIC);
            }
        }
    }

    // The specific collision reported in the audit, pinned so it cannot return.
    #[test]
    fn the_reported_collisions_are_gone() {
        // A tenant rule with id 300 used to derive exactly INTERNAL_ERROR.
        assert_ne!(tenant_rule_code(300).unwrap(), INTERNAL_ERROR);
        assert_eq!(
            classify(tenant_rule_code(300).unwrap()),
            CodeClass::TenantRule { id: 300 }
        );
        // A policy rule id 1 and a tenant rule id 301 both used to derive 501.
        assert_ne!(policy_rule_code(1).unwrap(), tenant_rule_code(301).unwrap());
        // A tenant rule with id 213 used to land on the size-guard code.
        assert_ne!(tenant_rule_code(213).unwrap(), PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn codes_outside_every_band_are_reported_as_unknown_not_guessed() {
        assert_eq!(classify(TENANT_RULE_BASE), CodeClass::Unknown);
        assert_eq!(classify(POLICY_RULE_BASE), CodeClass::Unknown);
        assert_eq!(
            classify(TENANT_RULE_BASE + MAX_OPERATOR_RULE_ID + 1),
            CodeClass::Unknown
        );
        assert_eq!(classify(u32::MAX), CodeClass::Unknown);
        assert!(!classify(u32::MAX).is_detection());
    }
}
