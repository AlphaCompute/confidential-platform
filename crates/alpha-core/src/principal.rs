//! What an organization's principal key may sign (PRD-06 Q88).

use serde::{Deserialize, Serialize};

use crate::context;

/// The kind a delegated key's registration document names in `kind`, under the signature of the
/// key that registered it, so the chain walk re-reads it on every call and a database edit cannot
/// change it. A document without `kind` is a `member` key: every key registered before kinds
/// existed, and every organization's root key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyKind {
    /// Signs any Control call of its organization, and its reads.
    #[default]
    Member,
    /// Signs reads only ([`READ_CONTEXTS`]): a customer's auditor holds no key that can register
    /// or revoke a Revision, put a Secret, or register or revoke a key, and registers no key.
    Auditor,
}

/// The contexts an auditor key may sign under: requests that change nothing but the audit log's
/// record of the read itself.
pub const READ_CONTEXTS: &[&str] = &[context::DECISIONS_EXPORT];

impl KeyKind {
    /// Whether a key of this kind may sign a document under `ctx`.
    pub fn may_sign(self, ctx: &str) -> bool {
        match self {
            Self::Member => true,
            Self::Auditor => READ_CONTEXTS.contains(&ctx),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Auditor => "auditor",
        }
    }
}

impl std::fmt::Display for KeyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_auditor_key_signs_the_decisions_export_and_nothing_else() {
        for ctx in [
            context::REVISION,
            context::SECRET,
            context::CONTROL,
            context::PRINCIPAL_KEY,
            context::ORG_ROOT_KEY,
        ] {
            assert!(!KeyKind::Auditor.may_sign(ctx), "{ctx}");
            assert!(KeyKind::Member.may_sign(ctx), "{ctx}");
        }
        assert!(KeyKind::Auditor.may_sign(context::DECISIONS_EXPORT));
        assert!(KeyKind::Member.may_sign(context::DECISIONS_EXPORT));
    }

    #[test]
    fn a_kind_is_named_in_kebab_case_and_absent_means_member() {
        assert_eq!(
            serde_json::to_value(KeyKind::Auditor).unwrap(),
            serde_json::json!("auditor")
        );
        assert_eq!(
            serde_json::from_value::<KeyKind>(serde_json::json!("member")).unwrap(),
            KeyKind::Member
        );
        assert!(serde_json::from_value::<KeyKind>(serde_json::json!("admin")).is_err());
        assert_eq!(KeyKind::default(), KeyKind::Member);
    }
}
