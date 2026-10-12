//! The Fortanix tenancy check (PRD-06 P0 "customer-controlled tenancy", P1 "separation of
//! duties"): given who holds what in a Fortanix CCM or DSM account, decide whether any
//! AlphaCompute identity holds a CCM policy right or a DSM key-admin right there, and whether
//! anyone on the separation-of-duties roster who is a Rafay admin, an infrastructure admin, a
//! release-key holder, a custodian or a platform org key holder also holds a Fortanix admin role.
//!
//! It only reads. The listing comes either from an export the customer's security admin made
//! ([`dsm::parse_export`], [`ccm::parse_export`]) or from a live read with a read-only login the
//! customer granted ([`dsm::fetch`]). Nothing here can change the account.
//!
//! **Draft (PRD-06).** Every Fortanix-specific value (role names, permission names, endpoints,
//! listing shapes) is an [`Assumption`] tied to the vendor question that settles it. Until an
//! assumption is confirmed the check never passes: with no violation found it says
//! [`Verdict::Unconfirmed`], which callers treat as a failure. A role or permission the check
//! does not know is [`Right::Unknown`] and counts as an admin right.
//!
//! The procedure this serves is alpha-infra `docs/fortanix-tenancy.md` (onboarding and the
//! quarterly audit) and `docs/separation-of-duties.md` (the roster and its roles).

pub mod ccm;
pub mod dsm;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REPORT_FORMAT: &str = "alphacompute-fortanix-tenancy-report/1";
pub const ROSTER_FORMAT: &str = "alphacompute-sod-roster/1";
pub const ACCOUNT_FORMAT: &str = "alphacompute-fortanix-account/1";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Input(String),
    #[error("{0}")]
    Dsm(#[from] crate::Error),
    /// A path the draft does not implement yet; it refuses rather than guess.
    #[error("not implemented in this draft: {0}")]
    NotImplemented(String),
}

/// One Fortanix-specific value this check relies on that Fortanix has not confirmed.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Assumption {
    pub id: &'static str,
    /// The vendor question on the PRD's questions page that settles it.
    pub question: &'static str,
    /// The open question in the PR and the code (`QUESTION(PRD-06 Qn)`).
    pub open_question: &'static str,
    pub text: &'static str,
    /// Flipped to true, in a reviewed commit, only once the vendor's answer confirms the text.
    pub confirmed: bool,
}

// QUESTION(PRD-06 Q1): DSM role names and which of them are key-admin rights.
// QUESTION(PRD-06 Q2): DSM App permission names and how each is classified.
// QUESTION(PRD-06 Q3): CCM role names and which of them are policy rights.
// QUESTION(PRD-06 Q4): DSM listing endpoints, paging, and the auditor login.
// QUESTION(PRD-06 Q5): what CCM lists, and how.
pub const ASSUMPTIONS: &[Assumption] = &[
    Assumption {
        id: "dsm-roles",
        question: "F3",
        open_question: "Q1",
        text: "DSM user roles: ACCOUNTADMINISTRATOR and GROUPADMINISTRATOR administer keys; \
               ACCOUNTAUDITOR and GROUPAUDITOR only read; ACCOUNTMEMBER alone grants no key or \
               policy right. Custom roles (any other value) are unknown and count as admin.",
        confirmed: false,
    },
    Assumption {
        id: "dsm-app-permissions",
        question: "F3",
        open_question: "Q2",
        text: "DSM App group permissions: SIGN, VERIFY, ENCRYPT, DECRYPT, WRAPKEY, UNWRAPKEY, \
               DERIVEKEY, MACGENERATE, MACVERIFY, EXPORT, AGREEKEY, MASKDECRYPT and TRANSFORM \
               use or read keys; AUDIT only reads; MANAGE and every other value administer keys.",
        confirmed: false,
    },
    Assumption {
        id: "dsm-listing",
        question: "F3",
        open_question: "Q4",
        text: "GET /sys/v1/users, /sys/v1/apps and /sys/v1/groups, paged by limit and offset, \
               list every principal of the selected account with account_role and groups; an \
               ACCOUNTAUDITOR user may call them after POST /sys/v1/session/auth and \
               /sys/v1/session/select_account.",
        confirmed: false,
    },
    Assumption {
        id: "ccm-roles",
        question: "F3",
        open_question: "Q3",
        text: "CCM account roles: ACCOUNT_ADMINISTRATOR and ACCOUNT_MEMBER can change \
               attestation policy (approve builds, apps or nodes); READ_ONLY and \
               ACCOUNT_AUDITOR only read. Anything else is unknown and counts as admin.",
        confirmed: false,
    },
    Assumption {
        id: "ccm-listing",
        question: "F3",
        open_question: "Q5",
        text: "The customer can export every CCM user and API principal with its roles; this \
               draft reads that export in its own shape (alphacompute-ccm-listing/0) because \
               CCM's listing API is not known.",
        confirmed: false,
    },
];

fn assumption(id: &str) -> Option<&'static Assumption> {
    ASSUMPTIONS.iter().find(|a| a.id == id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Service {
    Dsm,
    Ccm,
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Dsm => "DSM",
            Self::Ccm => "CCM",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalKind {
    User,
    App,
}

/// What a grant lets its holder do, as this check classifies it. Ordered by weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Right {
    /// Reads metadata or audit logs; changes nothing and reads no key.
    ReadOnly,
    /// Listed in the account with no right over keys or policy of its own.
    Member,
    /// Uses or exports keys (DSM crypto operations).
    KeyUse,
    /// CCM policy or DSM key administration.
    Admin,
    /// A role or permission this check does not know: treated as [`Right::Admin`].
    Unknown,
}

impl Right {
    pub fn is_admin(self) -> bool {
        matches!(self, Self::Admin | Self::Unknown)
    }
}

/// One role or permission a principal holds, in one scope (the account, or one group).
#[derive(Clone, Debug, Serialize)]
pub struct Grant {
    pub scope: String,
    /// As the listing spelled it.
    pub role: String,
    pub right: Right,
    /// The [`Assumption`] the classification rests on.
    pub assumption: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Principal {
    pub service: Service,
    pub kind: PrincipalKind,
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub grants: Vec<Grant>,
}

impl Principal {
    /// The heaviest right any grant gives, if it holds any.
    pub fn strongest(&self) -> Option<Right> {
        self.grants.iter().map(|g| g.right).max()
    }

    fn label(&self) -> String {
        let who = self
            .email
            .as_deref()
            .or(self.name.as_deref())
            .unwrap_or(self.id.as_str());
        format!("{} {:?} {who} ({})", self.service, self.kind, self.id)
    }
}

/// Everyone a listing names in one service of one account, and where the listing came from.
#[derive(Clone, Debug, Serialize)]
pub struct Listing {
    pub service: Service,
    /// `export:<file>` or `live:<endpoint>`.
    pub source: String,
    /// SHA-256 of the listing's bytes, so the audit record can name exactly what was checked.
    pub sha256: String,
    /// The assumptions the listing's shape rests on.
    pub assumptions: Vec<&'static str>,
    pub principals: Vec<Principal>,
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Uppercase letters and digits only, so `Account Administrator`, `ACCOUNT_ADMINISTRATOR` and
/// `ACCOUNTADMINISTRATOR` compare equal.
pub(crate) fn normalize(role: &str) -> String {
    role.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

// --- the roster and the account record ----------------------------------------------------------

/// The roles of alpha-infra `docs/separation-of-duties.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    ReleaseKeyHolder,
    Custodian,
    PlatformOrgKeyHolder,
    InfrastructureAdmin,
    RafayAdmin,
    FortanixAdmin,
}

impl Role {
    /// Roles whose holders may hold no Fortanix admin role (PRD-06 P1, doc 08 section 4).
    pub fn excludes_fortanix_admin(self) -> bool {
        !matches!(self, Self::FortanixAdmin)
    }
}

/// One person on the separation-of-duties roster, with every identity they use.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Person {
    pub name: String,
    pub roles: BTreeSet<Role>,
    /// Every address the person might sign in to Fortanix with, work or not.
    #[serde(default)]
    pub emails: Vec<String>,
    /// Fortanix user ids (CCM or DSM) recorded for the person.
    #[serde(default)]
    pub fortanix_ids: Vec<String>,
}

/// The roster `docs/separation-of-duties.md` keeps at `<roster location>`, in the shape this
/// check reads.
// QUESTION(PRD-06 Q9): this format is new; the roster's owner decides whether it is kept in it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roster {
    pub format: String,
    /// Email domains that are AlphaCompute's, e.g. `alphacompute.ai`.
    pub domains: Vec<String>,
    pub people: Vec<Person>,
}

impl Roster {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let roster: Self =
            serde_json::from_slice(bytes).map_err(|e| Error::Input(format!("roster: {e}")))?;
        if roster.format != ROSTER_FORMAT {
            return Err(Error::Input(format!(
                "roster: format is {:?}, not {ROSTER_FORMAT}",
                roster.format
            )));
        }
        if roster.domains.iter().any(|d| d.trim().is_empty()) {
            return Err(Error::Input("roster: an empty domain".into()));
        }
        if roster.domains.is_empty() {
            return Err(Error::Input(
                "roster: names no AlphaCompute email domain".into(),
            ));
        }
        if let Some(p) = roster.people.iter().find(|p| p.roles.is_empty()) {
            return Err(Error::Input(format!("roster: {} holds no role", p.name)));
        }
        Ok(roster)
    }
}

/// Whose account it is (alpha-infra `docs/fortanix-tenancy.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tenancy {
    /// The customer's own CCM/DSM account: no AlphaCompute identity in it at all, beyond the
    /// credentials recorded at onboarding, and none of those with an admin right.
    Customer,
    /// An AlphaCompute-administered account for a customer who accepted that in writing. Its
    /// admins are Fortanix admins under the roster.
    CustomerException,
    /// AlphaCompute's own DSM (PRD-06 I3). Its admins are Fortanix admins under the roster.
    Own,
}

/// Why AlphaCompute holds a credential in the account. Each purpose allows certain rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    /// The I1 trusted-CA App that Instances of one App or Revision authenticate as.
    Workload,
    /// A read-only login the customer granted for this check.
    Audit,
    /// What the Fortanix node agents need (F4).
    NodeAgent,
}

impl Purpose {
    // QUESTION(PRD-06 Q8): the rights each recorded credential may hold. The node agents'
    // needs are F4; until it is answered they may hold nothing but read-only.
    fn allows(self, right: Right) -> bool {
        match self {
            Self::Workload => right == Right::KeyUse,
            Self::Audit | Self::NodeAgent => right == Right::ReadOnly,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub service: Service,
    /// The principal id the listing shows for it (user id or App uuid).
    pub id: String,
    pub purpose: Purpose,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccount {
    /// `https://` base URL.
    pub endpoint: String,
    pub account_id: String,
    /// CA(s) for a live read; none means only an export can be checked.
    #[serde(default)]
    pub ca_pem: Option<String>,
}

/// The onboarding record of one Fortanix account (`<onboarding record>` in
/// `docs/fortanix-tenancy.md`), in the shape this check reads.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub format: String,
    /// Customer name, or `AlphaCompute` for [`Tenancy::Own`].
    pub owner: String,
    pub tenancy: Tenancy,
    #[serde(default)]
    pub dsm: Option<ServiceAccount>,
    #[serde(default)]
    pub ccm: Option<ServiceAccount>,
    /// Every credential AlphaCompute holds for the account, as recorded at onboarding.
    #[serde(default)]
    pub credentials: Vec<Credential>,
    /// For [`Tenancy::CustomerException`]: where the customer's written acceptance is kept.
    #[serde(default)]
    pub accepted_in_writing: Option<String>,
}

impl Account {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let account: Self =
            serde_json::from_slice(bytes).map_err(|e| Error::Input(format!("account: {e}")))?;
        if account.format != ACCOUNT_FORMAT {
            return Err(Error::Input(format!(
                "account: format is {:?}, not {ACCOUNT_FORMAT}",
                account.format
            )));
        }
        if account.dsm.is_none() && account.ccm.is_none() {
            return Err(Error::Input(
                "account: names neither a DSM nor a CCM".into(),
            ));
        }
        for s in [&account.dsm, &account.ccm].into_iter().flatten() {
            if !s.endpoint.starts_with("https://") {
                return Err(Error::Input(format!(
                    "account: {} is not an https:// URL",
                    s.endpoint
                )));
            }
        }
        Ok(account)
    }

    pub fn service(&self, service: Service) -> Option<&ServiceAccount> {
        match service {
            Service::Dsm => self.dsm.as_ref(),
            Service::Ccm => self.ccm.as_ref(),
        }
    }
}

// --- the check ---------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Note,
    /// An assumption the result rests on is not confirmed; the check cannot pass.
    Unconfirmed,
    /// A breach of the tenancy or of separation of duties.
    Violation,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub rule: &'static str,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Pass,
    /// No violation found, but under unconfirmed assumptions: not a pass.
    Unconfirmed,
    Fail,
}

impl Verdict {
    /// The CLI's exit status: only a pass is 0.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Pass => 0,
            Self::Fail => 1,
            Self::Unconfirmed => 3,
        }
    }
}

/// How a principal was recognised as AlphaCompute's, if it was.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "by")]
pub enum Match {
    /// A credential recorded in the account record.
    Recorded { purpose: Purpose },
    /// Someone on the roster, by email or Fortanix id.
    Person { name: String, roles: Vec<Role> },
    /// An address in an AlphaCompute domain that is on no roster entry.
    Domain { email: String },
}

#[derive(Clone, Debug, Serialize)]
pub struct Checked {
    #[serde(flatten)]
    pub principal: Principal,
    pub alphacompute: Option<Match>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Source {
    pub service: Service,
    pub source: String,
    pub sha256: String,
}

/// The audit record: what was read, who holds what, and what is wrong.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub format: &'static str,
    pub generated_at: String,
    pub owner: String,
    pub tenancy: Tenancy,
    pub verdict: Verdict,
    pub sources: Vec<Source>,
    pub findings: Vec<Finding>,
    /// Every principal holding an admin or key right, AlphaCompute's or not, for the customer's
    /// review; and every AlphaCompute principal whatever it holds.
    pub principals: Vec<Checked>,
    pub assumptions: Vec<Assumption>,
}

fn email_domain(email: &str) -> Option<String> {
    email
        .rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase())
}

fn identify(principal: &Principal, roster: &Roster, account: &Account) -> Option<Match> {
    if let Some(c) = account
        .credentials
        .iter()
        .find(|c| c.service == principal.service && c.id == principal.id)
    {
        return Some(Match::Recorded { purpose: c.purpose });
    }
    let email = principal.email.as_deref().map(str::to_ascii_lowercase);
    if let Some(p) = roster.people.iter().find(|p| {
        p.fortanix_ids.contains(&principal.id)
            || email
                .as_deref()
                .is_some_and(|e| p.emails.iter().any(|x| x.eq_ignore_ascii_case(e)))
    }) {
        return Some(Match::Person {
            name: p.name.clone(),
            roles: p.roles.iter().copied().collect(),
        });
    }
    let email = email?;
    let domain = email_domain(&email)?;
    let ours = roster.domains.iter().any(|d| {
        let d = d.trim().to_ascii_lowercase();
        domain == d || domain.ends_with(&format!(".{d}"))
    });
    ours.then_some(Match::Domain { email })
}

fn roster_findings(roster: &Roster, findings: &mut Vec<Finding>) {
    for p in &roster.people {
        if !p.roles.contains(&Role::FortanixAdmin) {
            continue;
        }
        let other: Vec<_> = p
            .roles
            .iter()
            .filter(|r| r.excludes_fortanix_admin())
            .collect();
        if !other.is_empty() {
            findings.push(Finding {
                severity: Severity::Violation,
                rule: "sod.roster",
                detail: format!(
                    "{} is a Fortanix admin on the roster and also holds {other:?}",
                    p.name
                ),
            });
        }
    }
}

/// Rights a recorded credential holds beyond what its purpose allows.
fn beyond_purpose(principal: &Principal, purpose: Purpose) -> Vec<&Grant> {
    principal
        .grants
        .iter()
        .filter(|g| !purpose.allows(g.right))
        .collect()
}

fn grants_text(grants: &[&Grant]) -> String {
    grants
        .iter()
        .map(|g| format!("{} in {} ({:?})", g.role, g.scope, g.right))
        .collect::<Vec<_>>()
        .join(", ")
}

fn principal_findings(
    tenancy: Tenancy,
    principal: &Principal,
    matched: Option<&Match>,
    findings: &mut Vec<Finding>,
) {
    let mut violation = |rule: &'static str, detail: String| {
        findings.push(Finding {
            severity: Severity::Violation,
            rule,
            detail,
        });
    };
    if let Some(Match::Recorded { purpose }) = matched {
        let beyond = beyond_purpose(principal, *purpose);
        if !beyond.is_empty() {
            violation(
                "tenancy.credential-beyond-purpose",
                format!(
                    "{}, recorded as {purpose:?}, also holds {}",
                    principal.label(),
                    grants_text(&beyond)
                ),
            );
        }
        return;
    }
    match tenancy {
        Tenancy::Customer => {
            // "No AlphaCompute identity ... is a member of the customer's account", whatever it
            // holds; the recorded credentials are handled above.
            if let Some(m @ (Match::Person { .. } | Match::Domain { .. })) = matched {
                let rule = match principal.strongest() {
                    Some(r) if r.is_admin() => "tenancy.alphacompute-admin",
                    Some(Right::KeyUse) => "tenancy.alphacompute-key-use",
                    _ => "tenancy.alphacompute-member",
                };
                violation(
                    rule,
                    format!(
                        "{} is AlphaCompute's ({m:?}) and holds {}",
                        principal.label(),
                        grants_text(&principal.grants.iter().collect::<Vec<_>>())
                    ),
                );
            }
        }
        Tenancy::CustomerException | Tenancy::Own => {
            let admin: Vec<_> = principal
                .grants
                .iter()
                .filter(|g| g.right.is_admin())
                .collect();
            if admin.is_empty() {
                return;
            }
            match matched {
                Some(Match::Person { name, roles }) => {
                    if !roles.contains(&Role::FortanixAdmin) {
                        violation(
                            "sod.admin-not-a-fortanix-admin",
                            format!(
                                "{name} holds {} but is not a Fortanix admin on the roster",
                                grants_text(&admin)
                            ),
                        );
                    }
                    let other: Vec<_> = roles
                        .iter()
                        .filter(|r| r.excludes_fortanix_admin())
                        .collect();
                    if !other.is_empty() {
                        violation(
                            "sod.fortanix-admin-holds-another-role",
                            format!("{name} holds {} and is {other:?}", grants_text(&admin)),
                        );
                    }
                }
                _ => violation(
                    "sod.admin-not-on-roster",
                    format!(
                        "{} holds {} and is on no roster entry",
                        principal.label(),
                        grants_text(&admin)
                    ),
                ),
            }
        }
    }
}

/// Runs every rule over `listings` and returns the audit record.
pub fn check(
    account: &Account,
    roster: &Roster,
    listings: &[Listing],
    generated_at: String,
) -> Report {
    let mut findings = Vec::new();
    roster_findings(roster, &mut findings);

    if account.tenancy == Tenancy::CustomerException && account.accepted_in_writing.is_none() {
        findings.push(Finding {
            severity: Severity::Violation,
            rule: "tenancy.exception-without-acceptance",
            detail: "an AlphaCompute-administered customer account with no written acceptance \
                     recorded"
                .into(),
        });
    }

    let mut used: BTreeSet<&'static str> = BTreeSet::new();
    let mut seen: BTreeMap<Service, usize> = BTreeMap::new();
    for l in listings {
        let n = seen.entry(l.service).or_insert(0);
        *n = n.saturating_add(1);
        if account.service(l.service).is_none() {
            findings.push(Finding {
                severity: Severity::Violation,
                rule: "input.unexpected-listing",
                detail: format!(
                    "a {} listing ({}) for an account that records no {}",
                    l.service, l.source, l.service
                ),
            });
        }
        used.extend(l.assumptions.iter().copied());
    }
    for service in [Service::Dsm, Service::Ccm] {
        let count = seen.get(&service).copied().unwrap_or(0);
        if account.service(service).is_some() && count == 0 {
            findings.push(Finding {
                severity: Severity::Violation,
                rule: "input.missing-listing",
                detail: format!("the account has a {service} but no {service} listing was given"),
            });
        }
        if count > 1 {
            findings.push(Finding {
                severity: Severity::Violation,
                rule: "input.duplicate-listing",
                detail: format!("{count} {service} listings; give exactly one"),
            });
        }
    }

    let mut principals = Vec::new();
    for l in listings {
        for p in &l.principals {
            let matched = identify(p, roster, account);
            principal_findings(account.tenancy, p, matched.as_ref(), &mut findings);
            used.extend(p.grants.iter().map(|g| g.assumption));
            let worth_listing = matched.is_some()
                || p.strongest()
                    .is_some_and(|r| r.is_admin() || r == Right::KeyUse);
            if worth_listing {
                principals.push(Checked {
                    principal: p.clone(),
                    alphacompute: matched,
                });
            }
        }
    }

    for c in &account.credentials {
        let listed = listings
            .iter()
            .filter(|l| l.service == c.service)
            .flat_map(|l| &l.principals)
            .any(|p| p.id == c.id);
        if !listed {
            findings.push(Finding {
                severity: Severity::Note,
                rule: "tenancy.recorded-credential-not-listed",
                detail: format!(
                    "{} credential {} ({:?}) is recorded but not in the listing: revoked, or the \
                     listing is incomplete",
                    c.service, c.id, c.purpose
                ),
            });
        }
    }

    let assumptions: Vec<Assumption> = used
        .iter()
        .filter_map(|id| assumption(id))
        .copied()
        .collect();
    for a in assumptions.iter().filter(|a| !a.confirmed) {
        findings.push(Finding {
            severity: Severity::Unconfirmed,
            rule: "assumption.unconfirmed",
            detail: format!(
                "{} rests on Fortanix's answer to {} (PRD-06 {}): {}",
                a.id, a.question, a.open_question, a.text
            ),
        });
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let verdict = match findings.first().map(|f| f.severity) {
        Some(Severity::Violation) => Verdict::Fail,
        Some(Severity::Unconfirmed) => Verdict::Unconfirmed,
        _ => Verdict::Pass,
    };
    Report {
        format: REPORT_FORMAT,
        generated_at,
        owner: account.owner.clone(),
        tenancy: account.tenancy,
        verdict,
        sources: listings
            .iter()
            .map(|l| Source {
                service: l.service,
                source: l.source.clone(),
                sha256: l.sha256.clone(),
            })
            .collect(),
        findings,
        principals,
        assumptions,
    }
}

impl Report {
    /// The same record as Markdown, for the quarterly audit's file.
    pub fn markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Fortanix tenancy check: {}", self.owner);
        let _ = writeln!(out);
        let _ = writeln!(out, "- Generated: {}", self.generated_at);
        let _ = writeln!(out, "- Tenancy: {:?}", self.tenancy);
        let _ = writeln!(out, "- **Verdict: {:?}**", self.verdict);
        if self.verdict == Verdict::Unconfirmed {
            let _ = writeln!(
                out,
                "  (no violation found, but under Fortanix assumptions that are not confirmed; \
                 this is not a pass)"
            );
        }
        let _ = writeln!(out, "\n## Sources\n");
        for s in &self.sources {
            let _ = writeln!(
                out,
                "- {}: `{}`, sha256 `{}`",
                s.service, s.source, s.sha256
            );
        }
        let _ = writeln!(out, "\n## Findings\n");
        if self.findings.is_empty() {
            let _ = writeln!(out, "None.");
        }
        for f in &self.findings {
            let _ = writeln!(out, "- **{:?}** `{}`: {}", f.severity, f.rule, f.detail);
        }
        let _ = writeln!(
            out,
            "\n## Principals with admin or key rights, and AlphaCompute's\n"
        );
        let _ = writeln!(
            out,
            "| Service | Kind | Id | Email / name | Rights | AlphaCompute |"
        );
        let _ = writeln!(out, "|---|---|---|---|---|---|");
        for c in &self.principals {
            let p = &c.principal;
            let rights = p
                .grants
                .iter()
                .map(|g| format!("{} @ {} ({:?})", g.role, g.scope, g.right))
                .collect::<Vec<_>>()
                .join("; ");
            let who = p.email.as_deref().or(p.name.as_deref()).unwrap_or("");
            let ours = c
                .alphacompute
                .as_ref()
                .map_or_else(|| "no".to_owned(), |m| format!("{m:?}"));
            let _ = writeln!(
                out,
                "| {} | {:?} | `{}` | {} | {} | {} |",
                p.service,
                p.kind,
                p.id,
                cell(who),
                cell(&rights),
                cell(&ours)
            );
        }
        let _ = writeln!(out, "\n## Assumptions this result rests on\n");
        for a in &self.assumptions {
            let state = if a.confirmed {
                "confirmed"
            } else {
                "NOT confirmed"
            };
            let _ = writeln!(
                out,
                "- `{}` ({}, PRD-06 {}, {state}): {}",
                a.id, a.question, a.open_question, a.text
            );
        }
        out
    }
}

/// A Markdown table cell: no pipe or newline from a listing can break the table.
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster() -> Roster {
        Roster::parse(
            br#"{"format":"alphacompute-sod-roster/1","domains":["alphacompute.ai"],"people":[
              {"name":"Cus Todian","roles":["custodian"],"emails":["cus@alphacompute.ai","cus@home.example"]},
              {"name":"Raf Admin","roles":["rafay-admin"],"emails":["raf@alphacompute.ai"],"fortanix_ids":["u-raf"]},
              {"name":"For Admin","roles":["fortanix-admin"],"emails":["for@alphacompute.ai"]},
              {"name":"Two Hats","roles":["fortanix-admin","infrastructure-admin"],"emails":["two@alphacompute.ai"]}
            ]}"#,
        )
        .unwrap()
    }

    fn account(tenancy: &str, credentials: &str) -> Account {
        Account::parse(
            format!(
                r#"{{"format":"alphacompute-fortanix-account/1","owner":"Acme","tenancy":"{tenancy}",
                "dsm":{{"endpoint":"https://dsm.example","account_id":"acct-1"}},
                "credentials":{credentials}}}"#
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn user(id: &str, email: &str, role: &str, right: Right) -> Principal {
        Principal {
            service: Service::Dsm,
            kind: PrincipalKind::User,
            id: id.into(),
            name: None,
            email: Some(email.into()),
            grants: vec![Grant {
                scope: "account".into(),
                role: role.into(),
                right,
                assumption: "dsm-roles",
            }],
        }
    }

    fn listing(principals: Vec<Principal>) -> Listing {
        Listing {
            service: Service::Dsm,
            source: "export:test".into(),
            sha256: "00".into(),
            assumptions: vec!["dsm-listing"],
            principals,
        }
    }

    fn rules(report: &Report, severity: Severity) -> Vec<&'static str> {
        report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .map(|f| f.rule)
            .collect()
    }

    #[test]
    fn a_clean_customer_account_is_still_only_unconfirmed() {
        // The roster itself has a two-hats entry; use one without it.
        let mut r = roster();
        r.people.retain(|p| p.name != "Two Hats");
        let report = check(
            &account("customer", "[]"),
            &r,
            &[listing(vec![user(
                "u-1",
                "sec@acme.example",
                "ACCOUNTADMINISTRATOR",
                Right::Admin,
            )])],
            "t".into(),
        );
        assert!(rules(&report, Severity::Violation).is_empty());
        assert_eq!(report.verdict, Verdict::Unconfirmed);
        assert_eq!(report.verdict.exit_code(), 3);
        // The customer's own admin is listed for their review, not flagged.
        assert_eq!(report.principals.len(), 1);
        assert_eq!(report.principals[0].alphacompute, None);
    }

    #[test]
    fn any_alphacompute_identity_in_a_customer_account_fails() {
        let report = check(
            &account("customer", "[]"),
            &roster(),
            &[listing(vec![
                user("u-a", "cus@home.example", "ACCOUNTMEMBER", Right::Member),
                user("u-raf", "x@y.example", "GROUPADMINISTRATOR", Right::Admin),
                user(
                    "u-c",
                    "New.Hire@Ops.AlphaCompute.ai",
                    "ACCOUNTAUDITOR",
                    Right::ReadOnly,
                ),
                user("u-d", "z@acme.example", "SOMETHINGNEW", Right::Unknown),
            ])],
            "t".into(),
        );
        let v = rules(&report, Severity::Violation);
        assert!(v.contains(&"tenancy.alphacompute-member"), "{v:?}");
        assert!(v.contains(&"tenancy.alphacompute-admin"), "{v:?}");
        // By domain, on no roster entry, case-insensitive, subdomain included.
        assert!(
            report
                .principals
                .iter()
                .any(|c| matches!(&c.alphacompute, Some(Match::Domain { .. })))
        );
        assert_eq!(report.verdict, Verdict::Fail);
        // The customer's unknown-role principal is listed for review (unknown counts as admin).
        assert!(report.principals.iter().any(|c| c.principal.id == "u-d"));
    }

    #[test]
    fn recorded_credentials_may_hold_only_what_their_purpose_allows() {
        let creds = r#"[{"service":"dsm","id":"app-w","purpose":"workload"},
                        {"service":"dsm","id":"u-audit","purpose":"audit"},
                        {"service":"dsm","id":"gone","purpose":"node-agent"}]"#;
        let app = |perm: &str, right| Principal {
            kind: PrincipalKind::App,
            ..user("app-w", "", perm, right)
        };
        let ok = check(
            &account("customer", creds),
            &roster(),
            &[listing(vec![
                app("EXPORT", Right::KeyUse),
                user(
                    "u-audit",
                    "audit@alphacompute.ai",
                    "ACCOUNTAUDITOR",
                    Right::ReadOnly,
                ),
            ])],
            "t".into(),
        );
        let v = rules(&ok, Severity::Violation);
        assert!(v.iter().all(|r| *r == "sod.roster"), "{v:?}");
        assert!(rules(&ok, Severity::Note).contains(&"tenancy.recorded-credential-not-listed"));

        let bad = check(
            &account("customer", creds),
            &roster(),
            &[listing(vec![
                app("MANAGE", Right::Admin),
                user(
                    "u-audit",
                    "audit@alphacompute.ai",
                    "ACCOUNTMEMBER",
                    Right::Member,
                ),
            ])],
            "t".into(),
        );
        let n = rules(&bad, Severity::Violation)
            .iter()
            .filter(|r| **r == "tenancy.credential-beyond-purpose")
            .count();
        assert_eq!(n, 2);
    }

    #[test]
    fn separation_of_duties_in_an_account_we_administer() {
        let report = check(
            &account("own", "[]"),
            &roster(),
            &[listing(vec![
                user(
                    "u-f",
                    "for@alphacompute.ai",
                    "ACCOUNTADMINISTRATOR",
                    Right::Admin,
                ),
                user(
                    "u-2",
                    "two@alphacompute.ai",
                    "ACCOUNTADMINISTRATOR",
                    Right::Admin,
                ),
                user(
                    "u-raf",
                    "raf@alphacompute.ai",
                    "GROUPADMINISTRATOR",
                    Right::Admin,
                ),
                user(
                    "u-x",
                    "stranger@example.com",
                    "ACCOUNTADMINISTRATOR",
                    Right::Admin,
                ),
                user(
                    "u-c",
                    "cus@alphacompute.ai",
                    "ACCOUNTAUDITOR",
                    Right::ReadOnly,
                ),
            ])],
            "t".into(),
        );
        let v = rules(&report, Severity::Violation);
        assert!(v.contains(&"sod.roster"), "{v:?}");
        assert!(
            v.contains(&"sod.fortanix-admin-holds-another-role"),
            "{v:?}"
        );
        assert!(v.contains(&"sod.admin-not-a-fortanix-admin"), "{v:?}");
        assert!(v.contains(&"sod.admin-not-on-roster"), "{v:?}");
        // A custodian with read-only rights in our own DSM is not an admin.
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.detail.contains("Cus Todian"))
        );
        assert_eq!(report.verdict, Verdict::Fail);
    }

    #[test]
    fn missing_unexpected_and_duplicate_listings_fail() {
        let none = check(&account("customer", "[]"), &roster(), &[], "t".into());
        assert!(rules(&none, Severity::Violation).contains(&"input.missing-listing"));
        let mut ccm = listing(vec![]);
        ccm.service = Service::Ccm;
        let two = check(
            &account("customer", "[]"),
            &roster(),
            &[listing(vec![]), listing(vec![]), ccm],
            "t".into(),
        );
        let v = rules(&two, Severity::Violation);
        assert!(v.contains(&"input.duplicate-listing"));
        assert!(v.contains(&"input.unexpected-listing"));
    }

    #[test]
    fn an_exception_needs_its_written_acceptance() {
        let report = check(
            &account("customer-exception", "[]"),
            &roster(),
            &[listing(vec![])],
            "t".into(),
        );
        assert!(
            rules(&report, Severity::Violation).contains(&"tenancy.exception-without-acceptance")
        );
    }

    #[test]
    fn inputs_are_refused_unless_well_formed() {
        assert!(Roster::parse(br#"{"format":"x","domains":["a"],"people":[]}"#).is_err());
        assert!(
            Roster::parse(br#"{"format":"alphacompute-sod-roster/1","domains":[],"people":[]}"#)
                .is_err()
        );
        assert!(
            Roster::parse(
                br#"{"format":"alphacompute-sod-roster/1","domains":["a"],"people":[{"name":"n","roles":[]}]}"#
            )
            .is_err()
        );
        assert!(
            Account::parse(
                br#"{"format":"alphacompute-fortanix-account/1","owner":"o","tenancy":"customer"}"#
            )
            .is_err()
        );
        assert!(
            Account::parse(
                br#"{"format":"alphacompute-fortanix-account/1","owner":"o","tenancy":"customer","dsm":{"endpoint":"http://d","account_id":"a"}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn every_assumption_is_tied_to_a_vendor_question_and_unconfirmed() {
        for a in ASSUMPTIONS {
            assert!(a.question.starts_with('F'), "{}", a.id);
            assert!(a.open_question.starts_with('Q'), "{}", a.id);
            // Flip only in a reviewed commit that cites the vendor's answer.
            assert!(!a.confirmed, "{}", a.id);
        }
    }

    #[test]
    fn markdown_cells_cannot_break_the_table() {
        assert_eq!(cell("a|b\nc"), "a\\|b c");
        let report = check(
            &account("customer", "[]"),
            &roster(),
            &[listing(vec![user(
                "u|1",
                "raf@alphacompute.ai",
                "ACCOUNTADMINISTRATOR",
                Right::Admin,
            )])],
            "t".into(),
        );
        let md = report.markdown();
        assert!(md.contains("**Verdict: Fail**"));
        assert!(md.contains("NOT confirmed"));
    }

    #[test]
    fn role_names_normalize() {
        assert_eq!(normalize("Account Administrator"), "ACCOUNTADMINISTRATOR");
        assert_eq!(normalize("ACCOUNT_ADMINISTRATOR"), "ACCOUNTADMINISTRATOR");
    }
}
