//! `alpha kms migrate` (PRD-05 draft): production KMS by join, deliverable 11 and M4. The
//! prototype KMS nodes are replaced by Kata nodes **one node at a time, never by re-bootstrap**:
//! each Kata node joins a serving node over the existing join protocol, so the CA and every key
//! are kept, and no client changes a pin.
//!
//! The tool does not start or stop anything. Rafay deploys a Kata node (`deploy/coco/platform`,
//! #89), which joins on start; the prototype platform's tooling stops a prototype node. What the
//! tool does is decide the order, and refuse to go on unless what it observes is exactly what the
//! plan says should be true by now:
//!
//! - `plan`: the order from an inventory. Joins and stops alternate, and the serving count never
//!   drops below the quorum.
//! - `baseline`: before the first step, the serving prototype nodes' CA and key identifiers
//!   (`GET /v1/node/key-ids`), all of them equal, and equal to the platform document's
//!   `kms_ca_pem`.
//! - `verify`: every listed node, pinned to the **baseline's** CA key and the document's
//!   `kms_revisions`. Every serving node must report the baseline's identifiers, and at least
//!   `quorum` must serve. A node under another CA fails the handshake, so it never counts as
//!   serving.
//! - `step`: `verify`, then checks that every step already recorded still holds. It marks the next
//!   step done only once its effect is observed (the joined node serves with the baseline's
//!   identifiers, or the stopped node no longer serves), and prints the one action that follows.
//!   It never marks two steps at once.
//!
//! Unknowns are open questions in the PR (PRD-05 draft): the prototype inventory (Q57), the
//! key identifiers' publication (Q58), the quorum (Q59), cut-over order (Q60), rollback (Q61),
//! and whether the tool should drive Rafay and the prototype platform itself (Q62).

use std::collections::BTreeSet;

use alpha_attest::PlatformDocument;
use alpha_client::{Client, NodeKeyIds, Pin};
use alpha_core::ComposeHash;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const INVENTORY_FORMAT: &str = "alphacompute-kms-migration/1";
pub const BASELINE_FORMAT: &str = "alphacompute-kms-migration-baseline/1";
pub const STATE_FORMAT: &str = "alphacompute-kms-migration-state/1";

/// QUESTION(PRD-05 Q59): how many nodes must serve at every point. Proposed: 2, PRD-05's "stop
/// the prototype nodes one at a time, never both" read as "two serving nodes, in two failure
/// domains, throughout". The inventory may lower it only explicitly.
pub const DEFAULT_QUORUM: usize = 2;

fn default_quorum() -> usize {
    DEFAULT_QUORUM
}

/// QUESTION(PRD-05 Q57): the prototype inventory is not in this repository (the nodes' endpoints
/// live in the prototype platform's deploy secrets). The operator writes this file at M-D.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub format: String,
    #[serde(default = "default_quorum")]
    pub quorum: usize,
    /// Prototype nodes in the order they stop, Kata nodes in the order they join.
    pub nodes: Vec<InventoryNode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryNode {
    pub name: String,
    pub endpoint: String,
    pub kind: NodeKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    /// Serving at the start; stopped by the plan.
    Prototype,
    /// Not running at the start; joins by the plan.
    Kata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "node", rename_all = "kebab-case")]
pub enum Step {
    Join(String),
    Stop(String),
}

impl Step {
    pub fn node(&self) -> &str {
        match self {
            Self::Join(n) | Self::Stop(n) => n,
        }
    }

    /// What the operator does for this step.
    pub fn action(&self, inventory: &Inventory) -> String {
        let endpoint = inventory
            .nodes
            .iter()
            .find(|n| n.name == self.node())
            .map_or("", |n| n.endpoint.as_str());
        match self {
            Self::Join(n) => format!(
                "deploy the Kata KMS node {n} ({endpoint}) through Rafay; it joins a serving node \
                 on start. Then run `alpha kms migrate step` again."
            ),
            Self::Stop(n) => format!(
                "stop the prototype KMS node {n} ({endpoint}) and only that one. Then run `alpha \
                 kms migrate step` again."
            ),
        }
    }
}

impl Inventory {
    pub fn check(&self) -> Result<(), String> {
        if self.format != INVENTORY_FORMAT {
            return Err(format!("inventory: format {:?}", self.format));
        }
        if self.quorum == 0 {
            return Err("inventory: quorum must be at least 1".into());
        }
        let mut names = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for node in &self.nodes {
            if node.name.is_empty() || !names.insert(node.name.as_str()) {
                return Err(format!(
                    "inventory: node name {:?} is empty or repeated",
                    node.name
                ));
            }
            let endpoint = node.endpoint.trim_end_matches('/');
            if !endpoint.starts_with("https://") || !endpoints.insert(endpoint) {
                return Err(format!(
                    "inventory: endpoint {:?} is not https:// or is repeated",
                    node.endpoint
                ));
            }
        }
        Ok(())
    }

    fn of(&self, kind: NodeKind) -> Vec<&InventoryNode> {
        self.nodes.iter().filter(|n| n.kind == kind).collect()
    }
}

/// QUESTION(PRD-05 Q60): cut-over order. Proposed and drafted: alternate — join Kata 1, stop
/// prototype 1, join Kata 2, stop prototype 2 — so there are never more than `quorum + 1` nodes
/// and never fewer than `quorum`. Kata nodes beyond the prototype count join at the end; extra
/// prototype nodes stop at the end. Refused if any stop would leave fewer than `quorum` serving.
pub fn plan(inventory: &Inventory) -> Result<Vec<Step>, String> {
    inventory.check()?;
    let prototypes = inventory.of(NodeKind::Prototype);
    let katas = inventory.of(NodeKind::Kata);
    if prototypes.is_empty() || katas.is_empty() {
        return Err("inventory: a migration needs at least one prototype and one Kata node".into());
    }
    if prototypes.len() < inventory.quorum {
        return Err(format!(
            "inventory: {} prototype nodes serve today, fewer than the quorum {}",
            prototypes.len(),
            inventory.quorum
        ));
    }
    if katas.len() < inventory.quorum {
        return Err(format!(
            "inventory: {} Kata nodes cannot keep the quorum {} once the prototype nodes stop",
            katas.len(),
            inventory.quorum
        ));
    }
    let mut steps = Vec::new();
    let mut k = katas.iter();
    let mut p = prototypes.iter();
    loop {
        let join = k.next();
        let stop = p.next();
        if join.is_none() && stop.is_none() {
            break;
        }
        if let Some(n) = join {
            steps.push(Step::Join(n.name.clone()));
        }
        if let Some(n) = stop {
            steps.push(Step::Stop(n.name.clone()));
        }
    }
    // Simulate the serving count; the stops come last when Kata nodes run out first, which the
    // count check catches only if the quorum would break.
    let mut serving = prototypes.len();
    for step in &steps {
        serving = match step {
            Step::Join(_) => serving.saturating_add(1),
            Step::Stop(n) => {
                let left = serving.saturating_sub(1);
                if left < inventory.quorum {
                    return Err(format!(
                        "plan: stopping {n} would leave {left} serving, below the quorum {}",
                        inventory.quorum
                    ));
                }
                left
            }
        };
    }
    Ok(steps)
}

/// The identifiers every node must keep through the migration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub format: String,
    pub ca_spki_sha256: String,
    pub ca_cert_sha256: String,
    pub tenant_kek_root_id: String,
    /// The platform document version the baseline was taken under, for the record.
    pub platform_document_version: u64,
    /// The nodes the baseline was read from, and their Revisions.
    pub taken_from: Vec<Value>,
}

impl Baseline {
    fn ca_pin(&self) -> Result<[u8; 32], String> {
        let hex = self
            .ca_spki_sha256
            .strip_prefix("sha256:")
            .ok_or("baseline: ca_spki_sha256 is not sha256:<hex>")?;
        alpha_core::hex_bytes::<32>(hex).ok_or_else(|| "baseline: ca_spki_sha256".into())
    }

    /// Every way `ids` differs from the baseline.
    pub fn differences(&self, ids: &NodeKeyIds) -> Vec<String> {
        let mut out = Vec::new();
        if ids.format != alpha_client::KEY_IDS_FORMAT {
            out.push(format!("key-ids format {:?}", ids.format));
        }
        for (what, baseline, node) in [
            ("CA key", &self.ca_spki_sha256, &ids.ca_spki_sha256),
            ("CA certificate", &self.ca_cert_sha256, &ids.ca_cert_sha256),
            (
                "tenant-kek-root",
                &self.tenant_kek_root_id,
                &ids.tenant_kek_root_id,
            ),
        ] {
            if baseline != node {
                out.push(format!("{what}: {node} where the baseline has {baseline}"));
            }
        }
        out
    }
}

/// What one node looked like through the baseline's pin.
#[derive(Clone, Debug)]
pub enum Observed {
    Serving(NodeKeyIds),
    /// No handshake under the pinned CA key and Revisions, or no answer: still booting, sealed
    /// (a sealed node presents a self-signed certificate), stopped, or under another CA.
    NotServing(String),
}

impl Observed {
    pub fn serving(&self) -> bool {
        matches!(self, Self::Serving(_))
    }
}

/// `endpoint` pinned to the CA key `ca_spki` and the listed `revisions`.
pub async fn observe(endpoint: &str, ca_spki: [u8; 32], revisions: Vec<ComposeHash>) -> Observed {
    let client = match Client::new(
        vec![endpoint.to_owned()],
        Pin::CaSpkiAndRevisions(ca_spki, revisions),
    ) {
        Ok(c) => c,
        Err(e) => return Observed::NotServing(e.to_string()),
    };
    match client.ready().await {
        Ok(ready) if !ready.sealed => {}
        Ok(_) => return Observed::NotServing("sealed".into()),
        Err(e) => return Observed::NotServing(e.to_string()),
    }
    match client.node_key_ids().await {
        Ok(ids) => Observed::Serving(ids),
        Err(e) => Observed::NotServing(format!("key-ids: {e}")),
    }
}

fn revisions(doc: &PlatformDocument) -> Vec<ComposeHash> {
    doc.kms_revisions.iter().map(|r| r.compose_hash).collect()
}

fn document_ca_spki(doc: &PlatformDocument) -> Result<String, String> {
    crate::sign::ca_spki_sha256(&doc.kms_ca_pem)?
        .ok_or_else(|| "the platform document names no KMS CA".into())
}

/// Reads the baseline from the serving prototype nodes. Refused unless at least `quorum` serve,
/// they all agree, and their CA is the platform document's.
pub async fn take_baseline(
    inventory: &Inventory,
    doc: &PlatformDocument,
) -> Result<Baseline, String> {
    inventory.check()?;
    let ca = document_ca_spki(doc)?;
    let pin = Baseline {
        format: BASELINE_FORMAT.into(),
        ca_spki_sha256: ca.clone(),
        ca_cert_sha256: String::new(),
        tenant_kek_root_id: String::new(),
        platform_document_version: doc.version,
        taken_from: Vec::new(),
    }
    .ca_pin()?;
    let mut seen: Option<NodeKeyIds> = None;
    let mut taken_from = Vec::new();
    for node in inventory.of(NodeKind::Prototype) {
        match observe(&node.endpoint, pin, revisions(doc)).await {
            Observed::Serving(ids) => {
                if let Some(first) = &seen
                    && (first.ca_cert_sha256 != ids.ca_cert_sha256
                        || first.tenant_kek_root_id != ids.tenant_kek_root_id
                        || first.ca_spki_sha256 != ids.ca_spki_sha256)
                {
                    return Err(format!(
                        "baseline: {} reports other identifiers than {}; the serving nodes \
                         disagree, so there is nothing to keep",
                        node.name,
                        taken_from
                            .first()
                            .and_then(|v: &Value| v["node"].as_str())
                            .unwrap_or("the first node")
                    ));
                }
                taken_from.push(json!({ "node": node.name, "revision": ids.revision }));
                seen.get_or_insert(ids);
            }
            Observed::NotServing(why) => {
                eprintln!("baseline: {} is not serving: {why}", node.name);
            }
        }
    }
    let ids = seen.ok_or("baseline: no prototype node is serving under the document's CA")?;
    if taken_from.len() < inventory.quorum {
        return Err(format!(
            "baseline: {} prototype nodes serve, fewer than the quorum {}",
            taken_from.len(),
            inventory.quorum
        ));
    }
    if ids.ca_spki_sha256 != ca {
        return Err(format!(
            "baseline: the nodes' CA key {} is not the platform document's {ca}",
            ids.ca_spki_sha256
        ));
    }
    Ok(Baseline {
        format: BASELINE_FORMAT.into(),
        ca_spki_sha256: ids.ca_spki_sha256,
        ca_cert_sha256: ids.ca_cert_sha256,
        tenant_kek_root_id: ids.tenant_kek_root_id,
        platform_document_version: doc.version,
        taken_from,
    })
}

/// One node in a [`Report`].
#[derive(Clone, Debug, Serialize)]
pub struct NodeReport {
    pub node: String,
    pub kind: NodeKind,
    pub serving: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<ComposeHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_serving: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub differences: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub ok: bool,
    pub serving: usize,
    pub quorum: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
    pub nodes: Vec<NodeReport>,
}

impl Report {
    pub fn serving(&self, name: &str) -> bool {
        self.nodes.iter().any(|n| n.node == name && n.serving)
    }
}

/// Every listed node through the baseline's pin.
pub async fn verify(
    inventory: &Inventory,
    baseline: &Baseline,
    doc: &PlatformDocument,
) -> Result<Report, String> {
    inventory.check()?;
    if baseline.format != BASELINE_FORMAT {
        return Err(format!("baseline: format {:?}", baseline.format));
    }
    let pin = baseline.ca_pin()?;
    let mut problems = Vec::new();
    match document_ca_spki(doc) {
        Ok(ca) if ca == baseline.ca_spki_sha256 => {}
        Ok(ca) => problems.push(format!(
            "the platform document (version {}) names the CA key {ca}, not the baseline's",
            doc.version
        )),
        Err(e) => problems.push(e),
    }
    let mut nodes = Vec::new();
    for node in &inventory.nodes {
        let observed = observe(&node.endpoint, pin, revisions(doc)).await;
        let report = match observed {
            Observed::Serving(ids) => {
                let differences = baseline.differences(&ids);
                problems.extend(differences.iter().map(|d| format!("{}: {d}", node.name)));
                NodeReport {
                    node: node.name.clone(),
                    kind: node.kind,
                    serving: true,
                    revision: Some(ids.revision),
                    not_serving: None,
                    differences,
                }
            }
            Observed::NotServing(why) => NodeReport {
                node: node.name.clone(),
                kind: node.kind,
                serving: false,
                revision: None,
                not_serving: Some(why),
                differences: Vec::new(),
            },
        };
        nodes.push(report);
    }
    let serving = nodes.iter().filter(|n| n.serving).count();
    if serving < inventory.quorum {
        problems.push(format!(
            "{serving} nodes serve under the baseline CA, below the quorum {}",
            inventory.quorum
        ));
    }
    Ok(Report {
        ok: problems.is_empty(),
        serving,
        quorum: inventory.quorum,
        problems,
        nodes,
    })
}

/// The steps done so far, in plan order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub format: String,
    pub completed: Vec<Step>,
}

impl State {
    pub fn new() -> Self {
        Self {
            format: STATE_FORMAT.into(),
            completed: Vec::new(),
        }
    }
}

/// Which nodes must serve, and which must not, once `done` steps of `plan` are complete.
pub fn expected(inventory: &Inventory, plan: &[Step], done: usize) -> (Vec<String>, Vec<String>) {
    let mut serving: Vec<String> = inventory
        .of(NodeKind::Prototype)
        .iter()
        .map(|n| n.name.clone())
        .collect();
    let mut stopped = Vec::new();
    for step in plan.iter().take(done) {
        match step {
            Step::Join(n) => serving.push(n.clone()),
            Step::Stop(n) => {
                serving.retain(|s| s != n);
                stopped.push(n.clone());
            }
        }
    }
    (serving, stopped)
}

/// What `step` decided.
#[derive(Clone, Debug, Serialize)]
pub struct StepOutcome {
    /// The step marked done by this run, if its effect was observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed: Option<Step>,
    /// The next step, and what the operator does for it; `None` once the migration is done.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<Value>,
    pub report: Report,
}

/// Checks the observed state against `state`, marks at most one step done, and names the next
/// action. Refuses on any difference from the baseline, a broken quorum, a state file that is not
/// a prefix of the plan, or a node serving or stopped out of order.
pub async fn step(
    inventory: &Inventory,
    baseline: &Baseline,
    state: &mut State,
    doc: &PlatformDocument,
) -> Result<StepOutcome, String> {
    if state.format != STATE_FORMAT {
        return Err(format!("state: format {:?}", state.format));
    }
    let plan = plan(inventory)?;
    if !plan.starts_with(&state.completed) {
        return Err(
            "state: the completed steps are not the start of this inventory's plan; \
                    the inventory changed mid-migration"
                .into(),
        );
    }
    let report = verify(inventory, baseline, doc).await?;
    if !report.ok {
        return Err(format!(
            "verify failed, nothing marked: {}",
            report.problems.join("; ")
        ));
    }
    let done = state.completed.len();
    let (must_serve, must_not) = expected(inventory, &plan, done);
    for name in &must_serve {
        if !report.serving(name) {
            return Err(format!(
                "{name} must serve after {done} steps but does not; nothing marked \
                 (TODO(draft): rollback, QUESTION(PRD-05 Q61))"
            ));
        }
    }
    for name in &must_not {
        if report.serving(name) {
            return Err(format!(
                "{name} was stopped by an earlier step but serves again"
            ));
        }
    }
    let Some(pending) = plan.get(done) else {
        return Ok(StepOutcome {
            completed: None,
            next: None,
            report,
        });
    };
    let observed = match pending {
        Step::Join(n) => report.serving(n),
        Step::Stop(n) => !report.serving(n),
    };
    // A Kata node of a later step must not have joined ahead of the plan: one node at a time.
    // (A prototype node stopped early is caught above: it is still in `must_serve`.)
    for later in plan.iter().skip(done.saturating_add(1)) {
        if let Step::Join(n) = later
            && report.serving(n)
        {
            return Err(format!(
                "{n} serves before its turn (step {pending:?} is pending); one node at a time"
            ));
        }
    }
    let next_of = |i: usize| {
        plan.get(i)
            .map(|s| json!({ "step": s, "action": s.action(inventory) }))
    };
    if observed {
        state.completed.push(pending.clone());
        Ok(StepOutcome {
            completed: Some(pending.clone()),
            next: next_of(done.saturating_add(1)),
            report,
        })
    } else {
        Ok(StepOutcome {
            completed: None,
            next: next_of(done),
            report,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory(protos: usize, katas: usize, quorum: usize) -> Inventory {
        let mut nodes = Vec::new();
        for i in 0..protos {
            nodes.push(InventoryNode {
                name: format!("proto-{i}"),
                endpoint: format!("https://proto-{i}.example:8443"),
                kind: NodeKind::Prototype,
            });
        }
        for i in 0..katas {
            nodes.push(InventoryNode {
                name: format!("kata-{i}"),
                endpoint: format!("https://kata-{i}.example:8443"),
                kind: NodeKind::Kata,
            });
        }
        Inventory {
            format: INVENTORY_FORMAT.into(),
            quorum,
            nodes,
        }
    }

    #[test]
    fn two_by_two_alternates_join_and_stop() {
        let steps = plan(&inventory(2, 2, 2)).unwrap();
        assert_eq!(
            steps,
            [
                Step::Join("kata-0".into()),
                Step::Stop("proto-0".into()),
                Step::Join("kata-1".into()),
                Step::Stop("proto-1".into()),
            ]
        );
        let json = serde_json::to_value(&steps[0]).unwrap();
        assert_eq!(json, json!({ "action": "join", "node": "kata-0" }));
    }

    #[test]
    fn the_quorum_holds_or_there_is_no_plan() {
        // One Kata node cannot replace two prototypes under a quorum of two.
        assert!(
            plan(&inventory(2, 1, 2))
                .unwrap_err()
                .contains("cannot keep the quorum")
        );
        assert!(
            plan(&inventory(1, 2, 2))
                .unwrap_err()
                .contains("fewer than the quorum")
        );
        assert!(plan(&inventory(0, 2, 1)).is_err());
        assert!(plan(&inventory(2, 0, 1)).is_err());
        // Three Kata nodes for two prototypes: the extra one joins at the end.
        let steps = plan(&inventory(2, 3, 2)).unwrap();
        assert_eq!(steps.last(), Some(&Step::Join("kata-2".into())));
        assert_eq!(
            inventory(1, 1, 0).check().unwrap_err(),
            "inventory: quorum must be at least 1"
        );
    }

    #[test]
    fn an_inventory_names_each_node_and_endpoint_once_over_https() {
        let mut inv = inventory(2, 2, 2);
        inv.nodes[1].name = "proto-0".into();
        assert!(inv.check().unwrap_err().contains("repeated"));
        let mut inv = inventory(2, 2, 2);
        inv.nodes[3].endpoint = "http://kata-1.example".into();
        assert!(inv.check().unwrap_err().contains("https"));
        let mut inv = inventory(2, 2, 2);
        inv.nodes[3].endpoint = "https://kata-0.example:8443/".into();
        assert!(inv.check().unwrap_err().contains("repeated"));
        let mut inv = inventory(2, 2, 2);
        inv.format = "other".into();
        assert!(inv.check().is_err());
        let parsed: Inventory = serde_json::from_value(json!({
            "format": INVENTORY_FORMAT,
            "nodes": [{ "name": "a", "endpoint": "https://a", "kind": "prototype" }]
        }))
        .unwrap();
        assert_eq!(parsed.quorum, DEFAULT_QUORUM);
    }

    #[test]
    fn expected_sets_follow_the_plan() {
        let inv = inventory(2, 2, 2);
        let steps = plan(&inv).unwrap();
        assert_eq!(
            expected(&inv, &steps, 0),
            (vec!["proto-0".into(), "proto-1".into()], vec![])
        );
        assert_eq!(
            expected(&inv, &steps, 2),
            (
                vec!["proto-1".into(), "kata-0".into()],
                vec!["proto-0".into()]
            )
        );
        assert_eq!(
            expected(&inv, &steps, 4),
            (
                vec!["kata-0".into(), "kata-1".into()],
                vec!["proto-0".into(), "proto-1".into()]
            )
        );
    }

    fn ids(ca: &str, tenant: &str) -> NodeKeyIds {
        NodeKeyIds {
            format: alpha_client::KEY_IDS_FORMAT.into(),
            revision: ComposeHash::from([1; 32]),
            runtime_pubkey_sha256: "00".into(),
            ca_spki_sha256: ca.into(),
            ca_cert_sha256: "sha256:cert".into(),
            tenant_kek_root_id: tenant.into(),
        }
    }

    #[test]
    fn any_identifier_that_moved_is_a_difference() {
        let baseline = Baseline {
            format: BASELINE_FORMAT.into(),
            ca_spki_sha256: format!("sha256:{}", "ab".repeat(32)),
            ca_cert_sha256: "sha256:cert".into(),
            tenant_kek_root_id: "hmac-sha256:t".into(),
            platform_document_version: 1,
            taken_from: Vec::new(),
        };
        assert!(baseline.ca_pin().is_ok());
        assert!(
            baseline
                .differences(&ids(&baseline.ca_spki_sha256, "hmac-sha256:t"))
                .is_empty()
        );
        let moved = baseline.differences(&ids(&baseline.ca_spki_sha256, "hmac-sha256:other"));
        assert_eq!(moved.len(), 1);
        assert!(moved[0].starts_with("tenant-kek-root"));
        let rebootstrapped = baseline.differences(&ids("sha256:new", "hmac-sha256:new"));
        assert_eq!(rebootstrapped.len(), 2);
        let mut cert = ids(&baseline.ca_spki_sha256, "hmac-sha256:t");
        cert.ca_cert_sha256 = "sha256:reissued".into();
        assert!(baseline.differences(&cert)[0].starts_with("CA certificate"));
    }
}
