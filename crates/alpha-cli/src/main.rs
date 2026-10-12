#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use alpha_attest::PlatformDocument;
use alpha_cli::call::Route;
use alpha_cli::deploy::{Shroud, wrap};
use alpha_cli::keyfile::{self, Algorithm};
use alpha_cli::request::Call;
use alpha_cli::{coco, custodians, instances, node, sign};
use alpha_client::platform::SignedDocument;
use alpha_client::{Client, Pin};
use alpha_core::{AppId, KeyId, OrgId, PrincipalId};
use alpha_crypto::PublicKey;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};

/// The alphacompute CLI: keys, Control calls, the platform document, deploys, and the
/// custodians' bootstrap, unseal and rotation.
#[derive(Parser)]
#[command(name = "alpha", version)]
struct Cli {
    #[command(flatten)]
    config: Config,
    #[command(subcommand)]
    command: Command,
}

/// Everything from flags or `ALPHACOMPUTE_*`; each command asks for what it needs.
#[derive(Args)]
struct Config {
    /// Comma-separated KMS endpoints, tried in turn.
    #[arg(
        long,
        global = true,
        env = "ALPHACOMPUTE_KMS_ENDPOINTS",
        value_delimiter = ','
    )]
    endpoints: Vec<String>,
    /// The release-signed platform document.
    #[arg(long, global = true, env = "ALPHACOMPUTE_PLATFORM_DOCUMENT_URL")]
    platform_document_url: Option<String>,
    /// PCCS for DCAP collateral.
    #[arg(
        long,
        global = true,
        env = "ALPHACOMPUTE_PCCS_URL",
        default_value = "https://pccs.phala.network"
    )]
    pccs_url: String,
    #[arg(long, global = true, env = "ALPHACOMPUTE_SHROUD_URL")]
    shroud_url: Option<String>,
    #[arg(
        long,
        global = true,
        env = "ALPHACOMPUTE_SHROUD_API_KEY",
        hide_env_values = true
    )]
    shroud_api_key: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// A new key under a passphrase; prints the public key for registration.
    Keygen {
        /// Ed25519 admin key (prints its SPKI DER, base64url).
        #[arg(
            long,
            conflicts_with = "custodian",
            required_unless_present = "custodian"
        )]
        admin: bool,
        /// X-Wing custodian key (prints its 1216-byte public key, base64url).
        #[arg(long)]
        custodian: bool,
        #[arg(long)]
        out: PathBuf,
    },
    /// One signed Control call; the path comes from the payload.
    Call {
        route: Route,
        /// Signing context; defaults to the route's.
        #[arg(long)]
        context: Option<String>,
        /// Admin key file.
        #[arg(long)]
        key: PathBuf,
        /// The key's id in the KMS roster.
        // ponytail: the key file does not record its roster id; the admin keeps it from the
        // registration or bootstrap reply. Record it in the file when the second admin asks.
        #[arg(long)]
        key_id: KeyId,
        /// put-secret only: file holding the secret's bytes.
        #[arg(long)]
        value: Option<PathBuf>,
        payload: PathBuf,
    },
    /// Register the organization's root key, which signs for itself and claims the
    /// organization's identifier once and for all.
    RegisterRootKey {
        /// The key to register; it signs its own registration.
        #[arg(long)]
        key: PathBuf,
        /// The organization's identifier, as the console shows it.
        #[arg(long)]
        org_id: OrgId,
        /// The Principal the key acts for.
        #[arg(long)]
        principal_id: PrincipalId,
        #[arg(long, default_value = "root key")]
        label: String,
    },
    /// Sign a platform document with the release key, or check a signed artifact.
    Sign {
        #[arg(long, conflicts_with = "check", required_unless_present = "check")]
        release_key: Option<PathBuf>,
        /// Verify with the compiled-in key and print version, CA SPKI hash and Revisions.
        #[arg(long)]
        check: bool,
        document: PathBuf,
    },
    /// Tenant YAML, or the output of `alpha compose wrap` → Revision → shroud-go deploy.
    Deploy {
        /// Register the Revision and stop before shroud-go.
        #[arg(long)]
        register_only: bool,
        /// After deploying, probe every copy shroud-go returned, all within this many seconds,
        /// and fail unless each answers with a leaf from the KMS CA naming this Revision.
        #[arg(long, value_name = "SECONDS")]
        wait: Option<u64>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        key_id: KeyId,
        /// The JSON `alpha compose wrap` printed; its compose is registered and deployed byte for
        /// byte.
        #[arg(long, conflicts_with = "app", requires_all = ["cpu", "memory_mib"])]
        compose: Option<PathBuf>,
        /// The CVM's CPU count, for a wrapped compose.
        #[arg(long, requires = "compose", conflicts_with = "app")]
        cpu: Option<u64>,
        /// The CVM's memory, for a wrapped compose.
        #[arg(long, requires = "compose", conflicts_with = "app")]
        memory_mib: Option<u64>,
        #[arg(required_unless_present = "compose")]
        app: Option<PathBuf>,
    },
    /// A customer's plain docker-compose as a Revision.
    Compose {
        #[command(subcommand)]
        command: ComposeCommand,
    },
    /// Catalog entries signed with the catalog key.
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
    /// An App's running copies through shroud-go.
    Instances {
        #[arg(long)]
        app: AppId,
        #[command(subcommand)]
        command: InstancesCommand,
    },
    /// One HTTP request to one or every live copy of an App, each checked first to present a
    /// leaf from the KMS CA naming this App; prints `{"responses": [...]}`, one per copy.
    Request {
        #[arg(long)]
        app: AppId,
        #[arg(long, conflicts_with = "all", required_unless_present = "all")]
        instance: Option<uuid::Uuid>,
        /// Every copy shroud-go lists, running or draining.
        #[arg(long)]
        all: bool,
        /// File holding the bearer the App's route expects; never taken from the command line.
        #[arg(long)]
        bearer_file: PathBuf,
        /// JSON request body.
        #[arg(long)]
        body: Option<String>,
        method: reqwest::Method,
        path: String,
    },
    /// Hand one custodian's share to an attested sealed node.
    Unseal {
        #[arg(long)]
        share: PathBuf,
        /// Custodian key file.
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        endpoint: String,
    },
    /// Genesis on an empty database: three custodian public keys.
    Bootstrap {
        /// Three files, each holding a custodian's public key as `keygen --custodian` printed it.
        #[arg(long, value_delimiter = ',', num_args = 3)]
        custodians: Vec<PathBuf>,
        #[arg(long)]
        endpoint: String,
    },
    /// Replace the custodians: a new root KEK split to three new keys, approved by two current
    /// custodians; the old shares open nothing afterwards.
    Custodians {
        #[command(subcommand)]
        command: CustodiansCommand,
    },
    /// CoCo Kubernetes pod-spec rendering (init-data, Kata annotation, Revision v2).
    Coco {
        #[command(subcommand)]
        command: CocoCommand,
    },
}

#[derive(Subcommand)]
enum CocoCommand {
    /// Render a CoCo pod-spec template with init-data and the Revision v2, or prepare it for
    /// genpolicy. Prints the rendered manifest to stdout; revision info to stderr.
    ///
    /// Workflow:
    ///   1. alpha coco render --spec pod.yaml --for-genpolicy --env cluster.env > for_genpolicy.yaml
    ///   2. alpha coco genpolicy-settings --out gp; genpolicy -y for_genpolicy.yaml -p gp/rules.rego -j gp -r > policy.rego
    ///   3. alpha coco render --spec pod.yaml --policy policy.rego --env cluster.env
    Render {
        /// The YAML spec template (`${VARIABLE}` placeholders filled from --env files).
        #[arg(long)]
        spec: PathBuf,
        /// The agent policy genpolicy 4.1.0 printed under `genpolicy-settings`; refused unless it
        /// holds the baseline and admits exactly the spec's containers. Required unless
        /// --for-genpolicy is set.
        #[arg(long, conflicts_with = "for_genpolicy")]
        policy: Option<PathBuf>,
        /// Render with an empty CC_INIT_DATA annotation for genpolicy input (no policy needed).
        #[arg(long)]
        for_genpolicy: bool,
        /// KEY=VALUE files (# comments; values must not contain \" \' ` \\ $ or newlines).
        /// APP_ID (lower-case UUID) and, when the spec requests GPUs, GPU_MODEL must be set.
        #[arg(long = "env", value_name = "FILE")]
        env_files: Vec<PathBuf>,
        /// An encrypted persistent volume, `<name>:<size>:<container>:<mount path>`: adds its
        /// block-mode claim, the alpha-volume init container and the container's mount.
        #[arg(long = "volume", value_name = "VOLUME")]
        volumes: Vec<String>,
        /// The alpha-volume image, pinned by digest; required with --volume, and one the
        /// platform document lists in `alpha_volume_images`.
        #[arg(long, requires = "platform")]
        volume_image: Option<String>,
        /// The signed platform document, as `alpha sign --check` reads it; required with
        /// --volume, whose image it must list.
        #[arg(long)]
        platform: Option<PathBuf>,
    },
    /// A customer's docker-compose as one Kata confidential pod of a shape. Prints
    /// `{revision, revision_hash, initdata, pod_spec, secrets}`; runs genpolicy 4.1.0 from
    /// /opt/kata/bin/genpolicy (pinned by digest) for the agent policy.
    Wrap {
        #[arg(long)]
        app_id: AppId,
        /// The signed platform document, as `alpha compose wrap` reads it.
        #[arg(long)]
        platform: PathBuf,
        /// The `alpha-runtime` image, pinned as `<image>@sha256:<digest>`.
        #[arg(long)]
        runtime_image: String,
        /// `{"runtime_class", "gpu": {"model", "count"}, "cpu", "memory_mib"}`; no `gpu` for
        /// `kata-qemu-tdx`.
        #[arg(long)]
        shape: PathBuf,
        /// Refuse every tag instead of asking its registry for the digest.
        #[arg(long)]
        no_resolve: bool,
        /// The `alpha-volume` image, pinned by digest, for a compose that declares persistent
        /// volumes (`x-alphacompute-volumes`); without it such a compose is refused. It must be
        /// one the platform document lists in `alpha_volume_images`.
        #[arg(long)]
        volume_image: Option<String>,
        compose: PathBuf,
    },
    /// Writes genpolicy's settings directory (genpolicy 4.1.0's defaults plus the Alpha baseline
    /// drop-ins) and the patched rules.rego into a directory, for running genpolicy by hand before
    /// `render --policy`.
    GenpolicySettings {
        #[arg(long)]
        out: PathBuf,
    },
}

/// What every custodian command takes beside its own flags.
#[derive(Args)]
struct NodeFlags {
    /// The serving node, attested before anything is sent to it.
    #[arg(long)]
    endpoint: String,
    /// Skip the D9 check that a Kata node's agent policy holds the Alpha baseline; the output
    /// records `"policy_baseline": "skipped"`.
    #[arg(long)]
    no_policy_baseline: bool,
}

#[derive(Subcommand)]
enum CustodiansCommand {
    /// Writes the proposal: the attested node, a nonce it minted (five minutes) and the three new
    /// custodians' public keys. Hand it to the two approving custodians.
    Propose {
        /// Three files, each holding a new custodian's public key as `keygen --custodian` printed it.
        #[arg(long, value_delimiter = ',', num_args = 3)]
        custodians: Vec<PathBuf>,
        #[arg(long, default_value = "proposal.json")]
        out: PathBuf,
        #[command(flatten)]
        node: NodeFlags,
    },
    /// A current custodian approves the proposal with their share. The second approval rotates
    /// and writes the rotation (new shares sealed to the new custodians, and the receipt).
    Rotate {
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        share: PathBuf,
        /// Custodian key file.
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "rotation.json")]
        out: PathBuf,
        #[command(flatten)]
        node: NodeFlags,
    },
    /// A new custodian verifies the rotation and the node, then keeps their share. Without
    /// `--rotation`, the node's last committed rotation is fetched.
    Accept {
        #[arg(long)]
        rotation: Option<PathBuf>,
        /// The new custodian's key file.
        #[arg(long)]
        key: PathBuf,
        /// The new share file; it must not exist.
        #[arg(long)]
        out: PathBuf,
        #[command(flatten)]
        node: NodeFlags,
    },
}

fn read_custodian_keys(paths: &[PathBuf], flag: &str) -> Result<[PublicKey; 3], Exit> {
    let mut keys = Vec::new();
    for path in paths {
        let text = fs::read_to_string(path)
            .map_err(|e| Exit::Usage(format!("{}: {e}", path.display())))?;
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(text.trim())
            .map_err(|_| Exit::Usage(format!("{}: not base64url", path.display())))?;
        keys.push(
            PublicKey::try_from(bytes.as_slice())
                .map_err(|e| Exit::Usage(format!("{}: {e}", path.display())))?,
        );
    }
    keys.try_into()
        .map_err(|_| Exit::Usage(format!("--{flag} takes exactly three files")))
}

/// The node attested as `unseal` attests it, then its agent policy against the baseline.
async fn attested_custodian_node(
    config: &Config,
    flags: &NodeFlags,
    doc: &PlatformDocument,
    remembered: Option<u64>,
    now: SystemTime,
) -> Result<(node::AttestedNode, Client, Value), Exit> {
    let (attested, client) =
        node::attested_node(&flags.endpoint, &config.pccs_url, doc, remembered, now).await?;
    let baseline = if flags.no_policy_baseline {
        custodians::Baseline::Skip
    } else {
        custodians::Baseline::Check(custodians::alpha_baseline)
    };
    let held = custodians::check_baseline(attested.policy.as_deref(), baseline)?;
    let mut summary = attested.summary();
    if let Some(fields) = summary.as_object_mut() {
        fields.insert("policy_baseline".into(), json!(held));
    }
    Ok((attested, client, summary))
}

fn write_new(path: &Path, value: &impl serde::Serialize) -> Result<(), Exit> {
    let text =
        serde_json::to_string_pretty(value).map_err(|e| Exit::Refused(e.to_string()))? + "\n";
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()))
        .map_err(|e| Exit::Usage(format!("{}: {e}", path.display())))
}

fn read_typed<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Exit> {
    serde_json::from_value(read_json(path)?)
        .map_err(|e| Exit::Usage(format!("{}: {e}", path.display())))
}

#[derive(Subcommand)]
enum ComposeCommand {
    /// Prints `{compose_hash, compose, secrets}`: the App's `app-compose.json` with
    /// `alpha-runtime` added, and the secret names whose values the App needs.
    Wrap {
        #[arg(long)]
        app_id: AppId,
        /// The signed platform document, as `alpha sign --check` reads it; the KMS pins come from
        /// it once it verifies under the compiled-in release key.
        #[arg(long)]
        platform: PathBuf,
        /// The `alpha-runtime` image, pinned as `<image>@sha256:<digest>`.
        #[arg(long)]
        runtime_image: String,
        /// Refuse every tag instead of asking its registry for the digest.
        #[arg(long)]
        no_resolve: bool,
        compose: PathBuf,
    },
}

#[derive(Subcommand)]
enum CatalogCommand {
    /// Tenant YAML → template (the compose for the nil App id) → signed entry, written as
    /// `<template hash hex>.json`.
    Sign {
        #[arg(long)]
        id: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        title: String,
        /// The catalog key: an Ed25519 key file from `alpha keygen --admin`.
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        /// The spec `alpha deploy` reads; its `app_id` is ignored.
        app: PathBuf,
    },
}

#[derive(Subcommand)]
enum InstancesCommand {
    /// The App's live copies, running and draining.
    List,
    /// Start one more copy of the App's current Revision.
    Add {
        /// The copy's CPU count; defaults to the shape of the last deploy.
        #[arg(long, requires = "memory_mib")]
        cpu: Option<u64>,
        #[arg(long, requires = "cpu")]
        memory_mib: Option<u64>,
        /// Probe the new copy's Endpoint for this many seconds and fail unless it answers with
        /// a leaf from the KMS CA naming the App's Revision.
        #[arg(long, value_name = "SECONDS")]
        wait: Option<u64>,
    },
    /// Stop one copy: drain it by default, so its chats finish first.
    Stop {
        instance: uuid::Uuid,
        /// Delete the copy now, ending its chats.
        #[arg(long, conflicts_with = "drain_seconds")]
        force: bool,
        /// How long the copy may drain before shroud-go stops it; shroud-go's default is an
        /// hour.
        #[arg(long, value_name = "SECONDS")]
        drain_seconds: Option<u64>,
    },
}

enum Exit {
    Refused(String),
    Usage(String),
    /// Printed like a success, but some part of it failed.
    Partial(Value),
    /// The command wrote its own output; the main loop prints nothing.
    Silent,
}

impl From<String> for Exit {
    fn from(message: String) -> Self {
        Self::Refused(message)
    }
}

impl From<alpha_client::Error> for Exit {
    fn from(e: alpha_client::Error) -> Self {
        Self::Refused(e.to_string())
    }
}

fn need<T>(value: Option<T>, flag: &str) -> Result<T, Exit> {
    value.ok_or_else(|| Exit::Usage(format!("--{flag} (or ALPHACOMPUTE_*) is required")))
}

/// Prompted on the terminal; one line of stdin when stdin is a pipe.
fn passphrase(prompt: &str) -> Result<Vec<u8>, Exit> {
    let read = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map(|_| line.trim_end_matches(['\r', '\n']).to_owned())
    };
    read.map(String::into_bytes)
        .map_err(|e| Exit::Refused(format!("passphrase: {e}")))
}

fn read_json(path: &Path) -> Result<Value, Exit> {
    let text = fs::read(path).map_err(|e| Exit::Usage(format!("{}: {e}", path.display())))?;
    serde_json::from_slice(&text).map_err(|e| Exit::Usage(format!("{}: {e}", path.display())))
}

fn read_spec(path: &Path) -> Result<alpha_cli::deploy::AppSpec, Exit> {
    let text =
        fs::read_to_string(path).map_err(|e| Exit::Usage(format!("{}: {e}", path.display())))?;
    alpha_cli::deploy::parse(&text).map_err(|e| Exit::Usage(format!("{}: {e}", path.display())))
}

fn read_ed25519(path: &Path) -> Result<ed25519_dalek::SigningKey, Exit> {
    Ok(keyfile::read(path, &passphrase("passphrase: ")?)?.ed25519()?)
}

async fn platform_document(config: &Config, now: SystemTime) -> Result<PlatformDocument, Exit> {
    let url = need(
        config.platform_document_url.as_deref(),
        "platform-document-url",
    )?;
    Ok(alpha_client::platform::fetch(url, &alpha_cli::release_key()?, now).await?)
}

/// The admin's pin: `kms_ca_pem` of the platform document fetched and verified now.
async fn admin_client(config: &Config, now: SystemTime) -> Result<Client, Exit> {
    Ok(admin_client_and_document(config, now).await?.0)
}

/// The same, keeping the document: `deploy --wait` pins the Endpoint to the same `kms_ca_pem`
/// and must not fetch it twice.
async fn admin_client_and_document(
    config: &Config,
    now: SystemTime,
) -> Result<(Client, PlatformDocument), Exit> {
    let doc = platform_document(config, now).await?;
    let ca = alpha_client::tls::cert_from_pem(&doc.kms_ca_pem)?;
    if config.endpoints.is_empty() {
        return Err(Exit::Usage(
            "--endpoints (or ALPHACOMPUTE_KMS_ENDPOINTS) is required".into(),
        ));
    }
    // The CA also issues Instance leaves with the server-auth EKU, so a chain to it alone would
    // let any attested tenant Instance stand in for a node and receive a secret value.
    let revisions = doc.kms_revisions.iter().map(|r| r.compose_hash).collect();
    Ok((
        Client::new(config.endpoints.clone(), Pin::CaAndRevisions(ca, revisions))?,
        doc,
    ))
}

async fn run(cli: Cli) -> Result<Value, Exit> {
    let now = SystemTime::now();
    let config = &cli.config;
    match cli.command {
        Command::Keygen { custodian, out, .. } => {
            let algorithm = if custodian {
                Algorithm::XWing
            } else {
                Algorithm::Ed25519
            };
            let pass = passphrase("new passphrase: ")?;
            if pass != passphrase("again: ")? {
                return Err(Exit::Refused("passphrases differ".into()));
            }
            let key = keyfile::generate(algorithm, &out, &pass)?;
            Ok(json!({ "file": out, "public_key": key.public_key_text()? }))
        }
        Command::Call {
            route,
            context,
            key,
            key_id,
            value,
            payload,
        } => {
            let payload = read_json(&payload)?;
            let value = value
                .map(|p| fs::read(&p).map_err(|e| Exit::Usage(format!("{}: {e}", p.display()))))
                .transpose()?;
            let key = read_ed25519(&key)?;
            let client = admin_client(config, now).await?;
            Ok(alpha_cli::call::run(
                &client,
                route,
                context.as_deref(),
                (key_id, &key),
                payload,
                value.as_deref(),
                now,
            )
            .await?)
        }
        Command::RegisterRootKey {
            key,
            org_id,
            principal_id,
            label,
        } => {
            let key = read_ed25519(&key)?;
            let client = admin_client(config, now).await?;
            Ok(alpha_cli::call::root_key(&client, org_id, principal_id, &label, &key, now).await?)
        }
        Command::Sign {
            release_key,
            check,
            document,
        } => {
            let document = read_json(&document)?;
            if check {
                let artifact: SignedDocument = serde_json::from_value(document)
                    .map_err(|e| Exit::Refused(format!("artifact: {e}")))?;
                let summary = sign::check(&artifact, &alpha_cli::release_key()?, now)?;
                return Ok(json!(summary));
            }
            let key = read_ed25519(&need(release_key, "release-key")?)?;
            Ok(json!(sign::sign(document, &key)?))
        }
        Command::Deploy {
            register_only,
            wait,
            key,
            key_id,
            compose,
            cpu,
            memory_mib,
            app,
        } => {
            let (app_id, compose, resources) = match (compose, app) {
                (Some(path), _) => {
                    let (app_id, compose) = wrap::wrapped(&read_json(&path)?)?;
                    let resources = json!({ "cpu": cpu, "memory_mib": memory_mib });
                    (app_id, compose, resources)
                }
                (None, Some(app)) => {
                    let spec = read_spec(&app)?;
                    (
                        spec.app_id,
                        alpha_cli::deploy::compose(&spec)?,
                        spec.resources,
                    )
                }
                (None, None) => return Err(Exit::Usage("give an app spec or --compose".into())),
            };
            let shroud = if register_only {
                None
            } else {
                Some(Shroud {
                    url: need(config.shroud_url.clone(), "shroud-url")?,
                    api_key: need(config.shroud_api_key.clone(), "shroud-api-key")?,
                })
            };
            let key = read_ed25519(&key)?;
            let (client, doc) = admin_client_and_document(config, now).await?;
            let wait = wait.map(|secs| (Duration::from_secs(secs), doc.kms_ca_pem.as_str()));
            Ok(alpha_cli::deploy::deploy_compose(
                &client,
                app_id,
                compose,
                &resources,
                key_id,
                &key,
                shroud.as_ref(),
                wait,
            )
            .await?)
        }
        Command::Compose {
            command:
                ComposeCommand::Wrap {
                    app_id,
                    platform,
                    runtime_image,
                    no_resolve,
                    compose,
                },
        } => {
            let bytes = fs::read(&compose)
                .map_err(|e| Exit::Usage(format!("{}: {e}", compose.display())))?;
            let plain = wrap::parse(&bytes)?;
            let artifact: SignedDocument = serde_json::from_value(read_json(&platform)?)
                .map_err(|e| Exit::Refused(format!("artifact: {e}")))?;
            let runtime =
                wrap::runtime(&artifact, &alpha_cli::release_key()?, now, &runtime_image)?;
            let digests = if no_resolve {
                BTreeMap::new()
            } else {
                let http = wrap::registry_client_builder()
                    .build()
                    .map_err(|e| Exit::Refused(format!("registry client: {e}")))?;
                wrap::resolve_all(&http, &plain).await?
            };
            Ok(json!(wrap::wrap(plain, &digests, app_id, &runtime)?))
        }
        Command::Catalog {
            command:
                CatalogCommand::Sign {
                    id,
                    version,
                    title,
                    key,
                    out_dir,
                    app,
                },
        } => {
            let spec = read_spec(&app)?;
            let key = read_ed25519(&key)?;
            let file = alpha_cli::catalog::sign(spec, &id, &version, &title, &key)?;
            let path = out_dir.join(alpha_cli::catalog::file_name(&file));
            fs::write(&path, alpha_cli::catalog::file_bytes(&file)?)
                .map_err(|e| Exit::Refused(format!("{}: {e}", path.display())))?;
            Ok(json!({
                "file": path,
                "template_sha256": file.entry.template_sha256,
                "catalog_key": alpha_core::CatalogKey::from(&key.verifying_key()),
            }))
        }
        Command::Instances { app, command } => {
            let shroud = Shroud {
                url: need(config.shroud_url.clone(), "shroud-url")?,
                api_key: need(config.shroud_api_key.clone(), "shroud-api-key")?,
            };
            match command {
                InstancesCommand::List => Ok(instances::list(&shroud, app).await?),
                InstancesCommand::Add {
                    cpu,
                    memory_mib,
                    wait,
                } => {
                    let resources = cpu
                        .zip(memory_mib)
                        .map(|(cpu, memory_mib)| json!({ "cpu": cpu, "memory_mib": memory_mib }));
                    let doc = match wait {
                        Some(_) => Some(platform_document(config, now).await?),
                        None => None,
                    };
                    let wait = wait
                        .zip(doc.as_ref())
                        .map(|(s, d)| (Duration::from_secs(s), d.kms_ca_pem.as_str()));
                    Ok(instances::add(&shroud, app, resources, wait).await?)
                }
                InstancesCommand::Stop {
                    instance,
                    force,
                    drain_seconds,
                } => Ok(instances::stop(&shroud, app, instance, force, drain_seconds).await?),
            }
        }
        Command::Request {
            app,
            instance,
            all: _,
            bearer_file,
            body,
            method,
            path,
        } => {
            let shroud = Shroud {
                url: need(config.shroud_url.clone(), "shroud-url")?,
                api_key: need(config.shroud_api_key.clone(), "shroud-api-key")?,
            };
            let bearer = fs::read_to_string(&bearer_file)
                .map_err(|e| Exit::Usage(format!("{}: {e}", bearer_file.display())))?;
            let bearer = bearer.trim();
            if bearer.is_empty() {
                return Err(Exit::Usage(format!("{} is empty", bearer_file.display())));
            }
            // The path is appended to the copy's URL, so without the slash it could extend the host.
            if !path.starts_with('/') {
                return Err(Exit::Usage(format!("{path} does not start with /")));
            }
            let body = body
                .map(|b| serde_json::from_str::<Value>(&b))
                .transpose()
                .map_err(|e| Exit::Usage(format!("--body: {e}")))?;
            let call = Call {
                method,
                path: &path,
                bearer,
                body: body.as_ref(),
            };
            let doc = platform_document(config, now).await?;
            let (out, failed) =
                alpha_cli::request::run(&shroud, app, instance, &doc.kms_ca_pem, &call).await?;
            if failed {
                return Err(Exit::Partial(out));
            }
            Ok(out)
        }
        Command::Unseal {
            share,
            key,
            endpoint,
        } => {
            let remembered = node::ShareFile::read(&share)?.platform_document_version;
            let doc = platform_document(config, now).await?;
            let custodian = keyfile::read(&key, &passphrase("passphrase: ")?)?.xwing()?;
            let (attested, client) =
                node::attested_node(&endpoint, &config.pccs_url, &doc, Some(remembered), now)
                    .await?;
            let reply =
                node::unseal(&client, &attested.identity, &share, &custodian, doc.version).await?;
            Ok(
                json!({ "sealed": reply.sealed, "shares": reply.shares, "node": attested.summary() }),
            )
        }
        Command::Bootstrap {
            custodians,
            endpoint,
        } => {
            let custodians = read_custodian_keys(&custodians, "custodians")?;
            let doc = platform_document(config, now).await?;
            let (attested, client) =
                node::attested_node(&endpoint, &config.pccs_url, &doc, None, now).await?;
            let mut out = node::bootstrap(
                &client,
                &attested.identity,
                custodians,
                doc.version,
                Path::new("."),
            )
            .await?;
            if let Some(fields) = out.as_object_mut() {
                fields.insert("node".into(), attested.summary());
            }
            Ok(out)
        }
        Command::Coco {
            command:
                CocoCommand::Render {
                    spec,
                    policy,
                    for_genpolicy,
                    env_files,
                    volumes,
                    volume_image,
                    platform,
                },
        } => {
            let listed = match platform {
                Some(platform) => {
                    let artifact: SignedDocument = serde_json::from_value(read_json(&platform)?)
                        .map_err(|e| Exit::Refused(format!("artifact: {e}")))?;
                    coco::volume::listed_images(&artifact, &alpha_cli::release_key()?, now)
                        .map_err(Exit::Refused)?
                }
                None => BTreeSet::new(),
            };
            let volumes = coco::Volumes {
                image: volume_image,
                volumes: volumes
                    .iter()
                    .map(|v| coco::RenderVolume::parse(v))
                    .collect::<Result<_, _>>()
                    .map_err(Exit::Usage)?,
                listed,
            };
            let template = fs::read_to_string(&spec)
                .map_err(|e| Exit::Usage(format!("{}: {e}", spec.display())))?;
            let paths: Vec<&Path> = env_files.iter().map(PathBuf::as_path).collect();
            let env = coco::read_env_files(&paths).map_err(Exit::Refused)?;

            if for_genpolicy {
                let out = coco::render_volumes_for_genpolicy(&template, &env, &volumes)
                    .map_err(Exit::Refused)?;
                print!("{out}");
                return Err(Exit::Silent);
            }

            let policy_path = policy.ok_or_else(|| {
                Exit::Usage("--policy is required unless --for-genpolicy is set".into())
            })?;
            let policy_text = fs::read_to_string(&policy_path)
                .map_err(|e| Exit::Usage(format!("{}: {e}", policy_path.display())))?;

            let out = coco::render_volumes(&template, &policy_text, &env, &volumes)
                .map_err(Exit::Refused)?;
            print!("{}", out.manifest);
            eprintln!(
                "init-data {}, policy {}",
                out.revision.initdata_sha256, out.revision.policy_sha256
            );
            eprintln!("revision {}", out.revision_canonical);
            eprintln!("revision hash {}", out.revision_hash);
            Err(Exit::Silent)
        }
        Command::Coco {
            command:
                CocoCommand::Wrap {
                    app_id,
                    platform,
                    runtime_image,
                    shape,
                    no_resolve,
                    volume_image,
                    compose,
                },
        } => {
            let bytes = fs::read(&compose)
                .map_err(|e| Exit::Usage(format!("{}: {e}", compose.display())))?;
            let shape =
                fs::read(&shape).map_err(|e| Exit::Usage(format!("{}: {e}", shape.display())))?;
            let shape = coco::wrap::Shape::parse(&shape).map_err(Exit::Usage)?;
            let plain = wrap::parse(&bytes)?;
            let artifact: SignedDocument = serde_json::from_value(read_json(&platform)?)
                .map_err(|e| Exit::Refused(format!("artifact: {e}")))?;
            let persistent = coco::wrap::Persistent {
                volumes: coco::wrap::persistent_volumes(&bytes)?,
                image: volume_image,
                listed: coco::volume::listed_images(&artifact, &alpha_cli::release_key()?, now)
                    .map_err(Exit::Refused)?,
            };
            let runtime =
                wrap::runtime(&artifact, &alpha_cli::release_key()?, now, &runtime_image)?;
            let digests = if no_resolve {
                BTreeMap::new()
            } else {
                let http = wrap::registry_client_builder()
                    .build()
                    .map_err(|e| Exit::Refused(format!("registry client: {e}")))?;
                wrap::resolve_all(&http, &plain).await?
            };
            let genpolicy = coco::policy::Genpolicy::pinned();
            // A refusal is about the compose and exits 1; anything on our side exits 2, so the
            // adapter shows its own message instead of ours.
            let wrapped = coco::wrap::wrap(
                plain,
                &digests,
                app_id,
                &runtime,
                &shape,
                &persistent,
                &genpolicy,
            )
            .await;
            match wrapped {
                Ok(wrapped) => Ok(json!(wrapped)),
                Err(coco::wrap::WrapError::Refused(m)) => Err(Exit::Refused(m)),
                Err(coco::wrap::WrapError::Failed(m)) => Err(Exit::Usage(m)),
            }
        }
        Command::Coco {
            command: CocoCommand::GenpolicySettings { out },
        } => {
            let write = |name: &str, text: &str| {
                let path = out.join(name);
                fs::write(&path, text)
                    .map_err(|e| Exit::Refused(format!("{}: {e}", path.display())))
            };
            fs::create_dir_all(out.join("genpolicy-settings.d"))
                .map_err(|e| Exit::Refused(format!("{}: {e}", out.display())))?;
            for (path, text) in coco::policy::settings_files() {
                write(&path, text)?;
            }
            write("rules.rego", coco::policy::RULES)?;
            Ok(json!({ "dir": out, "genpolicy_sha256": coco::policy::GENPOLICY_SHA256 }))
        }
        Command::Custodians { command } => custodians_command(config, command, now).await,
    }
}

async fn custodians_command(
    config: &Config,
    command: CustodiansCommand,
    now: SystemTime,
) -> Result<Value, Exit> {
    match command {
        CustodiansCommand::Propose {
            custodians: paths,
            out,
            node: flags,
        } => {
            let keys = read_custodian_keys(&paths, "custodians")?;
            let doc = platform_document(config, now).await?;
            let (attested, client, summary) =
                attested_custodian_node(config, &flags, &doc, None, now).await?;
            let proposal = custodians::propose(&client, &attested.identity, keys).await?;
            write_new(&out, &proposal)?;
            Ok(json!({
                "proposal": out,
                "check": custodians::describe(&proposal)?,
                "node": summary,
            }))
        }
        CustodiansCommand::Rotate {
            proposal,
            share,
            key,
            out,
            node: flags,
        } => {
            let proposal: alpha_client::RotationProposal = read_typed(&proposal)?;
            let remembered = node::ShareFile::read(&share)?.platform_document_version;
            let doc = platform_document(config, now).await?;
            let custodian = keyfile::read(&key, &passphrase("passphrase: ")?)?.xwing()?;
            let (attested, client, summary) =
                attested_custodian_node(config, &flags, &doc, Some(remembered), now).await?;
            let reply = custodians::approve(
                &client,
                &attested.identity,
                &proposal,
                &share,
                &custodian,
                &doc,
            )
            .await?;
            let mut result = json!({
                "rotated": reply.rotated,
                "approvals": reply.approvals,
                "check": custodians::describe(&proposal)?,
                "node": summary,
            });
            if let (Some(rotation), Some(fields)) = (&reply.rotation, result.as_object_mut()) {
                write_new(&out, rotation)?;
                fields.insert("rotation".into(), json!(out));
                fields.insert("rotation_id".into(), json!(rotation.id));
            }
            Ok(result)
        }
        CustodiansCommand::Accept {
            rotation,
            key,
            out,
            node: flags,
        } => {
            let doc = platform_document(config, now).await?;
            let custodian = keyfile::read(&key, &passphrase("passphrase: ")?)?.xwing()?;
            let (attested, client, summary) =
                attested_custodian_node(config, &flags, &doc, None, now).await?;
            let rotation = match rotation {
                Some(path) => read_typed(&path)?,
                None => client.last_rotation().await?,
            };
            let mut result = custodians::accept(&rotation, &doc, &custodian, &out)?;
            if let Some(fields) = result.as_object_mut() {
                fields.insert(
                    "rotating_node_attested".into(),
                    json!(custodians::is_rotating_node(&rotation, &attested.identity)),
                );
                fields.insert("node".into(), summary);
            }
            Ok(result)
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(value) => println!("{value:#}"),
        Err(Exit::Refused(message)) => {
            eprintln!("alpha: {message}");
            std::process::exit(1);
        }
        Err(Exit::Usage(message)) => {
            eprintln!("alpha: {message}");
            std::process::exit(2);
        }
        Err(Exit::Partial(value)) => {
            println!("{value:#}");
            std::process::exit(1);
        }
        Err(Exit::Silent) => {}
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn stop_takes_force_or_a_drain_not_both() {
        let stop = |flags: &[&str]| {
            let args = [
                "alpha",
                "instances",
                "--app",
                "0199a1b2-0000-7000-8000-000000000001",
            ];
            Cli::try_parse_from(
                args.iter()
                    .chain(&["stop", "0199a1b2-0000-7000-8000-000000000002"])
                    .chain(flags),
            )
            .is_ok()
        };
        assert!(stop(&[]));
        assert!(stop(&["--force"]));
        assert!(stop(&["--drain-seconds", "60"]));
        assert!(!stop(&["--force", "--drain-seconds", "60"]));
    }

    #[test]
    fn catalog_sign_takes_its_flags() {
        let sign = |flags: &[&str]| {
            let args = ["alpha", "catalog", "sign"];
            Cli::try_parse_from(args.iter().chain(flags).chain(&["app.yaml"])).is_ok()
        };
        let all = [
            "--id",
            "cpu-app",
            "--version",
            "1",
            "--title",
            "CPU App",
            "--key",
            "k",
        ];
        assert!(sign(&all));
        assert!(sign(&[&all[..], &["--out-dir", "d"]].concat()));
        assert!(!sign(&all[2..]));
        assert_eq!(
            Cli::try_parse_from(["alpha", "--version"])
                .err()
                .map(|e| e.kind()),
            Some(clap::error::ErrorKind::DisplayVersion)
        );
    }

    #[test]
    fn compose_wrap_parses() {
        let image = format!("r@sha256:{}", "7d".repeat(32));
        let wrap = |flags: &[&str]| {
            let args = ["alpha", "compose", "wrap"];
            Cli::try_parse_from(args.iter().chain(flags).chain(&["c.yaml"])).is_ok()
        };
        let app = ["--app-id", "0199a1b2-0000-7000-8000-000000000001"];
        let platform = ["--platform", "p.json"];
        let runtime = ["--runtime-image", image.as_str()];
        assert!(wrap(&[&app[..], &platform, &runtime].concat()));
        assert!(wrap(
            &[&app[..], &platform, &runtime, &["--no-resolve"]].concat()
        ));
        assert!(!wrap(&[&app[..], &runtime].concat()));
        assert!(!wrap(&[&app[..], &platform].concat()));
        assert!(!wrap(
            &[&["--app-id", "not-a-uuid"][..], &platform, &runtime].concat()
        ));
    }

    #[test]
    fn coco_wrap_takes_the_adapters_flags() {
        let image = format!("r@sha256:{}", "7d".repeat(32));
        let wrap = |flags: &[&str]| {
            let args = ["alpha", "coco", "wrap"];
            Cli::try_parse_from(args.iter().chain(flags).chain(&["c.yaml"])).is_ok()
        };
        let all = [
            "--app-id",
            "0199a1b2-0000-7000-8000-000000000001",
            "--platform",
            "p.json",
            "--runtime-image",
            image.as_str(),
            "--shape",
            "s.json",
        ];
        assert!(wrap(&all));
        assert!(wrap(&[&all[..], &["--no-resolve"]].concat()));
        assert!(!wrap(&all[..6]));
        assert!(!wrap(&all[2..]));
    }

    #[test]
    fn deploy_takes_a_spec_or_a_wrapped_compose() {
        let deploy = |flags: &[&str]| {
            let args = [
                "alpha",
                "deploy",
                "--key",
                "k",
                "--key-id",
                "0199a1b2-0000-7000-8000-000000000001",
            ];
            Cli::try_parse_from(args.iter().chain(flags)).is_ok()
        };
        let wrapped = ["--compose", "w.json", "--cpu", "1", "--memory-mib", "2048"];
        assert!(deploy(&["app.yaml"]));
        assert!(deploy(&wrapped));
        assert!(deploy(&[&wrapped[..], &["--register-only"]].concat()));
        assert!(deploy(&[&wrapped[..], &["--wait", "60"]].concat()));
        assert!(!deploy(&[&wrapped[..], &["app.yaml"]].concat()));
        assert!(!deploy(&["--compose", "w.json", "--memory-mib", "2048"]));
        assert!(!deploy(&["--cpu", "1", "--memory-mib", "2048", "app.yaml"]));
        assert!(!deploy(&[]));
    }
}
