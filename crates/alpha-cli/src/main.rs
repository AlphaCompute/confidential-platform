use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use alpha_attest::PlatformDocument;
use alpha_cli::call::Route;
use alpha_cli::deploy::Shroud;
use alpha_cli::keyfile::{self, Algorithm};
use alpha_cli::{instances, node, sign};
use alpha_client::platform::SignedDocument;
use alpha_client::{Client, Pin};
use alpha_core::{AppId, KeyId, OrgId, PrincipalId};
use alpha_crypto::PublicKey;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};

/// The alphacompute CLI: keys, Control calls, the platform document, deploys, and the
/// custodians' bootstrap and unseal.
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
    /// Tenant YAML → compose → Revision → shroud-go deploy.
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
        app: PathBuf,
    },
    /// An App's running copies through shroud-go.
    Instances {
        #[arg(long)]
        app: AppId,
        #[command(subcommand)]
        command: InstancesCommand,
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
        instance: String,
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
            app,
        } => {
            let text = fs::read_to_string(&app)
                .map_err(|e| Exit::Usage(format!("{}: {e}", app.display())))?;
            let spec = alpha_cli::deploy::parse(&text)
                .map_err(|e| Exit::Usage(format!("{}: {e}", app.display())))?;
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
            Ok(alpha_cli::deploy::run(&client, &spec, key_id, &key, shroud.as_ref(), wait).await?)
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
                        Some(secs) => Some((secs, platform_document(config, now).await?)),
                        None => None,
                    };
                    let wait = doc
                        .as_ref()
                        .map(|(secs, doc)| (Duration::from_secs(*secs), doc.kms_ca_pem.as_str()));
                    Ok(instances::add(&shroud, app, resources, wait).await?)
                }
                InstancesCommand::Stop {
                    instance,
                    force,
                    drain_seconds,
                } => Ok(instances::stop(&shroud, app, &instance, force, drain_seconds).await?),
            }
        }
        Command::Unseal {
            share,
            key,
            endpoint,
        } => {
            let remembered = node::ShareFile::read(&share)?.platform_document_version;
            let doc = platform_document(config, now).await?;
            let custodian = keyfile::read(&key, &passphrase("passphrase: ")?)?.xwing()?;
            let (identity, client) =
                node::attested_node(&endpoint, &config.pccs_url, &doc, Some(remembered), now)
                    .await?;
            let reply = node::unseal(&client, &identity, &share, &custodian, doc.version).await?;
            Ok(json!(reply))
        }
        Command::Bootstrap {
            custodians,
            endpoint,
        } => {
            let mut keys = Vec::new();
            for path in &custodians {
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
            let custodians: [PublicKey; 3] = keys
                .try_into()
                .map_err(|_| Exit::Usage("--custodians takes exactly three files".into()))?;
            let doc = platform_document(config, now).await?;
            let (identity, client) =
                node::attested_node(&endpoint, &config.pccs_url, &doc, None, now).await?;
            Ok(
                node::bootstrap(&client, &identity, custodians, doc.version, Path::new("."))
                    .await?,
            )
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
            Cli::try_parse_from(args.iter().chain(&["stop", "some-copy"]).chain(flags)).is_ok()
        };
        assert!(stop(&[]));
        assert!(stop(&["--force"]));
        assert!(stop(&["--drain-seconds", "60"]));
        assert!(!stop(&["--force", "--drain-seconds", "60"]));
    }
}
