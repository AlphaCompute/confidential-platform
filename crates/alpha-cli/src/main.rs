use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use alpha_cli::call::{ROUTES, Route};
use alpha_cli::deploy::Shroud;
use alpha_cli::keyfile::{self, Algorithm};
use alpha_cli::{node, sign};
use alpha_client::platform::SignedDocument;
use alpha_client::{Anchor, Client, Pin};
use alpha_core::KeyId;
use alpha_crypto::PublicKey;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use clap::{Args, Parser, Subcommand};
use serde_json::Value;

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
        #[arg(value_parser = ROUTES)]
        route: String,
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
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        key_id: KeyId,
        app: PathBuf,
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
    /// Genesis on an empty database: three custodian public keys and the anchor.
    Bootstrap {
        /// Three files, each holding a custodian's public key as `keygen --custodian` printed it.
        #[arg(long, value_delimiter = ',', num_args = 3)]
        custodians: Vec<PathBuf>,
        /// JSON `{org_id, principal_id, public_key, label}`.
        #[arg(long)]
        anchor: PathBuf,
        #[arg(long)]
        endpoint: String,
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

/// The admin's pin: `kms_ca_pem` of the platform document fetched and verified now.
async fn admin_client(config: &Config, now: SystemTime) -> Result<Client, Exit> {
    let url = need(
        config.platform_document_url.as_deref(),
        "platform-document-url",
    )?;
    let (_, doc) = alpha_client::platform::fetch(url, &alpha_cli::release_key(), now).await?;
    let ca = alpha_client::tls::ca_from_pem(&doc.kms_ca_pem)?;
    if config.endpoints.is_empty() {
        return Err(Exit::Usage(
            "--endpoints (or ALPHACOMPUTE_KMS_ENDPOINTS) is required".into(),
        ));
    }
    Ok(Client::new(config.endpoints.clone(), Pin::Ca(ca))?)
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
            Ok(serde_json::json!({ "file": out, "public_key": key.public_key_text() }))
        }
        Command::Call {
            route,
            context,
            key,
            key_id,
            value,
            payload,
        } => {
            let route: Route = route.parse().map_err(Exit::Usage)?;
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
        Command::Sign {
            release_key,
            check,
            document,
        } => {
            let document = read_json(&document)?;
            if check {
                let artifact: SignedDocument = serde_json::from_value(document)
                    .map_err(|e| Exit::Refused(format!("artifact: {e}")))?;
                let summary = sign::check(&artifact, &alpha_cli::release_key(), now)?;
                return Ok(serde_json::to_value(summary).expect("serializes"));
            }
            let key = read_ed25519(&release_key.expect("required unless --check"))?;
            Ok(serde_json::to_value(sign::sign(document, &key)?).expect("serializes"))
        }
        Command::Deploy {
            register_only,
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
            let client = admin_client(config, now).await?;
            Ok(alpha_cli::deploy::run(&client, &spec, key_id, &key, shroud.as_ref()).await?)
        }
        Command::Unseal {
            share,
            key,
            endpoint,
        } => {
            let remembered = node::ShareFile::read(&share)?.platform_document_version;
            let url = need(
                config.platform_document_url.as_deref(),
                "platform-document-url",
            )?;
            let (_, doc) =
                alpha_client::platform::fetch(url, &alpha_cli::release_key(), now).await?;
            let custodian = keyfile::read(&key, &passphrase("passphrase: ")?)?.xwing()?;
            let (identity, client) =
                node::attested_node(&endpoint, &config.pccs_url, &doc, Some(remembered), now)
                    .await?;
            let reply = node::unseal(&client, &identity, &share, &custodian, doc.version).await?;
            Ok(serde_json::to_value(reply).expect("serializes"))
        }
        Command::Bootstrap {
            custodians,
            anchor,
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
            let custodians: [PublicKey; 3] = keys.try_into().expect("clap took exactly three");
            let anchor: Anchor = serde_json::from_value(read_json(&anchor)?)
                .map_err(|e| Exit::Usage(format!("anchor: {e}")))?;
            let url = need(
                config.platform_document_url.as_deref(),
                "platform-document-url",
            )?;
            let (_, doc) =
                alpha_client::platform::fetch(url, &alpha_cli::release_key(), now).await?;
            let (identity, client) =
                node::attested_node(&endpoint, &config.pccs_url, &doc, None, now).await?;
            Ok(node::bootstrap(
                &client,
                &identity,
                custodians,
                anchor,
                doc.version,
                Path::new("."),
            )
            .await?)
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(value) => println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("serializes")
        ),
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
