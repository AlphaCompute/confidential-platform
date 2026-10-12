use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_runtime::{Config, Guest, Runtime};
use alpha_trustee::wire::KbsLeaf;
use alpha_trustee_feed::admin::Admin;
use alpha_trustee_feed::files::{self, AS_TOKEN_PURPOSE, Paths, VAULT_ADDR};
use alpha_trustee_feed::gate::{self, Feed};
use alpha_trustee_feed::kms::{Kms, RuntimeKms};
use alpha_trustee_feed::tls::{self, GateCert};
use alpha_trustee_feed::{Clock, Error, GATE_PORT, SYNC_EVERY};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use zeroize::Zeroizing;

const RETRY: Duration = Duration::from_secs(10);

// ponytail: eprintln and no metrics, like alpha-kms and alpha-runtime.
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("alpha-trustee-feed: {e}");
        std::process::exit(1);
    }
}

fn env(name: &str) -> Result<String, Error> {
    std::env::var(name).map_err(|_| Error::Config(format!("{name} is not set")))
}

/// Attests until the KMS answers; a refusal it gives is final.
async fn attest(runtime: &Runtime) -> Result<(), Error> {
    loop {
        match runtime.attest().await {
            Ok(_) => return Ok(()),
            Err(e) if e.revoked() => return Err(Error::Kms(e.to_string())),
            Err(e) => {
                eprintln!("alpha-trustee-feed: attest: {e}; retrying");
                tokio::time::sleep(RETRY).await;
            }
        }
    }
}

async fn kbs_leaf(runtime: &Runtime) -> Result<KbsLeaf, Error> {
    let attested = runtime
        .attested()
        .ok_or_else(|| Error::Kms("no valid leaf".into()))?;
    attested
        .client()
        .post_json("/v1/trustee/kbs-leaf", &serde_json::json!({}))
        .await
        .map_err(|e| Error::Kms(format!("kbs leaf: {e}")))
}

async fn run() -> Result<(), Error> {
    let config = Config::from_env().map_err(|e| Error::Config(e.to_string()))?;
    let pccs_url = env("ALPHACOMPUTE_PCCS_URL")?;
    let paths = Paths::new(
        std::env::var("ALPHACOMPUTE_TRUSTEE_DIR").unwrap_or_else(|_| "/run/trustee".into()),
    );
    let Guest::Coco(source) = alpha_runtime::parse_guest(
        std::env::var(alpha_runtime::QUOTE_SOURCE_ENV)
            .ok()
            .as_deref(),
    )
    .map_err(|e| Error::Config(e.to_string()))?
    else {
        return Err(Error::Config(
            "a Trustee pod is a Kata pod: set ALPHACOMPUTE_QUOTE_SOURCE".into(),
        ));
    };
    let initdata = alpha_tsm::coco::initdata(Path::new(alpha_tsm::coco::INITDATA_PATH))
        .map_err(|e| Error::Config(format!("init-data: {e}")))?;
    let identity =
        alpha_runtime::coco_identity(source, initdata).map_err(|e| Error::Config(e.to_string()))?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|e| Error::Key(format!("rng: {e}")))?;
    let key = SigningKey::from_bytes((&*seed).into()).map_err(|e| Error::Key(e.to_string()))?;
    let clock: Clock = Arc::new(SystemTime::now);
    let runtime = Runtime::new(
        config,
        &key,
        clock.clone(),
        identity.evidence,
        alpha_client::system_time_provider(),
        identity.revision,
    )
    .map_err(|e| Error::Config(e.to_string()))?;
    runtime.set_initdata(identity.initdata);
    attest(&runtime).await?;

    // The token-signing key every Trustee pod shares, the state, the KBS's TLS leaf.
    let derived = runtime
        .attested()
        .ok_or_else(|| Error::Kms("no valid leaf".into()))?
        .client()
        .derive_key(AS_TOKEN_PURPOSE)
        .await
        .map_err(|e| Error::Kms(format!("derive {AS_TOKEN_PURPOSE}: {e}")))?;
    let derived: Zeroizing<[u8; 32]> = Zeroizing::new(
        BASE64_URL_SAFE_NO_PAD
            .decode(derived.key.as_bytes())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::Kms("derived key is not 32 bytes".into()))?,
    );
    let as_key = files::as_signing_key(&derived)?;
    let kms = RuntimeKms(runtime.clone());
    let state = loop {
        match kms.state().await {
            Ok(state) => break state,
            Err(e) => {
                eprintln!("alpha-trustee-feed: state: {e}; retrying");
                tokio::time::sleep(RETRY).await;
            }
        }
    };
    let leaf = kbs_leaf(&runtime).await?;
    let gate_cert = Arc::new(GateCert::new(&leaf, runtime.tls_private_key())?);

    let admin = Admin::generate(clock.clone())?;
    let mut token = [0u8; 32];
    getrandom::fill(&mut token).map_err(|e| Error::Key(format!("rng: {e}")))?;
    let vault_token = hex::encode(token);
    files::write_all(
        &paths,
        &vault_token,
        &admin.public_pem()?,
        &as_key,
        &pccs_url,
        &state.nras_verifier_url,
    )?;
    let feed = Arc::new(Feed::new(
        kms,
        admin,
        gate::kbs_base(),
        vault_token,
        state.nras_verifier_url,
        clock,
    )?);

    let vault = tokio::net::TcpListener::bind(VAULT_ADDR)
        .await
        .map_err(|e| Error::Config(format!("{VAULT_ADDR}: {e}")))?;
    let vault_app = gate::vault_router(feed.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(vault, vault_app).await {
            eprintln!("alpha-trustee-feed: resource backend: {e}");
        }
    });
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", GATE_PORT))
        .await
        .map_err(|e| Error::Config(format!("port {GATE_PORT}: {e}")))?;
    let server = tls::server_config(gate_cert.clone())?;
    let app = gate::router(feed.clone());
    tokio::spawn(alpha_client::tls::serve(
        listener,
        server,
        app,
        std::future::pending(),
    ));
    eprintln!(
        "alpha-trustee-feed: configuration written; the gate refuses until the KBS holds a state"
    );

    let syncing = feed.clone();
    tokio::spawn(async move {
        loop {
            // The KBS starts after this container is up; until it answers, every sync fails.
            let wait = match syncing.sync().await {
                Ok(()) => SYNC_EVERY,
                Err(e) => {
                    eprintln!("alpha-trustee-feed: sync: {e}");
                    Duration::from_secs(5)
                }
            };
            tokio::time::sleep(wait).await;
        }
    });

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::Config(format!("SIGTERM handler: {e}")))?;
    loop {
        let not_after = runtime.last().map_or_else(SystemTime::now, |a| a.not_after);
        let delay = alpha_runtime::renewal_delay(not_after, SystemTime::now());
        tokio::select! {
            _ = term.recv() => return Ok(()),
            () = tokio::time::sleep(delay) => {}
        }
        // A revoked or delisted Trustee build ends here, and the pod with it.
        attest(&runtime).await?;
        match kbs_leaf(&runtime).await {
            Ok(leaf) => gate_cert.replace(&leaf, runtime.tls_private_key())?,
            Err(e) => eprintln!("alpha-trustee-feed: {e}"),
        }
    }
}
