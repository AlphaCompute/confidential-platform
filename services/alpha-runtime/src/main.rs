use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use alpha_runtime::{
    Config, EXIT_REFUSED, Error, Exit, INIT_DATA_PATH, PROBE_PORT, RevisionText, Runtime,
    SECRETS_DIR, SOCKET_PATH, TLS_PORT, gpu, proxy,
};
use alpha_tsm::Substrate;
use p256::ecdsa::SigningKey;
use tokio::net::UnixListener;

// ponytail: JSON lines on stderr only, like alpha-kms, which a Kata pod's policy keeps from the
// host; the upgrade is a collector App that receives them with runtime_pubkey_sha256 added.
#[tokio::main]
async fn main() {
    // First: Docker runs this as a second process in the live container, and the server path
    // removes and rebinds the live socket.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(healthcheck());
    }
    let code = match run().await {
        Ok(exit) => exit.code(),
        Err(e) => {
            alpha_client::error!("exit", error = e.kind());
            e.exit_code()
        }
    };
    std::process::exit(code);
}

fn healthcheck() -> i32 {
    let var = std::env::var("ALPHACOMPUTE_SECRETS").ok();
    let secrets = match alpha_runtime::parse_secrets(var.as_deref()) {
        Ok(secrets) => secrets,
        Err(e) => {
            alpha_client::error!("healthcheck_failed", error = e.kind());
            return EXIT_REFUSED;
        }
    };
    if alpha_runtime::healthcheck(Path::new(SECRETS_DIR), &secrets) {
        0
    } else {
        EXIT_REFUSED
    }
}

async fn run() -> Result<Exit, Error> {
    let config = Config::from_env()?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| Error::Key(format!("rng: {e}")))?;
    let key = SigningKey::from_bytes(&seed.into()).map_err(|e| Error::Key(e.to_string()))?;
    let substrate = Substrate::detect(Path::new(alpha_tsm::DSTACK_SOCKET));
    let revision = match substrate {
        Substrate::Dstack => Some(RevisionText::Compose(
            alpha_tsm::app_compose().map_err(|e| Error::Evidence(format!("app_compose: {e}")))?,
        )),
        // In a Kata pod the KMS pins above come from the pod spec the host writes; the agent
        // policy in the init-data, which the KMS requires, refuses this container unless every
        // variable has its rendered value.
        Substrate::Kata => {
            alpha_runtime::read_init_data(Path::new(INIT_DATA_PATH))?.map(RevisionText::InitData)
        }
    };
    let nvml = match substrate {
        Substrate::Kata => {
            match alpha_nvml::count_devices(Path::new("/dev")).map_err(Error::Evidence)? {
                0 => None,
                gpus => Some(alpha_nvml::Nvml::open(gpus).map_err(Error::Evidence)?),
            }
        }
        Substrate::Dstack => None,
    };
    let runtime = Runtime::new(
        config,
        &key,
        Arc::new(SystemTime::now),
        Arc::new(move |report_data| gpu::evidence(substrate, nvml.as_ref(), report_data)),
        alpha_client::system_time_provider(),
        revision,
    )?;
    let attested = runtime.attest().await?;
    alpha_client::info!(
        "attested",
        substrate = match substrate {
            Substrate::Dstack => "dstack",
            Substrate::Kata => "kata",
        },
        app_id = attested.identity.app_id,
        revision = &attested.identity.compose_hash,
        not_after = attested.not_after,
    );

    let socket = |e: std::io::Error| Error::Socket(format!("{SOCKET_PATH}: {e}"));
    match std::fs::remove_file(SOCKET_PATH) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(socket(e)),
    }
    let listener = UnixListener::bind(SOCKET_PATH).map_err(socket)?;
    // Connecting needs write permission on the socket and tenant services run as any uid;
    // the volume mount, not the mode, decides who reaches it.
    std::fs::set_permissions(
        SOCKET_PATH,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    )
    .map_err(socket)?;
    let tls = proxy::Endpoint::bind(
        runtime.clone(),
        ([0, 0, 0, 0], TLS_PORT).into(),
        ([0, 0, 0, 0], PROBE_PORT).into(),
    )
    .await?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::Socket(format!("SIGTERM handler: {e}")))?;
    let shutdown = async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    let exit = runtime
        .run(listener, PathBuf::from(SECRETS_DIR), tls, shutdown)
        .await;
    let _ = std::fs::remove_file(SOCKET_PATH);
    Ok(exit)
}
