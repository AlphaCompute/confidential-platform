//! `alpha-volume open <name> <device> <mount dir>`, the init container that gives a Kata
//! confidential pod an encrypted persistent volume (PRD-02 deliverable 25, Option A): wait for
//! `alpha-runtime` to attest, read the App's key for purpose `volume.<name>` from its socket,
//! then open the LUKS2 volume on the claim's block device, or format a device that carries no
//! LUKS header at all, and mount it where the App's container finds it. Every failure is a
//! non-zero exit naming the step, and nothing is ever formatted over an existing header.

use alpha_client::runtime::RuntimeSocket;
use alpha_volume::{Error, Request, Tools, key_purpose, open_or_format};

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(summary) => {
            eprintln!("alpha-volume: {summary}");
            0
        }
        Err(e) => {
            eprintln!("alpha-volume: {e}");
            1
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<String, Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [mode, name, device, mount_dir] = args.as_slice() else {
        return Err(Error::Usage);
    };
    if mode != "open" {
        return Err(Error::Usage);
    }
    let request = Request::new(name, device, mount_dir)?;
    let runtime = RuntimeSocket::default();
    runtime.wait_attested().await;
    let key = runtime
        .key(&key_purpose(&request.name))
        .await
        .map_err(|e| Error::Key(e.to_string()))?;
    tokio::task::spawn_blocking(move || open_or_format(&Tools::pinned(), &request, &key))
        .await
        .map_err(|e| Error::Io(format!("worker: {e}")))?
        .map(|outcome| format!("{outcome:?}: {}", args.get(1).map_or("", String::as_str)))
}
