//! `alpha-weights seal <model id> <source> <plain dir> <sealed dir>` and
//! `alpha-weights open <model id> <manifest sha256:hex> <sealed dir> <plain dir>`, run inside an
//! attested Instance of the model server's App: wait for the runtime to attest, read the App's
//! key for purpose `weights` from its socket, and do the work. `seal` prints the manifest's
//! digest, which the model server's measured spec gives `open`. Every failure is a non-zero exit
//! naming the step; nothing is left half-written under a final name.

use alpha_client::runtime::RuntimeSocket;
use alpha_weights::{Error, KEY_PURPOSE, open_dir, seal_dir};

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(summary) => {
            eprintln!("alpha-weights: {summary}");
            0
        }
        Err(e) => {
            eprintln!("alpha-weights: {e}");
            1
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<String, Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [mode, model, bound, from, to] = args.as_slice() else {
        return Err(Error::Usage);
    };
    if mode != "seal" && mode != "open" {
        return Err(Error::Usage);
    }
    let runtime = RuntimeSocket::default();
    runtime.wait_attested().await;
    let key = runtime
        .key(KEY_PURPOSE)
        .await
        .map_err(|e| Error::Key(e.to_string()))?;
    let (model, bound, from, to, sealing) = (
        model.clone(),
        bound.clone(),
        from.clone(),
        to.clone(),
        mode == "seal",
    );
    tokio::task::spawn_blocking(move || {
        if sealing {
            seal_dir(&key, &model, &bound, from.as_ref(), to.as_ref()).map(|s| {
                format!(
                    "seal: {} files of {model}, manifest {}",
                    s.files, s.manifest_sha256
                )
            })
        } else {
            open_dir(&key, &model, &bound, from.as_ref(), to.as_ref())
                .map(|n| format!("open: {n} files of {model}"))
        }
    })
    .await
    .map_err(|e| Error::Io(format!("worker: {e}")))?
}
