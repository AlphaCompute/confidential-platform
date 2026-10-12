//! `alpha-inference-bench`: drives an OpenAI-compatible endpoint with the checked-in prompt set
//! and prints the measurements and the SLO report (`alpha_inference::bench`), or prints the
//! Prometheus rules rendered from the SLO definition. Never prints a response's text.

use std::process::ExitCode;

use alpha_client::tls::Pin;
use alpha_core::ComposeHash;
use alpha_inference::{bench, slo};

const USAGE: &str = "usage:
  alpha-inference-bench run --endpoint <https://host[:port]/v1> --model <own|external>=<model>...
                            [--rounds <n>] [--slo <slo.toml>] [--prompts <prompts.json>]
                            [--kms-ca <ca.pem> --revision <sha256:...>[,...]]
  alpha-inference-bench rules [--slo <slo.toml>]

The bearer is read from ALPHA_BENCH_BEARER. --kms-ca and --revision pin the endpoint's TLS to an
Instance leaf of that KMS CA carrying one of those Revisions (alpha-inference itself); without
them the endpoint's certificate is checked against the system roots. Exits 0 when every SLO
objective passed, 1 when one failed or had too little data, 2 on a usage or input error.";

struct Args {
    command: String,
    flags: Vec<(String, String)>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut raw = std::env::args().skip(1);
        let command = raw.next().ok_or("no command")?;
        let mut flags = Vec::new();
        while let Some(flag) = raw.next() {
            let name = flag
                .strip_prefix("--")
                .ok_or_else(|| format!("{flag:?} is not a --flag"))?;
            let value = raw
                .next()
                .ok_or_else(|| format!("--{name} needs a value"))?;
            flags.push((name.to_owned(), value));
        }
        Ok(Self { command, flags })
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.flags
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn one(&self, name: &str) -> Result<Option<&str>, String> {
        match self.all(name).as_slice() {
            [] => Ok(None),
            [value] => Ok(Some(value)),
            _ => Err(format!("--{name} is given more than once")),
        }
    }

    fn check(&self, known: &[&str]) -> Result<(), String> {
        match self
            .flags
            .iter()
            .find(|(n, _)| !known.contains(&n.as_str()))
        {
            Some((name, _)) => Err(format!("unknown flag --{name}")),
            None => Ok(()),
        }
    }
}

fn read(path: Option<&str>, default: &'static str) -> Result<String, String> {
    match path {
        Some(path) => std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}")),
        None => Ok(default.to_owned()),
    }
}

fn client(args: &Args) -> Result<reqwest::Client, String> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    let builder = match (args.one("kms-ca")?, args.one("revision")?) {
        (None, None) => builder,
        (Some(ca), Some(revisions)) => {
            let pem = std::fs::read_to_string(ca).map_err(|e| format!("{ca}: {e}"))?;
            let ca = alpha_client::tls::cert_from_pem(&pem).map_err(|e| e.to_string())?;
            let revisions = revisions
                .split(',')
                .map(|r| {
                    r.trim()
                        .parse::<ComposeHash>()
                        .map_err(|_| format!("{r:?} is not sha256:<64 hex>"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let tls = alpha_client::tls::client_config(
                Some(Pin::CaAndInstanceRevisions(ca, revisions)),
                None,
                alpha_client::system_time_provider(),
            )
            .map_err(|e| e.to_string())?;
            builder.tls_backend_preconfigured(tls)
        }
        _ => return Err("--kms-ca and --revision go together".into()),
    };
    builder.build().map_err(|e| e.to_string())
}

async fn run(args: &Args) -> Result<bool, String> {
    args.check(&[
        "endpoint", "model", "rounds", "slo", "prompts", "kms-ca", "revision",
    ])?;
    let slo = slo::Slo::parse(&read(args.one("slo")?, slo::DEFAULT)?).map_err(|e| e.to_string())?;
    let prompts = bench::parse_prompts(&read(args.one("prompts")?, bench::DEFAULT_PROMPTS)?)
        .map_err(|e| e.to_string())?;
    let endpoint = args
        .one("endpoint")?
        .ok_or("--endpoint is required")?
        .trim_end_matches('/')
        .to_owned();
    let url = reqwest::Url::parse(&endpoint).map_err(|e| format!("--endpoint: {e}"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(
            "--endpoint must be https (http only on loopback): it carries the bearer".into(),
        );
    }
    let targets = args
        .all("model")
        .into_iter()
        .map(bench::parse_target)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if targets.is_empty() {
        return Err("name at least one --model".into());
    }
    let rounds: u32 = match args.one("rounds")? {
        None => 3,
        Some(n) => n
            .parse()
            .ok()
            .filter(|n| *n > 0)
            .ok_or("--rounds must be a positive number")?,
    };
    let bearer =
        std::env::var("ALPHA_BENCH_BEARER").map_err(|_| "ALPHA_BENCH_BEARER is not set")?;
    let client = client(args)?;

    println!(
        "alpha-inference-bench: {} prompts x {rounds} rounds per model, streamed, one at a time",
        prompts.len()
    );
    for t in &targets {
        println!("  {}: {}", t.upstream, t.model);
    }
    let samples = bench::run(&client, &endpoint, &bearer, &targets, &prompts, rounds).await;
    let (printed, passed) = bench::report(&slo, &samples);
    println!("\n{printed}");
    Ok(passed)
}

fn rules(args: &Args) -> Result<(), String> {
    args.check(&["slo"])?;
    let slo = slo::Slo::parse(&read(args.one("slo")?, slo::DEFAULT)?).map_err(|e| e.to_string())?;
    print!("{}", slo::prometheus_rules(&slo));
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let outcome = match Args::parse() {
        Err(e) => Err(e),
        Ok(args) => match args.command.as_str() {
            "run" => run(&args).await.map(|passed| {
                if passed {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }),
            "rules" => rules(&args).map(|()| ExitCode::SUCCESS),
            other => Err(format!("unknown command {other:?}")),
        },
    };
    outcome.unwrap_or_else(|e| {
        eprintln!("alpha-inference-bench: {e}\n\n{USAGE}");
        ExitCode::from(2)
    })
}
