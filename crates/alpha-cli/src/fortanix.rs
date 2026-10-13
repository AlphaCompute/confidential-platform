//! `alpha fortanix tenancy-check`: reads the account record, the roster and the listings, runs
//! [`alpha_dsm::tenancy::check`] and renders the report. Read-only: it changes nothing in any
//! Fortanix account. See `docs/fortanix-tenancy-check.md`.

use std::fs;
use std::path::{Path, PathBuf};

use alpha_dsm::KeyExchange;
use alpha_dsm::tenancy::{self, Account, Listing, Report, Roster, Service, dsm};

/// Where each service's listing comes from.
pub struct Sources {
    pub dsm_listing: Option<PathBuf>,
    pub ccm_listing: Option<PathBuf>,
    /// A live DSM read with this auditor login file (`{"email", "password"}`).
    pub dsm_login: Option<PathBuf>,
    /// TLS 1.3 hybrid only unless the DSM cannot do it (F6).
    pub classical_allowed: bool,
    /// Where a live read keeps the listing it fetched, so the audit record holds the bytes the
    /// report's sha256 names.
    pub save_listing_dir: Option<PathBuf>,
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn load_account(path: &Path) -> Result<Account, String> {
    Account::parse(&read(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn load_roster(path: &Path) -> Result<Roster, String> {
    Roster::parse(&read(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

pub async fn listings(account: &Account, sources: &Sources) -> Result<Vec<Listing>, String> {
    let mut out = Vec::new();
    if sources.dsm_listing.is_some() && sources.dsm_login.is_some() {
        return Err("give --dsm-listing or --dsm-login-file, not both".into());
    }
    // clap skips `requires` when a conflicting flag is present, so check it here too.
    if sources.dsm_login.is_none()
        && (sources.classical_allowed || sources.save_listing_dir.is_some())
    {
        return Err("--classical-allowed and --save-listing-dir apply only to a live read".into());
    }
    if let Some(path) = &sources.dsm_listing {
        out.push(
            dsm::parse_export(&read(path)?, format!("export:{}", path.display()))
                .map_err(|e| e.to_string())?,
        );
    }
    if let Some(login_path) = &sources.dsm_login {
        let service = account
            .service(Service::Dsm)
            .ok_or("--dsm-login-file, but the account records no DSM")?;
        let login: dsm::AuditorLogin = serde_json::from_slice(&read(login_path)?)
            .map_err(|e| format!("{}: {e}", login_path.display()))?;
        let kx = if sources.classical_allowed {
            KeyExchange::ClassicalAllowed
        } else {
            KeyExchange::Hybrid
        };
        let bytes = dsm::fetch(service, &login, kx)
            .await
            .map_err(|e| e.to_string())?;
        let listing = dsm::parse_export(&bytes, format!("live:{}", service.endpoint))
            .map_err(|e| e.to_string())?;
        if let Some(dir) = &sources.save_listing_dir {
            let path = dir.join(format!("dsm-listing-{}.json", listing.sha256));
            fs::write(&path, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        out.push(listing);
    }
    if let Some(path) = &sources.ccm_listing {
        out.push(
            tenancy::ccm::parse_export(&read(path)?, format!("export:{}", path.display()))
                .map_err(|e| e.to_string())?,
        );
    }
    Ok(out)
}

pub fn run(account: &Account, roster: &Roster, listings: &[Listing], now: String) -> Report {
    tenancy::check(account, roster, listings, now)
}
