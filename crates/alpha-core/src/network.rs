//! The network openings a Kata Revision declares in `[data] "network.toml"`. A pod has none
//! unless it lists them: each is one (direction, protocol, port, address range) with the reason
//! the tenant gives. The deployer enforces them as the pod's only NetworkPolicy; the approver
//! signs them as part of the init-data.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::InitDataError;

const MAX_PER_DIRECTION: usize = 32;
const MAX_JUSTIFICATION: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// `cidr` is where ingress comes from or egress goes to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    pub protocol: Protocol,
    pub port: u16,
    pub cidr: String,
    pub justification: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Openings {
    #[serde(default)]
    pub ingress: Vec<Opening>,
    #[serde(default)]
    pub egress: Vec<Opening>,
}

impl Openings {
    /// The openings in `toml`, each checked: a nonzero port, a canonical network address
    /// without host bits, a justification of 1 to 200 printable characters, at most 32 per
    /// direction, none twice.
    pub fn parse(toml: &str) -> Result<Self, InitDataError> {
        let openings: Self = toml::from_str(toml).map_err(|e| bad("network.toml", e))?;
        check("ingress", &openings.ingress)?;
        check("egress", &openings.egress)?;
        Ok(openings)
    }
}

fn bad(entry: impl std::fmt::Display, why: impl std::fmt::Display) -> InitDataError {
    InitDataError::Network(format!("{entry}: {why}"))
}

fn check(direction: &str, list: &[Opening]) -> Result<(), InitDataError> {
    if list.len() > MAX_PER_DIRECTION {
        return Err(bad(
            direction,
            format!("more than {MAX_PER_DIRECTION} openings"),
        ));
    }
    let mut seen = HashSet::new();
    for (i, o) in list.iter().enumerate() {
        let entry = format!("{direction}[{i}]");
        if o.port == 0 {
            return Err(bad(entry, "port is 0"));
        }
        check_cidr(&o.cidr).map_err(|why| bad(&entry, why))?;
        let reason = o.justification.trim();
        if reason.is_empty()
            || o.justification.chars().count() > MAX_JUSTIFICATION
            || o.justification.chars().any(char::is_control)
        {
            return Err(bad(
                entry,
                format!(
                    "justification is not 1 to {MAX_JUSTIFICATION} characters without control characters"
                ),
            ));
        }
        if !seen.insert((o.protocol, o.port, o.cidr.as_str())) {
            return Err(bad(entry, "repeats an earlier protocol, port and cidr"));
        }
    }
    Ok(())
}

fn check_cidr(cidr: &str) -> Result<(), &'static str> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or("cidr is not <address>/<prefix>")?;
    let addr: IpAddr = addr.parse().map_err(|_| "cidr address does not parse")?;
    let prefix: u8 = prefix.parse().map_err(|_| "cidr prefix does not parse")?;
    let (bits, width) = match addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32u32),
        IpAddr::V6(a) => (u128::from(a), 128),
    };
    let host_bits = width
        .checked_sub(u32::from(prefix))
        .ok_or("cidr prefix is longer than the address")?;
    if format!("{addr}/{prefix}") != cidr {
        return Err("cidr is not written canonically");
    }
    let host = 1u128
        .checked_shl(host_bits)
        .map_or(u128::MAX, |b| b.saturating_sub(1));
    if bits & host != 0 {
        return Err("cidr has host bits set");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "[[ingress]]\nprotocol = \"tcp\"\nport = 8080\ncidr = \"198.51.100.0/24\"\njustification = \"The partner's webhook posts orders here\"\n\n[[egress]]\nprotocol = \"udp\"\nport = 5432\ncidr = \"2001:db8::/32\"\njustification = \"The App's Postgres at its provider\"\n";

    fn entry(port: u16, cidr: &str, why: &str) -> String {
        format!(
            "[[egress]]\nprotocol = \"tcp\"\nport = {port}\ncidr = \"{cidr}\"\njustification = \"{why}\"\n"
        )
    }

    #[test]
    fn the_example_parses() {
        let openings = Openings::parse(EXAMPLE).unwrap();
        assert_eq!(openings.ingress[0].port, 8080);
        assert_eq!(openings.egress[0].protocol, Protocol::Udp);
        assert_eq!(Openings::parse("").unwrap(), Openings::default());
    }

    #[test]
    fn each_malformed_opening_is_refused() {
        let ok = "x";
        let long = "x".repeat(MAX_JUSTIFICATION + 1);
        let one = entry(1, "10.0.0.0/8", ok);
        let cases = [
            (EXAMPLE.replace("tcp", "icmp"), "network.toml"),
            (format!("{EXAMPLE}[[egres]]\n"), "network.toml"),
            (entry(0, "10.0.0.0/8", ok), "port is 0"),
            (entry(80, "10.0.0.0", ok), "<address>/<prefix>"),
            (entry(80, "10.0.0/8", ok), "does not parse"),
            (entry(80, "10.0.0.0/33", ok), "longer than the address"),
            (entry(80, "2001:db8::/129", ok), "longer than the address"),
            (entry(80, "010.0.0.0/8", ok), "does not parse"),
            (entry(80, "2001:DB8::/32", ok), "canonically"),
            (entry(80, "10.0.0.0/+8", ok), "canonically"),
            (entry(80, "10.0.0.1/8", ok), "host bits"),
            (entry(80, "2001:db8::1/32", ok), "host bits"),
            (entry(80, "10.0.0.0/8", " "), "justification"),
            (entry(80, "10.0.0.0/8", &long), "justification"),
            (entry(80, "10.0.0.0/8", "a\\tb"), "justification"),
            (format!("{one}{one}"), "repeats"),
            (
                (0..=MAX_PER_DIRECTION)
                    .map(|i| entry(i as u16 + 1, "10.0.0.0/8", ok))
                    .collect(),
                "more than 32",
            ),
        ];
        for (toml, fragment) in cases {
            let err = Openings::parse(&toml).unwrap_err().to_string();
            assert!(err.contains(fragment), "{toml}: {err}");
        }
    }

    #[test]
    fn the_whole_internet_and_a_host_are_valid_networks() {
        for cidr in ["0.0.0.0/0", "::/0", "203.0.113.10/32", "2001:db8::1/128"] {
            Openings::parse(&entry(443, cidr, "x")).unwrap();
        }
    }
}
