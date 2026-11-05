//! The network openings a Kata Revision declares in `[data] "network.toml"`. A pod has none
//! unless it lists them: each is one (direction, protocol, port, address range) with the reason
//! the tenant gives. The deployer enforces them as the pod's only NetworkPolicy; the approver
//! signs them as part of the init-data. An opening may contain the non-public ranges (the deployer
//! excludes them) but may not lie inside one.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::InitDataError;

const MAX_PER_DIRECTION: usize = 32;
const MAX_JUSTIFICATION: usize = 200;

/// The ranges IANA marks not globally reachable, apart from the documentation ranges, which no network routes.
const NON_PUBLIC: [(IpAddr, u8); 19] = [
    (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
    (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    (IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)), 24),
    (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15),
    (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 4),
    (IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0)), 4),
    (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128),
    (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
    (IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0)), 96),
    (
        IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0)),
        48,
    ),
    (IpAddr::V6(Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0)), 64),
    (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
    (IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)), 8),
];

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
    /// The openings in `toml`, each checked: a nonzero port, a canonical network address with no host
    /// bits set and not inside a non-public range, a justification of 1 to 200 characters with a
    /// letter or digit and no control characters, at most 32 per direction, none twice.
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
        if !reason.chars().any(char::is_alphanumeric)
            || o.justification.chars().count() > MAX_JUSTIFICATION
            || o.justification.chars().any(char::is_control)
        {
            return Err(bad(
                entry,
                format!(
                    "justification is not 1 to {MAX_JUSTIFICATION} characters with a letter or digit and no control characters"
                ),
            ));
        }
        if !seen.insert((o.protocol, o.port, o.cidr.as_str())) {
            return Err(bad(entry, "repeats an earlier protocol, port and cidr"));
        }
    }
    Ok(())
}

fn check_cidr(cidr: &str) -> Result<(), String> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or("cidr is not <address>/<prefix>")?;
    let addr: IpAddr = addr.parse().map_err(|_| "cidr address does not parse")?;
    let prefix: u8 = prefix.parse().map_err(|_| "cidr prefix does not parse")?;
    let (bits, width) = addr_bits(addr);
    let host_bits = width
        .checked_sub(u32::from(prefix))
        .ok_or("cidr prefix is longer than the address")?;
    if format!("{addr}/{prefix}") != cidr {
        return Err("cidr is not written canonically".into());
    }
    if bits & host_mask(host_bits) != 0 {
        return Err("cidr has host bits set".into());
    }
    for (range, range_prefix) in NON_PUBLIC {
        let (range_bits, range_width) = addr_bits(range);
        let range_host = host_mask(range_width.saturating_sub(u32::from(range_prefix)));
        if range_width == width && prefix >= range_prefix && bits & !range_host == range_bits {
            return Err(format!(
                "cidr lies inside the non-public range {range}/{range_prefix}"
            ));
        }
    }
    Ok(())
}

fn addr_bits(addr: IpAddr) -> (u128, u32) {
    match addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    }
}

fn host_mask(host_bits: u32) -> u128 {
    1u128
        .checked_shl(host_bits)
        .map_or(u128::MAX, |b| b.saturating_sub(1))
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
    fn a_justification_with_letters_or_digits_is_accepted() {
        for why in ["Base de données du client", "Postgres"] {
            assert!(Openings::parse(&entry(80, "198.51.100.0/24", why)).is_ok());
        }
    }

    #[test]
    fn each_malformed_opening_is_refused() {
        let ok = "x";
        let long = "x".repeat(MAX_JUSTIFICATION + 1);
        let one = entry(1, "198.51.100.0/24", ok);
        let cases = [
            (EXAMPLE.replace("tcp", "icmp"), "network.toml"),
            (format!("{EXAMPLE}[[egres]]\n"), "network.toml"),
            (entry(0, "198.51.100.0/24", ok), "port is 0"),
            (entry(80, "10.0.0.0", ok), "<address>/<prefix>"),
            (entry(80, "10.0.0/8", ok), "does not parse"),
            (entry(80, "10.0.0.0/33", ok), "longer than the address"),
            (entry(80, "2001:db8::/129", ok), "longer than the address"),
            (entry(80, "010.0.0.0/8", ok), "does not parse"),
            (entry(80, "2001:DB8::/32", ok), "canonically"),
            (entry(80, "10.0.0.0/+8", ok), "canonically"),
            (entry(80, "198.51.100.1/24", ok), "host bits"),
            (entry(80, "2001:db8::1/32", ok), "host bits"),
            (entry(80, "198.51.100.0/24", " "), "justification"),
            (entry(80, "198.51.100.0/24", &long), "justification"),
            (entry(80, "198.51.100.0/24", "a\\tb"), "justification"),
            (entry(80, "198.51.100.0/24", "\\u200B"), "justification"),
            (entry(80, "198.51.100.0/24", "--"), "justification"),
            (format!("{one}{one}"), "repeats"),
            (entry(80, "10.0.0.0/8", ok), "non-public range 10.0.0.0/8"),
            (entry(80, "10.1.0.0/16", ok), "non-public range 10.0.0.0/8"),
            (
                entry(80, "198.18.0.0/15", ok),
                "non-public range 198.18.0.0/15",
            ),
            (
                entry(80, "192.0.0.0/24", ok),
                "non-public range 192.0.0.0/24",
            ),
            (
                entry(80, "64:ff9b:1::/48", ok),
                "non-public range 64:ff9b:1::/48",
            ),
            (entry(80, "100::/64", ok), "non-public range 100::/64"),
            (
                entry(80, "192.168.1.1/32", ok),
                "non-public range 192.168.0.0/16",
            ),
            (entry(80, "::1/128", ok), "non-public range ::1/128"),
            (entry(80, "fd00::/8", ok), "non-public range fc00::/7"),
            (
                entry(80, "::ffff:10.0.0.1/128", ok),
                "non-public range ::ffff:0.0.0.0/96",
            ),
            (
                (0..=MAX_PER_DIRECTION)
                    .map(|i| entry(i as u16 + 1, "198.51.100.0/24", ok))
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
        for cidr in [
            "0.0.0.0/0",
            "::/0",
            "8.0.0.0/7",
            "2001:db8::/32",
            "203.0.113.10/32",
            "2001:db8::1/128",
        ] {
            Openings::parse(&entry(443, cidr, "x")).unwrap();
        }
    }
}
