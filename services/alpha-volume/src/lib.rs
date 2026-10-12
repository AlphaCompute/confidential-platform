//! An encrypted persistent volume inside a Kata confidential pod (PRD-02 deliverable 25, Option
//! A). The host provides a raw block device (a block-mode PVC) and sees only ciphertext: the
//! volume key is the App's key for purpose `volume.<name>`, which the KMS derives only for an
//! attested Instance of the App, and the LUKS2 format and the filesystem are made inside the TD.
//!
//! LUKS2 comes from `cryptsetup` at a fixed path in this image, which the agent policy pins by
//! digest, rather than from a Rust LUKS2 library: formatting and opening means writing the LUKS2
//! header and keyslots and loading dm-crypt and dm-integrity tables, and cryptsetup is the
//! reference implementation every other tool is checked against. What this crate decides is
//! everything around it, and it fails closed:
//!
//! - A device with any LUKS header (primary or one of the LUKS2 secondary copies) is never
//!   formatted. Only a device with none is.
//! - An existing header must be LUKS2, labelled for this volume, finished (not left half-made by
//!   an interrupted format), and its one segment must be `aes-xts-plain64` with
//!   `hmac(sha256)` integrity. Anything else is refused before the key is offered.
//! - A key the header does not accept, a filesystem that does not mount, or any tool's failure
//!   ends the container with the step named. Nothing is retried with other parameters, and an
//!   opened volume is never re-formatted.
//!
//! The key is the volume's passphrase, given to cryptsetup on stdin. It is 256 bits from the KMS,
//! so a slow key-derivation function adds nothing: PBKDF2 at cryptsetup's minimum iterations
//! keeps the TD's memory out of Argon2. dm-integrity (`hmac(sha256)`) makes a block the host
//! altered unreadable instead of silently different; it cannot detect the host replaying an
//! older copy of the whole device.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

pub mod db;

/// The App-key purpose of a volume: the KMS's purpose alphabet has no `:`, so PRD-02's
/// `volume:<name>` is spelled `volume.<name>`.
pub const KEY_PURPOSE_PREFIX: &str = "volume.";
/// Volume names: a key-purpose segment short enough for the purpose, the LUKS2 label and the
/// pod's volume names.
pub const MAX_NAME: usize = 40;
pub const CIPHER: &str = "aes-xts-plain64";
pub const INTEGRITY: &str = "hmac(sha256)";
/// LUKS2 binary headers: the primary at 0, its copies at these offsets.
const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
const LUKS2_SECONDARY_MAGIC: &[u8; 6] = b"SKUL\xba\xbe";
const SECONDARY_OFFSETS: [u64; 9] = [
    0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000,
];
/// In the LUKS2 binary header: version at 6 (big-endian), the label's 48 bytes at 24.
const LABEL_AT: u64 = 24;
const LABEL_LEN: usize = 48;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("usage: alpha-volume open|open-db <name> <device> <mount dir>")]
    Usage,
    #[error("{0}")]
    Invalid(String),
    #[error("key: {0}")]
    Key(String),
    #[error("{0}")]
    Io(String),
    #[error("refused: {0}")]
    Refused(String),
    #[error("{step} failed: {reason}")]
    Tool { step: &'static str, reason: String },
}

/// The binaries this image ships, at fixed paths.
pub struct Tools {
    pub cryptsetup: PathBuf,
    pub mkfs: PathBuf,
    pub mount: PathBuf,
}

impl Tools {
    pub fn pinned() -> Self {
        Self {
            cryptsetup: PathBuf::from("/sbin/cryptsetup"),
            mkfs: PathBuf::from("/sbin/mkfs.ext4"),
            mount: PathBuf::from("/bin/mount"),
        }
    }
}

/// One volume to open: its name, the claim's device and where to mount it.
#[derive(Clone, Debug)]
pub struct Request {
    pub name: String,
    pub device: PathBuf,
    pub mount_dir: PathBuf,
}

impl Request {
    pub fn new(name: &str, device: &str, mount_dir: &str) -> Result<Self, Error> {
        let named = alpha_core::is_key_purpose(name)
            && name.len() <= MAX_NAME
            && name.bytes().all(|b| b != b'.' && b != b'_');
        if !named {
            return Err(Error::Invalid(format!(
                "volume name {name:?}: lowercase letters, digits and -, at most {MAX_NAME}"
            )));
        }
        for path in [device, mount_dir] {
            if !path.starts_with('/') || path.split('/').any(|p| p == "..") {
                return Err(Error::Invalid(format!("{path:?} is not an absolute path")));
            }
        }
        Ok(Self {
            name: name.to_owned(),
            device: PathBuf::from(device),
            mount_dir: PathBuf::from(mount_dir),
        })
    }

    /// The device-mapper name of the opened volume.
    pub fn mapping(&self) -> String {
        format!("alpha-volume-{}", self.name)
    }

    /// The LUKS2 label of a finished volume.
    pub fn label(&self) -> String {
        format!("av:{}", self.name)
    }

    /// The label while it is being formatted: a header that still carries it was never finished.
    pub fn label_new(&self) -> String {
        format!("av:{}:new", self.name)
    }
}

pub fn key_purpose(name: &str) -> String {
    format!("{KEY_PURPOSE_PREFIX}{name}")
}

/// What the start of the device holds.
#[derive(Debug, PartialEq, Eq)]
pub enum Header {
    /// No LUKS header anywhere: a fresh device, which may be formatted.
    None,
    /// A LUKS2 primary header with this label.
    Luks2 { label: String },
    /// A LUKS header this volume cannot be: LUKS1, or LUKS2 copies without a primary.
    Foreign(String),
}

pub fn read_header(device: &Path) -> Result<Header, Error> {
    let io = |e: std::io::Error| Error::Io(format!("{}: {e}", device.display()));
    let mut file = File::open(device).map_err(io)?;
    let mut at = |offset: u64, len: usize| -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; len];
        file.seek(SeekFrom::Start(offset)).map_err(io)?;
        // A device shorter than the offset holds nothing there.
        let mut read = 0;
        while let Some(rest) = buf.get_mut(read..).filter(|r| !r.is_empty()) {
            match file.read(rest).map_err(io)? {
                0 => break,
                n => read = read.saturating_add(n),
            }
        }
        buf.truncate(read);
        Ok(buf)
    };
    let primary = at(0, 8)?;
    if primary.get(..6) == Some(LUKS_MAGIC.as_slice()) {
        if primary.get(6..8) != Some([0u8, 2].as_slice()) {
            return Ok(Header::Foreign("a LUKS1 header".into()));
        }
        let label = at(LABEL_AT, LABEL_LEN)?;
        let end = label.iter().position(|b| *b == 0).unwrap_or(label.len());
        let label = String::from_utf8_lossy(label.get(..end).unwrap_or_default()).into_owned();
        return Ok(Header::Luks2 { label });
    }
    for offset in SECONDARY_OFFSETS {
        if at(offset, 6)? == LUKS2_SECONDARY_MAGIC.as_slice() {
            return Ok(Header::Foreign(format!(
                "a LUKS2 header copy at {offset:#x} without its primary"
            )));
        }
    }
    Ok(Header::None)
}

/// What happened to the volume.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Opened,
    Formatted,
}

pub fn open_or_format(tools: &Tools, req: &Request, key: &[u8; 32]) -> Result<Outcome, Error> {
    let device = req.device.to_string_lossy().into_owned();
    match read_header(&req.device)? {
        Header::Foreign(what) => Err(Error::Refused(format!(
            "{device} carries {what}; it is not this volume and will not be formatted"
        ))),
        Header::Luks2 { label } if label == req.label_new() => Err(Error::Refused(format!(
            "{device}: an earlier format of volume {} did not finish; an operator must wipe the device",
            req.name
        ))),
        Header::Luks2 { label } if label != req.label() => Err(Error::Refused(format!(
            "{device} is labelled {label:?}, not volume {}",
            req.name
        ))),
        Header::Luks2 { .. } => {
            check_metadata(tools, &device)?;
            luks_open(tools, req, &device, key)?;
            mount(tools, req).inspect_err(|_| close(tools, req))?;
            Ok(Outcome::Opened)
        }
        Header::None => {
            run(
                &tools.cryptsetup,
                "luksFormat",
                &[
                    "luksFormat",
                    "--batch-mode",
                    "--type",
                    "luks2",
                    "--cipher",
                    CIPHER,
                    "--key-size",
                    "512",
                    "--integrity",
                    "hmac-sha256",
                    "--pbkdf",
                    "pbkdf2",
                    "--pbkdf-force-iterations",
                    "1000",
                    "--hash",
                    "sha256",
                    "--label",
                    &req.label_new(),
                    "--key-file",
                    "-",
                    &device,
                ],
                Some(key),
            )?;
            luks_open(tools, req, &device, key)?;
            let mapped = format!("/dev/mapper/{}", req.mapping());
            run(
                &tools.mkfs,
                "mkfs.ext4",
                &["-q", "-L", &req.name, &mapped],
                None,
            )
            .inspect_err(|_| close(tools, req))?;
            // Only now is the volume finished: a header still labelled `:new` never is.
            run(
                &tools.cryptsetup,
                "label",
                &["config", "--label", &req.label(), &device],
                None,
            )
            .inspect_err(|_| close(tools, req))?;
            mount(tools, req).inspect_err(|_| close(tools, req))?;
            Ok(Outcome::Formatted)
        }
    }
}

/// The header's metadata must describe the one segment this crate formats.
fn check_metadata(tools: &Tools, device: &str) -> Result<(), Error> {
    let out = run(
        &tools.cryptsetup,
        "luksDump",
        &["luksDump", "--dump-json-metadata", device],
        None,
    )?;
    let metadata: serde_json::Value = serde_json::from_slice(&out)
        .map_err(|e| Error::Refused(format!("{device}: header metadata: {e}")))?;
    let segments = metadata
        .get("segments")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| Error::Refused(format!("{device}: header names no segments")))?;
    let all: Vec<_> = segments.values().collect();
    let [segment] = all.as_slice() else {
        return Err(Error::Refused(format!(
            "{device}: header has {} segments, not one",
            segments.len()
        )));
    };
    let field = |pointer: &str| segment.pointer(pointer).and_then(serde_json::Value::as_str);
    let int_field = |pointer: &str| segment.pointer(pointer).and_then(serde_json::Value::as_u64);
    if field("/encryption") != Some(CIPHER)
        || field("/integrity/type") != Some(INTEGRITY)
        || int_field("/key_size") != Some(512)
    {
        return Err(Error::Refused(format!(
            "{device}: header is not {CIPHER} with a 512-bit key and {INTEGRITY} integrity"
        )));
    }
    Ok(())
}

fn luks_open(tools: &Tools, req: &Request, device: &str, key: &[u8; 32]) -> Result<(), Error> {
    run(
        &tools.cryptsetup,
        "open",
        &[
            "open",
            "--type",
            "luks2",
            "--key-file",
            "-",
            device,
            &req.mapping(),
        ],
        Some(key),
    )
    .map(drop)
}

fn mount(tools: &Tools, req: &Request) -> Result<(), Error> {
    let mapped = format!("/dev/mapper/{}", req.mapping());
    let dir = req.mount_dir.to_string_lossy().into_owned();
    run(
        &tools.mount,
        "mount",
        &["-t", "ext4", "-o", "nosuid,nodev", &mapped, &dir],
        None,
    )
    .map(drop)
}

/// Best effort after a failure: the mapping is closed so nothing else in the TD uses it.
fn close(tools: &Tools, req: &Request) {
    let _ = run(&tools.cryptsetup, "close", &["close", &req.mapping()], None);
}

/// Runs one tool with an empty environment, `key` (if any) on stdin, and returns its stdout.
fn run(
    program: &Path,
    step: &'static str,
    args: &[&str],
    key: Option<&[u8; 32]>,
) -> Result<Vec<u8>, Error> {
    let failed = |reason: String| Error::Tool { step, reason };
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .stdin(if key.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| failed(format!("{}: {e}", program.display())))?;
    if let (Some(key), Some(mut stdin)) = (key, child.stdin.take()) {
        let key = Zeroizing::new(*key);
        stdin
            .write_all(key.as_slice())
            .map_err(|e| failed(format!("key to stdin: {e}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| failed(e.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(failed(format!(
            "{}: {}",
            output.status,
            stderr.lines().last().unwrap_or_default()
        )));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const KEY: [u8; 32] = [7; 32];

    /// A scratch directory with fake tools that log their arguments and the bytes they got on
    /// stdin; `cryptsetup luksDump` prints `luksdump.json`, and a tool named in `fail` exits 1.
    struct Bench {
        dir: PathBuf,
    }

    impl Bench {
        fn new(fail: &[&str]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "alpha-volume-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            for tool in ["cryptsetup", "mkfs", "mount"] {
                let fails = fail
                    .iter()
                    .any(|f| *f == tool || f.starts_with(&format!("{tool} ")));
                let fail_on = fail
                    .iter()
                    .find_map(|f| f.strip_prefix(&format!("{tool} ")))
                    .unwrap_or("");
                let script = format!(
                    "#!/bin/sh\nlog={dir}/log\nn=$(cat | wc -c)\necho \"{tool} $* <$n\" >> $log\n\
                     if [ \"$1\" = luksDump ]; then cat {dir}/luksdump.json; fi\n\
                     if {fails} && {{ [ -z \"{fail_on}\" ] || [ \"$1\" = \"{fail_on}\" ]; }}; then exit 1; fi\n",
                    dir = dir.display(),
                );
                let path = dir.join(tool);
                std::fs::write(&path, script).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            std::fs::write(
                dir.join("luksdump.json"),
                r#"{"segments":{"0":{"type":"crypt","encryption":"aes-xts-plain64","key_size":512,"integrity":{"type":"hmac(sha256)"}}}}"#,
            )
            .unwrap();
            Self { dir }
        }

        fn tools(&self) -> Tools {
            Tools {
                cryptsetup: self.dir.join("cryptsetup"),
                mkfs: self.dir.join("mkfs"),
                mount: self.dir.join("mount"),
            }
        }

        /// A device of 8 MiB, zero but for `header` at 0.
        fn device(&self, header: &[u8]) -> Request {
            let path = self.dir.join("device");
            let mut bytes = vec![0u8; 8 << 20];
            bytes[..header.len()].copy_from_slice(header);
            std::fs::write(&path, bytes).unwrap();
            Request::new("pgdata", path.to_str().unwrap(), "/run/alpha-volume").unwrap()
        }

        fn log(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.join("log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn luks2(label: &str) -> Vec<u8> {
        let mut h = vec![0u8; 72];
        h[..6].copy_from_slice(LUKS_MAGIC);
        h[6..8].copy_from_slice(&[0, 2]);
        h[24..24 + label.len()].copy_from_slice(label.as_bytes());
        h
    }

    #[test]
    fn a_fresh_device_is_formatted_finished_then_mounted() {
        let bench = Bench::new(&[]);
        let req = bench.device(&[]);
        let outcome = open_or_format(&bench.tools(), &req, &KEY).unwrap();
        assert_eq!(outcome, Outcome::Formatted);
        let log = bench.log();
        let steps: Vec<_> = log
            .iter()
            .map(|l| l.split(' ').take(2).collect::<Vec<_>>().join(" "))
            .collect();
        assert_eq!(
            steps,
            [
                "cryptsetup luksFormat",
                "cryptsetup open",
                "mkfs -q",
                "cryptsetup config",
                "mount -t"
            ]
        );
        // The key goes on stdin to the two calls that need it, never on a command line.
        assert!(
            log[0].ends_with("<32") && log[1].ends_with("<32"),
            "{log:?}"
        );
        assert!(log[0].contains("--label av:pgdata:new --key-file - "));
        assert!(log[0].contains("--integrity hmac-sha256"));
        assert!(log[3].contains("--label av:pgdata "));
        assert!(log[4].contains("/dev/mapper/alpha-volume-pgdata /run/alpha-volume"));
    }

    #[test]
    fn an_existing_volume_is_opened_and_never_formatted() {
        let bench = Bench::new(&[]);
        let req = bench.device(&luks2("av:pgdata"));
        assert_eq!(
            open_or_format(&bench.tools(), &req, &KEY).unwrap(),
            Outcome::Opened
        );
        let log = bench.log().join("\n");
        assert!(log.contains("luksDump") && log.contains("cryptsetup open"));
        assert!(
            !log.contains("luksFormat") && !log.contains("mkfs"),
            "{log}"
        );

        // A key the header refuses, or a filesystem that does not mount: fail, never format.
        for fail in ["cryptsetup open", "mount"] {
            let bench = Bench::new(&[fail]);
            let req = bench.device(&luks2("av:pgdata"));
            let error = open_or_format(&bench.tools(), &req, &KEY).unwrap_err();
            assert!(matches!(error, Error::Tool { .. }), "{fail}: {error}");
            let log = bench.log().join("\n");
            assert!(
                !log.contains("luksFormat") && !log.contains("mkfs"),
                "{log}"
            );
        }
    }

    #[test]
    fn a_header_that_is_not_this_finished_volume_is_refused_before_the_key() {
        for (header, why) in [
            (luks2("av:pgdata:new"), "did not finish"),
            (luks2("av:other"), "not volume pgdata"),
            (
                {
                    let mut h = luks2("av:pgdata");
                    h[7] = 1;
                    h
                },
                "LUKS1",
            ),
        ] {
            let bench = Bench::new(&[]);
            let req = bench.device(&header);
            let error = open_or_format(&bench.tools(), &req, &KEY).unwrap_err();
            assert!(error.to_string().contains(why), "{why}: {error}");
            assert!(bench.log().is_empty(), "{why}: no tool ran");
        }
        // Only a secondary LUKS2 header: someone wiped the primary. Not formatted over.
        let bench = Bench::new(&[]);
        let req = bench.device(&[]);
        let mut bytes = std::fs::read(&req.device).unwrap();
        bytes[0x8000..0x8006].copy_from_slice(LUKS2_SECONDARY_MAGIC);
        std::fs::write(&req.device, bytes).unwrap();
        let error = open_or_format(&bench.tools(), &req, &KEY).unwrap_err();
        assert!(error.to_string().contains("without its primary"), "{error}");
        assert!(bench.log().is_empty());
        // A header whose segment is not what this crate formats.
        let bench = Bench::new(&[]);
        std::fs::write(
            bench.dir.join("luksdump.json"),
            r#"{"segments":{"0":{"type":"crypt","encryption":"cipher_null-ecb"}}}"#,
        )
        .unwrap();
        let req = bench.device(&luks2("av:pgdata"));
        let error = open_or_format(&bench.tools(), &req, &KEY).unwrap_err();
        assert!(
            error.to_string().contains("is not aes-xts-plain64"),
            "{error}"
        );
        assert!(!bench.log().join("\n").contains("cryptsetup open"));
    }

    #[test]
    fn a_failed_format_step_leaves_an_unfinished_label_and_mounts_nothing() {
        for fail in ["mkfs", "cryptsetup config"] {
            let bench = Bench::new(&[fail]);
            let req = bench.device(&[]);
            assert!(open_or_format(&bench.tools(), &req, &KEY).is_err());
            let log = bench.log().join("\n");
            assert!(
                log.contains("cryptsetup close alpha-volume-pgdata"),
                "{fail}: {log}"
            );
            assert!(!log.contains("mount -t"), "{fail}: {log}");
        }
    }

    #[test]
    fn requests_and_purposes() {
        assert_eq!(key_purpose("pgdata"), "volume.pgdata");
        assert!(alpha_core::is_key_purpose(&key_purpose(
            &"a".repeat(MAX_NAME)
        )));
        for (name, device, dir) in [
            ("PG", "/dev/x", "/m"),
            ("a.b", "/dev/x", "/m"),
            (&"a".repeat(MAX_NAME + 1)[..], "/dev/x", "/m"),
            ("pg", "dev/x", "/m"),
            ("pg", "/dev/x", "/m/../etc"),
        ] {
            assert!(
                Request::new(name, device, dir).is_err(),
                "{name} {device} {dir}"
            );
        }
        let r = Request::new(&"a".repeat(MAX_NAME), "/dev/x", "/m").unwrap();
        assert!(r.label_new().len() < LABEL_LEN);
    }
}
