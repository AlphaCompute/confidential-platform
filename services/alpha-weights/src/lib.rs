//! Model weights at rest under the model server App's own key, derived by the KMS for purpose
//! `weights` and released only to an attested Instance of that App — after CPU and GPU appraisal
//! on a confidential-GPU node. A sealed directory is useless anywhere else, including to the
//! host that stores it.
//!
//! Format v1. Every plain file `<p>` becomes `<p>.sealed`: the 8-byte magic `ALPHAWT1`, a random
//! 32-byte salt, then the file in 4 MiB chunks, each `AES-256-GCM(file key, chunk)` with
//! - file key = `HMAC-SHA256(App key, "alpha-weights/v1/file\0" ‖ salt)`, fresh per file;
//! - nonce = chunk counter (u64, big-endian) ‖ `00 00 00` ‖ last-chunk flag (`00`/`01`);
//! - AAD = `"alpha-weights/v1\0" ‖ <p>`.
//!
//! A file always ends with exactly one chunk flagged last (empty for an empty file), so a
//! truncated, reordered, renamed or spliced file fails to open. `MANIFEST.sealed`, sealed the
//! same way under the path `MANIFEST`, lists every file's path, length and SHA-256; opening
//! writes exactly the files it lists, verifies each length and digest, and refuses a missing
//! one. Each file lands under its final name, mode 0444, only once it verified.

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

use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const KEY_PURPOSE: &str = "weights";
const MAGIC: &[u8; 8] = b"ALPHAWT1";
const CHUNK: usize = 4 * 1024 * 1024;
const TAG: usize = 16;
const SUFFIX: &str = ".sealed";
const MANIFEST: &str = "MANIFEST";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("usage: alpha-weights seal|open <from dir> <to dir>")]
    Usage,
    #[error("key: {0}")]
    Key(String),
    #[error("{0}")]
    Io(String),
    #[error("{0}: does not open under this App's key (tampered, truncated or not ours)")]
    Open(String),
    #[error("{0}: not a plain relative path")]
    Path(String),
    #[error("{0}: length or digest does not match the manifest")]
    Mismatch(String),
}

fn io(context: &str, e: std::io::Error) -> Error {
    Error::Io(format!("{context}: {e}"))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    files: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    len: u64,
    sha256: String,
}

fn file_key(key: &[u8; 32], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(key)
        .map_err(|_| Error::Key("hmac key".into()))?;
    mac.update(b"alpha-weights/v1/file\0");
    mac.update(salt);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

fn nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    let (head, tail) = n.split_at_mut(8);
    head.copy_from_slice(&counter.to_be_bytes());
    if let Some(flag) = tail.last_mut() {
        *flag = u8::from(last);
    }
    n
}

fn aad(path: &str) -> Vec<u8> {
    [b"alpha-weights/v1\0".as_slice(), path.as_bytes()].concat()
}

/// A manifest path: `/`-separated, relative, every component plain.
fn checked(path: &str) -> Result<PathBuf, Error> {
    let p = Path::new(path);
    if path.is_empty()
        || path.contains('\\')
        || !p.components().all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(Error::Path(path.to_owned()));
    }
    Ok(p.to_path_buf())
}

/// Reads up to `buf.len()` bytes, short only at the end of the stream.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while let Some(rest) = buf.get_mut(filled..) {
        if rest.is_empty() {
            break;
        }
        let n = reader.read(rest)?;
        if n == 0 {
            break;
        }
        filled = filled.saturating_add(n);
    }
    Ok(filled)
}

/// Seals `reader` to `writer` under `path`; returns the plain length and SHA-256.
fn seal_stream(
    key: &[u8; 32],
    path: &str,
    reader: impl Read,
    writer: &mut impl Write,
) -> Result<(u64, String), Error> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|e| Error::Io(format!("rng: {e}")))?;
    let cipher = Aes256Gcm::new((&*file_key(key, &salt)?).into());
    let aad = aad(path);
    writer
        .write_all(MAGIC)
        .and_then(|()| writer.write_all(&salt))
        .map_err(|e| io(path, e))?;
    let mut reader = BufReader::with_capacity(CHUNK, reader);
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let (mut counter, mut len, mut digest) = (0u64, 0u64, Sha256::new());
    loop {
        let n = read_full(&mut reader, &mut buf).map_err(|e| io(path, e))?;
        let chunk = buf.get(..n).unwrap_or_default();
        let last = n < CHUNK || reader.fill_buf().map_err(|e| io(path, e))?.is_empty();
        digest.update(chunk);
        len = len.saturating_add(n as u64);
        let sealed = cipher
            .encrypt(
                &Nonce::from(nonce(counter, last)),
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Io(format!("{path}: encryption failed")))?;
        writer.write_all(&sealed).map_err(|e| io(path, e))?;
        if last {
            break;
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| Error::Io(format!("{path}: too many chunks")))?;
    }
    writer.flush().map_err(|e| io(path, e))?;
    Ok((len, hex::encode(digest.finalize())))
}

/// Opens `reader` sealed under `path` into `writer`; returns the plain length and SHA-256.
fn open_stream(
    key: &[u8; 32],
    path: &str,
    reader: impl Read,
    writer: &mut impl Write,
) -> Result<(u64, String), Error> {
    let mut reader = BufReader::with_capacity(CHUNK.saturating_add(TAG), reader);
    let mut header = [0u8; 40];
    if read_full(&mut reader, &mut header).map_err(|e| io(path, e))? != header.len() {
        return Err(Error::Open(path.to_owned()));
    }
    let (magic, salt) = header.split_at(8);
    if magic != MAGIC {
        return Err(Error::Open(path.to_owned()));
    }
    let salt: [u8; 32] = salt.try_into().map_err(|_| Error::Open(path.to_owned()))?;
    let cipher = Aes256Gcm::new((&*file_key(key, &salt)?).into());
    let aad = aad(path);
    let mut buf = vec![0u8; CHUNK.saturating_add(TAG)];
    let (mut counter, mut len, mut digest) = (0u64, 0u64, Sha256::new());
    loop {
        let n = read_full(&mut reader, &mut buf).map_err(|e| io(path, e))?;
        let last = reader.fill_buf().map_err(|e| io(path, e))?.is_empty();
        if n < TAG || (!last && n != buf.len()) {
            return Err(Error::Open(path.to_owned()));
        }
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::from(nonce(counter, last)),
                    Payload {
                        msg: buf.get(..n).unwrap_or_default(),
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Open(path.to_owned()))?,
        );
        digest.update(plain.as_slice());
        len = len.saturating_add(plain.len() as u64);
        writer.write_all(&plain).map_err(|e| io(path, e))?;
        if last {
            break;
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| Error::Open(path.to_owned()))?;
    }
    writer.flush().map_err(|e| io(path, e))?;
    Ok((len, hex::encode(digest.finalize())))
}

/// Every regular file under `root`, as `/`-separated relative paths, sorted. File symlinks are
/// followed (a Hugging Face snapshot is made of them); directory symlinks are not.
fn walk(root: &Path) -> Result<Vec<String>, Error> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), Error> {
        let entries = fs::read_dir(dir).map_err(|e| io(&dir.display().to_string(), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io(&dir.display().to_string(), e))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| io(&path.display().to_string(), e))?;
            if kind.is_dir() {
                visit(root, &path, out)?;
            } else if fs::metadata(&path).is_ok_and(|m| m.is_file()) {
                let rel = path
                    .strip_prefix(root)
                    .ok()
                    .and_then(Path::to_str)
                    .ok_or_else(|| Error::Path(path.display().to_string()))?;
                out.push(rel.replace(std::path::MAIN_SEPARATOR, "/"));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

/// Runs `work` on every item across the machine's cores; the first error wins.
fn parallel<T: Sync, R: Send>(
    items: &[T],
    work: impl Fn(&T) -> Result<R, Error> + Sync,
) -> Result<Vec<R>, Error> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<R>>> = Mutex::new(items.iter().map(|_| None).collect());
    let failure: Mutex<Option<Error>> = Mutex::new(None);
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(items.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(item) = items.get(i) else { return };
                    if failure.lock().map(|f| f.is_some()).unwrap_or(true) {
                        return;
                    }
                    match work(item) {
                        Ok(r) => {
                            if let Ok(mut all) = results.lock()
                                && let Some(slot) = all.get_mut(i)
                            {
                                *slot = Some(r);
                            }
                        }
                        Err(e) => {
                            if let Ok(mut f) = failure.lock() {
                                f.get_or_insert(e);
                            }
                            return;
                        }
                    }
                }
            });
        }
    });
    if let Some(e) = failure.into_inner().ok().flatten() {
        return Err(e);
    }
    results
        .into_inner()
        .map_err(|_| Error::Io("worker panicked".into()))?
        .into_iter()
        .map(|r| r.ok_or_else(|| Error::Io("worker panicked".into())))
        .collect()
}

/// Writes through a temp name and renames into place only after `fill` succeeded.
fn write_atomically(
    target: &Path,
    readonly: bool,
    fill: impl FnOnce(&mut BufWriter<File>) -> Result<(), Error>,
) -> Result<(), Error> {
    let name = target.display().to_string();
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| io(&name, e))?;
    }
    let partial = target.with_extension(format!(
        "{}partial",
        target
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!("{e}."))
            .unwrap_or_default()
    ));
    let file = File::create(&partial).map_err(|e| io(&name, e))?;
    let mut writer = BufWriter::with_capacity(CHUNK, file);
    let filled = fill(&mut writer).and_then(|()| {
        writer
            .into_inner()
            .map_err(|e| io(&name, e.into_error()))?
            .sync_all()
            .map_err(|e| io(&name, e))
    });
    if let Err(e) = filled {
        let _ = fs::remove_file(&partial);
        return Err(e);
    }
    if readonly {
        let mut perms = fs::metadata(&partial)
            .map_err(|e| io(&name, e))?
            .permissions();
        perms.set_readonly(true);
        fs::set_permissions(&partial, perms).map_err(|e| io(&name, e))?;
    }
    fs::rename(&partial, target).map_err(|e| io(&name, e))
}

fn sealed_name(path: &str) -> String {
    format!("{path}{SUFFIX}")
}

/// Seals every regular file under `plain` into `sealed`, plus the manifest; returns the count.
pub fn seal_dir(key: &[u8; 32], plain: &Path, sealed: &Path) -> Result<usize, Error> {
    let paths = walk(plain)?;
    if paths.iter().any(|p| p == MANIFEST || p.ends_with(SUFFIX)) {
        return Err(Error::Path(format!(
            "{MANIFEST} or a *{SUFFIX} file in the plain directory"
        )));
    }
    let files = parallel(&paths, |path| {
        let source = File::open(plain.join(checked(path)?)).map_err(|e| io(path, e))?;
        let mut sealed_meta = (0u64, String::new());
        write_atomically(&sealed.join(sealed_name(path)), false, |w| {
            sealed_meta = seal_stream(key, path, source, w)?;
            Ok(())
        })?;
        Ok(Entry {
            path: path.clone(),
            len: sealed_meta.0,
            sha256: sealed_meta.1,
        })
    })?;
    let manifest = serde_json::to_vec(&Manifest { version: 1, files })
        .map_err(|e| Error::Io(format!("manifest: {e}")))?;
    write_atomically(&sealed.join(sealed_name(MANIFEST)), false, |w| {
        seal_stream(key, MANIFEST, manifest.as_slice(), w).map(|_| ())
    })?;
    Ok(paths.len())
}

/// Opens every file the manifest in `sealed` lists into `plain`, each verified before it takes
/// its final name; returns the count.
pub fn open_dir(key: &[u8; 32], sealed: &Path, plain: &Path) -> Result<usize, Error> {
    let source = File::open(sealed.join(sealed_name(MANIFEST))).map_err(|e| io(MANIFEST, e))?;
    let mut raw = Vec::new();
    open_stream(key, MANIFEST, source, &mut raw)?;
    let manifest: Manifest =
        serde_json::from_slice(&raw).map_err(|_| Error::Open(MANIFEST.to_owned()))?;
    if manifest.version != 1 {
        return Err(Error::Open(MANIFEST.to_owned()));
    }
    for entry in &manifest.files {
        checked(&entry.path)?;
    }
    parallel(&manifest.files, |entry| {
        let rel = checked(&entry.path)?;
        let source =
            File::open(sealed.join(sealed_name(&entry.path))).map_err(|e| io(&entry.path, e))?;
        write_atomically(&plain.join(rel), true, |w| {
            let (len, sha256) = open_stream(key, &entry.path, source, w)?;
            if len != entry.len || sha256 != entry.sha256 {
                return Err(Error::Mismatch(entry.path.clone()));
            }
            Ok(())
        })
    })?;
    Ok(manifest.files.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    fn tmp(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let mut salt = [0u8; 8];
        getrandom::fill(&mut salt).unwrap();
        dir.push(format!("alpha-weights-{name}-{}", hex::encode(salt)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let mut sealed = Vec::new();
        seal_stream(&KEY, "f", data, &mut sealed).unwrap();
        let mut plain = Vec::new();
        open_stream(&KEY, "f", sealed.as_slice(), &mut plain).unwrap();
        plain
    }

    #[test]
    fn streams_roundtrip_at_every_chunk_edge() {
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(roundtrip(&data), data, "len {len}");
        }
    }

    #[test]
    fn a_wrong_key_path_truncation_or_extension_does_not_open() {
        let data = vec![1u8; CHUNK + 10];
        let mut sealed = Vec::new();
        seal_stream(&KEY, "f", data.as_slice(), &mut sealed).unwrap();
        let fails = |key: &[u8; 32], path: &str, bytes: &[u8]| {
            open_stream(key, path, bytes, &mut Vec::new()).is_err()
        };
        assert!(fails(&[8u8; 32], "f", &sealed));
        assert!(fails(&KEY, "g", &sealed));
        // Dropping the final chunk leaves a full chunk not flagged last.
        assert!(fails(&KEY, "f", &sealed[..40 + CHUNK + TAG]));
        let mut longer = sealed.clone();
        longer.extend_from_slice(&[0u8; 17]);
        assert!(fails(&KEY, "f", &longer));
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(fails(&KEY, "f", &flipped));
    }

    #[test]
    fn a_directory_roundtrips_and_lands_read_only() {
        let (plain, sealed, out) = (tmp("plain"), tmp("sealed"), tmp("out"));
        fs::create_dir_all(plain.join("sub")).unwrap();
        fs::write(plain.join("config.json"), b"{}").unwrap();
        fs::write(plain.join("sub/model.safetensors"), vec![9u8; CHUNK + 3]).unwrap();
        assert_eq!(seal_dir(&KEY, &plain, &sealed).unwrap(), 2);
        assert!(sealed.join("sub/model.safetensors.sealed").exists());
        assert_eq!(open_dir(&KEY, &sealed, &out).unwrap(), 2);
        assert_eq!(fs::read(out.join("config.json")).unwrap(), b"{}");
        assert_eq!(
            fs::read(out.join("sub/model.safetensors")).unwrap(),
            vec![9u8; CHUNK + 3]
        );
        assert!(
            fs::metadata(out.join("config.json"))
                .unwrap()
                .permissions()
                .readonly()
        );
        assert!(!out.join("config.json.partial").exists());
    }

    #[test]
    fn a_swapped_or_missing_file_refuses_and_leaves_no_final_name() {
        let (plain, sealed) = (tmp("plain2"), tmp("sealed2"));
        fs::write(plain.join("a"), b"aaaa").unwrap();
        fs::write(plain.join("b"), b"bbbb").unwrap();
        seal_dir(&KEY, &plain, &sealed).unwrap();
        // b's ciphertext under a's name: the AAD names the path, so it does not open.
        fs::copy(sealed.join("b.sealed"), sealed.join("a.sealed")).unwrap();
        let out = tmp("out2");
        assert!(open_dir(&KEY, &sealed, &out).is_err());
        assert!(!out.join("a").exists());

        let (plain, sealed) = (tmp("plain3"), tmp("sealed3"));
        fs::write(plain.join("a"), b"aaaa").unwrap();
        seal_dir(&KEY, &plain, &sealed).unwrap();
        fs::remove_file(sealed.join("a.sealed")).unwrap();
        assert!(open_dir(&KEY, &sealed, &tmp("out3")).is_err());
    }

    #[test]
    fn a_manifest_path_that_escapes_is_refused() {
        for bad in ["../x", "/etc/passwd", "a/../../b", "", "a\\b"] {
            assert!(checked(bad).is_err(), "{bad}");
        }
        assert!(checked("sub/model.safetensors").is_ok());
    }
}
