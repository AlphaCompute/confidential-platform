//! Model weights at rest under the model server App's own key, derived by the KMS for purpose
//! `weights` and released only to an attested Instance of that App — after CPU and GPU appraisal
//! on a confidential-GPU node. A sealed directory is useless anywhere else, including to the
//! host that stores it.
//!
//! Format v2. A sealing is bound to one model: every plain file `<p>` of model `<m>` becomes
//! `<p>.sealed`: the 8-byte magic `ALPHAWT2`, a random 32-byte salt, then the file in 4 MiB
//! chunks, each `AES-256-GCM(file key, chunk)` with
//! - file key = `HMAC-SHA256(App key, "alpha-weights/v2/file\0" ‖ <m> ‖ "\0" ‖ salt)`, fresh per
//!   file;
//! - nonce = chunk counter (u64, big-endian) ‖ `00 00 00` ‖ last-chunk flag (`00`/`01`);
//! - AAD = `"alpha-weights/v2\0" ‖ <m> ‖ "\0" ‖ <p>`.
//!
//! A file always ends with exactly one chunk flagged last (empty for an empty file), so a
//! truncated, reordered, renamed or spliced file fails to open, and so does a file of another
//! model sealed under the same App key. `MANIFEST.sealed`, sealed the same way under the path
//! `MANIFEST`, names the model and its source and lists every file's path, length and SHA-256.
//! Opening takes the model id and the SHA-256 the manifest must have — values the model server's
//! measured spec pins — and refuses any other manifest before writing a byte, so a sealing of
//! another model, or an older sealing of this one, never opens. It then writes exactly the files
//! the manifest lists, verifies each length and digest, and refuses a missing one. Each file
//! lands under its final name, mode 0444, only once it verified.

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
const MAGIC: &[u8; 8] = b"ALPHAWT2";
const VERSION: u32 = 2;
const CHUNK: usize = 4 * 1024 * 1024;
const TAG: usize = 16;
const SUFFIX: &str = ".sealed";
const MANIFEST: &str = "MANIFEST";
/// The manifest's digest, written in plain next to the sealed files for the operator who puts it
/// into the model server's measured spec. Never read back: `open` checks the measured value.
pub const MANIFEST_DIGEST_FILE: &str = "MANIFEST.sha256";
/// A model id is a name, not a document.
const MAX_MODEL: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "usage: alpha-weights seal <model id> <source> <plain dir> <sealed dir>, or alpha-weights open <model id> <manifest sha256:hex> <sealed dir> <plain dir>"
    )]
    Usage,
    #[error("key: {0}")]
    Key(String),
    #[error("{0}")]
    Io(String),
    #[error(
        "{0}: does not open under this App's key (tampered, truncated, another model's or not ours)"
    )]
    Open(String),
    #[error("{0}: not a plain relative path")]
    Path(String),
    #[error("{0}: length or digest does not match the manifest")]
    Mismatch(String),
    #[error("{0:?}: not a model id (1 to 256 bytes, no NUL) or not a source (no NUL)")]
    Model(String),
    #[error(
        "the sealed manifest is not the expected one (another sealing of the model, or not ours)"
    )]
    Manifest,
}

fn io(context: &str, e: std::io::Error) -> Error {
    Error::Io(format!("{context}: {e}"))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    /// The model id this sealing is bound to, as the model server serves it.
    model: String,
    /// Where the plain weights came from, such as `<repo>@<commit>`: bound by the manifest's
    /// digest, never acted on.
    source: String,
    files: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    len: u64,
    sha256: String,
}

/// What a sealing produced: how many files, and the digest `open` must be given.
#[derive(Debug, PartialEq, Eq)]
pub struct Sealed {
    pub files: usize,
    /// `sha256:<64 hex>` of the plain manifest.
    pub manifest_sha256: String,
}

fn file_key(key: &[u8; 32], model: &str, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(key)
        .map_err(|_| Error::Key("hmac key".into()))?;
    mac.update(b"alpha-weights/v2/file\0");
    mac.update(model.as_bytes());
    mac.update(b"\0");
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

fn aad(model: &str, path: &str) -> Vec<u8> {
    [
        b"alpha-weights/v2\0".as_slice(),
        model.as_bytes(),
        b"\0",
        path.as_bytes(),
    ]
    .concat()
}

/// A model id or source as a sealing binds it: bounded, and without the NUL that separates the
/// model from the path in the AAD.
fn checked_name(name: &str, max: usize) -> Result<&str, Error> {
    if name.is_empty() || name.len() > max || name.contains('\0') {
        return Err(Error::Model(name.to_owned()));
    }
    Ok(name)
}

/// `sha256:<64 hex>`, the form the measured spec carries the manifest's digest in.
fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
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

/// Seals `reader` to `writer` as model `model`'s file `path`; returns the plain length and
/// SHA-256.
fn seal_stream(
    key: &[u8; 32],
    model: &str,
    path: &str,
    reader: impl Read,
    writer: &mut impl Write,
) -> Result<(u64, String), Error> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|e| Error::Io(format!("rng: {e}")))?;
    let cipher = Aes256Gcm::new((&*file_key(key, model, &salt)?).into());
    let aad = aad(model, path);
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

/// Opens `reader`, sealed as model `model`'s file `path`, into `writer`; returns the plain length
/// and SHA-256.
fn open_stream(
    key: &[u8; 32],
    model: &str,
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
    let cipher = Aes256Gcm::new((&*file_key(key, model, &salt)?).into());
    let aad = aad(model, path);
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

/// Seals every regular file under `plain` into `sealed` as model `model`'s weights from `source`,
/// plus the manifest and, in plain, the manifest's digest; returns the count and that digest.
pub fn seal_dir(
    key: &[u8; 32],
    model: &str,
    source: &str,
    plain: &Path,
    sealed: &Path,
) -> Result<Sealed, Error> {
    let model = checked_name(model, MAX_MODEL)?;
    let source = checked_name(source, MAX_MODEL.saturating_mul(4))?;
    let paths = walk(plain)?;
    if paths
        .iter()
        .any(|p| p == MANIFEST || p == MANIFEST_DIGEST_FILE || p.ends_with(SUFFIX))
    {
        return Err(Error::Path(format!(
            "{MANIFEST}, {MANIFEST_DIGEST_FILE} or a *{SUFFIX} file in the plain directory"
        )));
    }
    let files = parallel(&paths, |path| {
        let source = File::open(plain.join(checked(path)?)).map_err(|e| io(path, e))?;
        let mut sealed_meta = (0u64, String::new());
        write_atomically(&sealed.join(sealed_name(path)), false, |w| {
            sealed_meta = seal_stream(key, model, path, source, w)?;
            Ok(())
        })?;
        Ok(Entry {
            path: path.clone(),
            len: sealed_meta.0,
            sha256: sealed_meta.1,
        })
    })?;
    let manifest = serde_json::to_vec(&Manifest {
        version: VERSION,
        model: model.to_owned(),
        source: source.to_owned(),
        files,
    })
    .map_err(|e| Error::Io(format!("manifest: {e}")))?;
    write_atomically(&sealed.join(sealed_name(MANIFEST)), false, |w| {
        seal_stream(key, model, MANIFEST, manifest.as_slice(), w).map(|_| ())
    })?;
    let manifest_sha256 = sha256_label(&manifest);
    write_atomically(&sealed.join(MANIFEST_DIGEST_FILE), false, |w| {
        writeln!(w, "{manifest_sha256}").map_err(|e| io(MANIFEST_DIGEST_FILE, e))
    })?;
    Ok(Sealed {
        files: paths.len(),
        manifest_sha256,
    })
}

/// Opens model `model`'s sealing in `sealed` into `plain`, but only if its manifest's digest is
/// `manifest_sha256`; every file the manifest lists is verified before it takes its final name.
/// Returns the count.
pub fn open_dir(
    key: &[u8; 32],
    model: &str,
    manifest_sha256: &str,
    sealed: &Path,
    plain: &Path,
) -> Result<usize, Error> {
    let model = checked_name(model, MAX_MODEL)?;
    let source = File::open(sealed.join(sealed_name(MANIFEST))).map_err(|e| io(MANIFEST, e))?;
    let mut raw = Vec::new();
    open_stream(key, model, MANIFEST, source, &mut raw)?;
    // The measured digest first: nothing of another sealing is parsed, let alone written.
    if sha256_label(&raw) != manifest_sha256 {
        return Err(Error::Manifest);
    }
    let manifest: Manifest =
        serde_json::from_slice(&raw).map_err(|_| Error::Open(MANIFEST.to_owned()))?;
    if manifest.version != VERSION || manifest.model != model {
        return Err(Error::Manifest);
    }
    for entry in &manifest.files {
        checked(&entry.path)?;
    }
    parallel(&manifest.files, |entry| {
        let rel = checked(&entry.path)?;
        let source =
            File::open(sealed.join(sealed_name(&entry.path))).map_err(|e| io(&entry.path, e))?;
        write_atomically(&plain.join(rel), true, |w| {
            let (len, sha256) = open_stream(key, model, &entry.path, source, w)?;
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
    const MODEL: &str = "nvidia/guard";

    fn tmp(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let mut salt = [0u8; 8];
        getrandom::fill(&mut salt).unwrap();
        dir.push(format!("alpha-weights-{name}-{}", hex::encode(salt)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sealed_stream(data: &[u8]) -> Vec<u8> {
        let mut sealed = Vec::new();
        seal_stream(&KEY, MODEL, "f", data, &mut sealed).unwrap();
        sealed
    }

    #[test]
    fn streams_roundtrip_at_every_chunk_edge() {
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut plain = Vec::new();
            open_stream(
                &KEY,
                MODEL,
                "f",
                sealed_stream(&data).as_slice(),
                &mut plain,
            )
            .unwrap();
            assert_eq!(plain, data, "len {len}");
        }
    }

    #[test]
    fn a_wrong_key_model_path_truncation_extension_or_flipped_byte_does_not_open() {
        let sealed = sealed_stream(&vec![1u8; CHUNK + 10]);
        let fails = |key: &[u8; 32], model: &str, path: &str, bytes: &[u8]| {
            open_stream(key, model, path, bytes, &mut Vec::new()).is_err()
        };
        assert!(!fails(&KEY, MODEL, "f", &sealed));
        assert!(fails(&[8u8; 32], MODEL, "f", &sealed));
        assert!(fails(&KEY, "nvidia/corpus", "f", &sealed));
        assert!(fails(&KEY, MODEL, "g", &sealed));
        // Dropping the final chunk leaves a full chunk not flagged last.
        assert!(fails(&KEY, MODEL, "f", &sealed[..40 + CHUNK + TAG]));
        let mut longer = sealed.clone();
        longer.extend_from_slice(&[0u8; 17]);
        assert!(fails(&KEY, MODEL, "f", &longer));
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(fails(&KEY, MODEL, "f", &flipped));
    }

    #[test]
    fn reordered_chunks_do_not_open() {
        let data: Vec<u8> = (0..2 * CHUNK + 10).map(|i| (i % 253) as u8).collect();
        let sealed = sealed_stream(&data);
        let full = CHUNK + TAG;
        let (header, body) = sealed.split_at(40);
        let (first, rest) = body.split_at(full);
        let (second, last) = rest.split_at(full);
        let swapped = [header, second, first, last].concat();
        assert_eq!(swapped.len(), sealed.len());
        assert!(open_stream(&KEY, MODEL, "f", swapped.as_slice(), &mut Vec::new()).is_err());
    }

    #[test]
    fn a_directory_roundtrips_under_its_manifest_digest_and_lands_read_only() {
        let (plain, sealed, out) = (tmp("plain"), tmp("sealed"), tmp("out"));
        fs::create_dir_all(plain.join("sub")).unwrap();
        fs::write(plain.join("config.json"), b"{}").unwrap();
        fs::write(plain.join("sub/model.safetensors"), vec![9u8; CHUNK + 3]).unwrap();
        let done = seal_dir(&KEY, MODEL, "nvidia/Guard@abc", &plain, &sealed).unwrap();
        assert_eq!(done.files, 2);
        assert!(done.manifest_sha256.starts_with("sha256:"));
        assert_eq!(
            fs::read_to_string(sealed.join(MANIFEST_DIGEST_FILE)).unwrap(),
            format!("{}\n", done.manifest_sha256)
        );
        assert!(sealed.join("sub/model.safetensors.sealed").exists());
        assert_eq!(
            open_dir(&KEY, MODEL, &done.manifest_sha256, &sealed, &out).unwrap(),
            2
        );
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
        // The same weights sealed again carry the same digest: it names the content, not the
        // salts, so it can be computed from the published checkpoint too.
        let again = seal_dir(
            &KEY,
            MODEL,
            "nvidia/Guard@abc",
            &plain,
            &tmp("sealed-again"),
        );
        assert_eq!(again.unwrap().manifest_sha256, done.manifest_sha256);
    }

    #[test]
    fn another_models_sealing_or_another_sealing_of_this_model_never_opens() {
        let plain = tmp("plain4");
        fs::write(plain.join("weights"), b"corpus weights").unwrap();
        let corpus_sealed = tmp("sealed4");
        let corpus = seal_dir(&KEY, "nvidia/corpus", "c@1", &plain, &corpus_sealed).unwrap();

        // The host swaps the corpus model's volume into the guard server: whatever digest the
        // guard server expects, the manifest does not even open under the guard's model id.
        let out = tmp("out4");
        assert!(matches!(
            open_dir(&KEY, MODEL, &corpus.manifest_sha256, &corpus_sealed, &out),
            Err(Error::Open(_))
        ));

        // An older sealing of the same model, rolled back by the host: refused by the digest
        // before a single file is written.
        let old = tmp("plain5");
        fs::write(old.join("weights"), b"older weights").unwrap();
        let old_sealed = tmp("sealed5");
        seal_dir(&KEY, "nvidia/corpus", "c@0", &old, &old_sealed).unwrap();
        assert!(matches!(
            open_dir(
                &KEY,
                "nvidia/corpus",
                &corpus.manifest_sha256,
                &old_sealed,
                &out
            ),
            Err(Error::Manifest)
        ));
        assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
        assert!(seal_dir(&KEY, "", "c@1", &plain, &tmp("sealed6")).is_err());
        assert!(seal_dir(&KEY, "a\0b", "c@1", &plain, &tmp("sealed7")).is_err());
    }

    #[test]
    fn a_swapped_or_missing_file_refuses_and_leaves_no_final_name() {
        let (plain, sealed) = (tmp("plain2"), tmp("sealed2"));
        fs::write(plain.join("a"), b"aaaa").unwrap();
        fs::write(plain.join("b"), b"bbbb").unwrap();
        let done = seal_dir(&KEY, MODEL, "s", &plain, &sealed).unwrap();
        // b's ciphertext under a's name: the AAD names the path, so it does not open.
        fs::copy(sealed.join("b.sealed"), sealed.join("a.sealed")).unwrap();
        let out = tmp("out2");
        assert!(open_dir(&KEY, MODEL, &done.manifest_sha256, &sealed, &out).is_err());
        assert!(!out.join("a").exists());

        let (plain, sealed) = (tmp("plain3"), tmp("sealed3"));
        fs::write(plain.join("a"), b"aaaa").unwrap();
        let done = seal_dir(&KEY, MODEL, "s", &plain, &sealed).unwrap();
        fs::remove_file(sealed.join("a.sealed")).unwrap();
        assert!(open_dir(&KEY, MODEL, &done.manifest_sha256, &sealed, &tmp("out3")).is_err());
    }

    #[test]
    fn a_manifest_path_that_escapes_is_refused() {
        for bad in ["../x", "/etc/passwd", "a/../../b", "", "a\\b"] {
            assert!(checked(bad).is_err(), "{bad}");
        }
        assert!(checked("sub/model.safetensors").is_ok());

        // A manifest sealed under the right key and model that names an escaping path: refused
        // before any file is opened or written, even with its own digest expected.
        let sealed = tmp("sealed8");
        let manifest = serde_json::to_vec(&Manifest {
            version: VERSION,
            model: MODEL.into(),
            source: "s".into(),
            files: vec![Entry {
                path: "../escaped".into(),
                len: 0,
                sha256: hex::encode(Sha256::digest(b"")),
            }],
        })
        .unwrap();
        let mut bytes = Vec::new();
        seal_stream(&KEY, MODEL, MANIFEST, manifest.as_slice(), &mut bytes).unwrap();
        fs::write(sealed.join(sealed_name(MANIFEST)), bytes).unwrap();
        let out = tmp("out8");
        assert!(matches!(
            open_dir(
                &KEY,
                MODEL,
                &sha256_label(&manifest),
                &sealed,
                &out.join("in")
            ),
            Err(Error::Path(_))
        ));
        assert!(!out.join("escaped").exists());
    }
}
