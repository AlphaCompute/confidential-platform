//! The data key (D12 item 2, Andrei Pfau's review of #102). A custodian rotation used to re-wrap
//! the intermediates without changing them, so two old shares and a copy of `intermediate_keys`
//! taken before the rotation still opened everything written after it. Each rotation now also makes
//! a new random data key and, in the same transaction, re-encrypts under it every row the old keys
//! protected (`store::rekey`): the sealed metadata, the blind indexes and the Secrets' values. New
//! audit rows and channel tickets also use it. The old shares and an old copy then open the data
//! as of that copy, and nothing written since.
//!
//! The key is wrapped under the root KEK like the other intermediates (`intermediate_keys`,
//! purpose `data-key`, aad `data-key`). Its `epoch` counts the rotations. The row also carries the
//! epoch in the clear, so every node can see, under the chain lock, whether its keys are still the
//! database's. A database no rotation has re-keyed is epoch 0: everything comes from
//! tenant-kek-root, as #95 built it.
//!
//! tenant-kek-root itself does not rotate. Every App's derived keys (`keys/derive`) come from it,
//! and customers' volumes are encrypted under them. It is the residual: `docs/custodian-rotation.md`.

use zeroize::Zeroizing;

use crate::error::ApiError;
use crate::keys::{Key32, aead_open, aead_seal};
use crate::random;

pub const PURPOSE: &str = "data-key";

/// One epoch of the data key.
#[derive(Clone)]
pub struct DataKey {
    /// 1 for the first rotation's key, one more for each later one.
    pub epoch: i32,
    pub(crate) key: Key32,
    /// The audit keys of epochs 1 to `epoch - 1`, oldest first. The rows they sealed stay in the
    /// append-only chain, and a node walks the chain from genesis. Epoch 0's comes from
    /// tenant-kek-root.
    pub(crate) earlier_audit: Vec<Key32>,
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataKey")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl DataKey {
    /// A new random key for the epoch after `epoch`, which keeps `earlier_audit`, the audit keys
    /// of the epochs since the first rotation, up to and including `epoch`'s.
    pub fn next(epoch: i32, earlier_audit: Vec<Key32>) -> Result<Self, ApiError> {
        let epoch = epoch
            .checked_add(1)
            .ok_or_else(|| ApiError::internal("the data key's epoch overflows"))?;
        let expected = usize::try_from(epoch.saturating_sub(1)).unwrap_or(usize::MAX);
        if earlier_audit.len() != expected {
            return Err(ApiError::internal(
                "the earlier audit keys do not match the epoch",
            ));
        }
        Ok(Self {
            epoch,
            key: Zeroizing::new(random::<32>()?),
            earlier_audit,
        })
    }

    /// `epoch (4, BE) ‖ key (32) ‖ each earlier audit key (32)`.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            36_usize.saturating_add(self.earlier_audit.len().saturating_mul(32)),
        ));
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(self.key.as_slice());
        for key in &self.earlier_audit {
            out.extend_from_slice(key.as_slice());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ApiError> {
        let bad = || ApiError::internal("the data key is not epoch ‖ key ‖ earlier audit keys");
        let (epoch, rest) = bytes.split_first_chunk::<4>().ok_or_else(bad)?;
        let (key, rest) = rest.split_first_chunk::<32>().ok_or_else(bad)?;
        let epoch = i32::from_be_bytes(*epoch);
        let (earlier, tail) = rest.as_chunks::<32>();
        let expected = usize::try_from(epoch.saturating_sub(1)).map_err(|_| bad())?;
        if epoch < 1 || !tail.is_empty() || earlier.len() != expected {
            return Err(bad());
        }
        Ok(Self {
            epoch,
            key: Zeroizing::new(*key),
            earlier_audit: earlier.iter().map(|k| Zeroizing::new(*k)).collect(),
        })
    }

    pub fn wrap(&self, root: &[u8; 32]) -> Result<Vec<u8>, ApiError> {
        aead_seal(root, PURPOSE.as_bytes(), &self.encode())
    }

    /// `None` when `wrapped` does not open under `root`.
    pub fn unwrap(root: &[u8; 32], wrapped: &[u8]) -> Option<Result<Self, ApiError>> {
        aead_open(root, PURPOSE.as_bytes(), wrapped).map(|plain| Self::decode(&plain))
    }

    /// The same key: what a rotation checks before it replaces the one this node serves.
    pub fn same_as(&self, other: &Self) -> bool {
        self.encode() == other.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_data_key_round_trips_and_its_epoch_counts_its_earlier_audit_keys() {
        let first = DataKey::next(0, Vec::new()).unwrap();
        assert_eq!(first.epoch, 1);
        let second = DataKey::next(1, vec![Zeroizing::new([5; 32])]).unwrap();
        assert_eq!(second.epoch, 2);
        assert!(DataKey::next(1, Vec::new()).is_err());
        for key in [&first, &second] {
            let back = DataKey::decode(&key.encode()).unwrap();
            assert!(back.same_as(key));
            let root = [9u8; 32];
            assert!(
                DataKey::unwrap(&root, &key.wrap(&root).unwrap())
                    .unwrap()
                    .unwrap()
                    .same_as(key)
            );
            assert!(DataKey::unwrap(&[8; 32], &key.wrap(&root).unwrap()).is_none());
        }
        assert!(!first.same_as(&DataKey::next(0, Vec::new()).unwrap()));
        let mut bytes = second.encode().to_vec();
        bytes.truncate(bytes.len() - 1);
        assert!(DataKey::decode(&bytes).is_err());
        bytes.truncate(36);
        assert!(
            DataKey::decode(&bytes).is_err(),
            "epoch 2 without epoch 1's audit key"
        );
        assert!(
            DataKey::decode(&[0, 0, 0, 0].repeat(9)).is_err(),
            "epoch 0 has no data key"
        );
    }
}
