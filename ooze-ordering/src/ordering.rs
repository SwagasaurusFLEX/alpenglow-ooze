//! Ooze ordering — replace priority-fee auction with verifiable randomness.
//!
//! Priority fees are still collected (validator revenue preserved)
//! but no longer determine position within a block. Ordering is a
//! VRF-seeded CSPRNG shuffle, so sandwich attacks, atomic bundling,
//! and sniping all lose their reliability. Arbitrage and normal
//! DeFi continue to work.

use {
    crate::vrf::{commit_hash, VrfOutput},
    rand::{seq::SliceRandom, SeedableRng},
    rand_chacha::ChaCha20Rng,
    serde::{Deserialize, Serialize},
    solana_keypair::Keypair,
};

/// A transaction as seen by the ordering module. Deliberately opaque —
/// we only need the signature (for commit) and a stable handle (for
/// returning ordering decisions).
#[derive(Debug, Clone)]
pub struct OrderableTx {
    /// The tx signature (64 bytes) or any stable identifier bytes.
    pub signature: Vec<u8>,
    /// Caller-defined handle — the scheduler passes IDs back in this.
    pub handle: u64,
    /// Priority fee in lamports. Preserved but unused for ordering.
    pub priority_fee: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderingResult {
    pub ordered_handles: Vec<u64>,
    pub vrf: VrfOutput,
    pub slot: u64,
    pub tx_count: usize,
}

pub struct OozeOrderer<'a> {
    keypair: &'a Keypair,
}

impl<'a> OozeOrderer<'a> {
    pub fn new(keypair: &'a Keypair) -> Self {
        Self { keypair }
    }

    /// Order a batch of transactions for the given slot.
    ///
    /// 1. Compute commit over the tx set (order-independent hash)
    /// 2. Evaluate VRF over (slot, commit) — only validator can do this
    /// 3. Seed ChaCha20 CSPRNG with the VRF randomness
    /// 4. Shuffle handles
    /// 5. Return handles + proof
    ///
    /// Verifiable by anyone: recompute commit, verify VRF, re-shuffle,
    /// compare ordering.
    pub fn order(&self, txs: &[OrderableTx], slot: u64) -> OrderingResult {
        if txs.is_empty() {
            let commit = commit_hash(&[]);
            let vrf = VrfOutput::evaluate(self.keypair, slot, commit);
            return OrderingResult {
                ordered_handles: vec![],
                vrf,
                slot,
                tx_count: 0,
            };
        }

        let sig_refs: Vec<&[u8]> = txs.iter().map(|t| t.signature.as_slice()).collect();
        let commit = commit_hash(&sig_refs);
        let vrf = VrfOutput::evaluate(self.keypair, slot, commit);
        let mut rng = ChaCha20Rng::from_seed(vrf.randomness);

        let mut handles: Vec<u64> = txs.iter().map(|t| t.handle).collect();
        handles.shuffle(&mut rng);

        OrderingResult {
            ordered_handles: handles,
            vrf,
            slot,
            tx_count: txs.len(),
        }
    }
}

/// Verify an OrderingResult: did the validator apply Ooze randomness
/// honestly, or did they manipulate?
pub fn verify_ordering(
    txs: &[OrderableTx],
    result: &OrderingResult,
) -> Result<(), VerifyError> {
    let sig_refs: Vec<&[u8]> = txs.iter().map(|t| t.signature.as_slice()).collect();
    let expected_commit = commit_hash(&sig_refs);
    if expected_commit != result.vrf.commit {
        return Err(VerifyError::CommitMismatch);
    }
    result.vrf.verify().map_err(|_| VerifyError::BadVrf)?;
    if result.slot != result.vrf.slot {
        return Err(VerifyError::SlotMismatch);
    }
    let mut rng = ChaCha20Rng::from_seed(result.vrf.randomness);
    let mut expected: Vec<u64> = txs.iter().map(|t| t.handle).collect();
    expected.shuffle(&mut rng);
    if expected != result.ordered_handles {
        return Err(VerifyError::OrderingMismatch);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("commit hash does not match tx set")]
    CommitMismatch,
    #[error("VRF signature invalid")]
    BadVrf,
    #[error("slot in result does not match VRF slot")]
    SlotMismatch,
    #[error("published ordering does not match re-derived ordering (validator cheated)")]
    OrderingMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_tx(handle: u64) -> OrderableTx {
        let mut sig = vec![0u8; 64];
        sig[..8].copy_from_slice(&handle.to_le_bytes());
        OrderableTx {
            signature: sig,
            handle,
            priority_fee: 5000,
        }
    }

    #[test]
    fn ordering_is_deterministic_for_same_keys() {
        let keypair = Keypair::new();
        let orderer = OozeOrderer::new(&keypair);
        let txs: Vec<_> = (0..10).map(mk_tx).collect();
        let r1 = orderer.order(&txs, 100);
        let r2 = orderer.order(&txs, 100);
        assert_eq!(r1.ordered_handles, r2.ordered_handles);
    }

    #[test]
    fn different_slots_produce_different_orderings() {
        let keypair = Keypair::new();
        let orderer = OozeOrderer::new(&keypair);
        let txs: Vec<_> = (0..20).map(mk_tx).collect();
        let r1 = orderer.order(&txs, 100);
        let r2 = orderer.order(&txs, 101);
        assert_ne!(r1.ordered_handles, r2.ordered_handles);
    }

    #[test]
    fn verify_accepts_honest_ordering() {
        let keypair = Keypair::new();
        let orderer = OozeOrderer::new(&keypair);
        let txs: Vec<_> = (0..15).map(mk_tx).collect();
        let result = orderer.order(&txs, 500);
        assert!(verify_ordering(&txs, &result).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_ordering() {
        let keypair = Keypair::new();
        let orderer = OozeOrderer::new(&keypair);
        let txs: Vec<_> = (0..15).map(mk_tx).collect();
        let mut result = orderer.order(&txs, 500);
        result.ordered_handles.swap(0, 5);
        assert!(matches!(
            verify_ordering(&txs, &result),
            Err(VerifyError::OrderingMismatch)
        ));
    }

    #[test]
    fn verify_rejects_injected_tx() {
        let keypair = Keypair::new();
        let orderer = OozeOrderer::new(&keypair);
        let txs: Vec<_> = (0..10).map(mk_tx).collect();
        let result = orderer.order(&txs, 500);
        let mut tampered_txs = txs.clone();
        tampered_txs.push(mk_tx(99));
        assert!(matches!(
            verify_ordering(&tampered_txs, &result),
            Err(VerifyError::CommitMismatch)
        ));
    }

    #[test]
    fn priority_fee_does_not_affect_ordering() {
        let keypair = Keypair::new();
        let orderer = OozeOrderer::new(&keypair);
        let txs_low_fee: Vec<_> = (0..10).map(mk_tx).collect();
        let mut txs_high_fee = txs_low_fee.clone();
        for t in &mut txs_high_fee {
            t.priority_fee = 100_000_000;
        }
        let r1 = orderer.order(&txs_low_fee, 77);
        let r2 = orderer.order(&txs_high_fee, 77);
        assert_eq!(r1.ordered_handles, r2.ordered_handles);
    }
}
