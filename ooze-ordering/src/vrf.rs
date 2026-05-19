//! VRF-based verifiable randomness for transaction ordering.
//!
//! Uses the validator's Solana identity keypair as the VRF primitive.
//! The signature over (slot || commit) is the "proof"; SHA-256 of the
//! proof is the "randomness". Any node can verify by checking the
//! signature against the validator's published pubkey — no external
//! key registry required.

use {
    serde::{Deserialize, Serialize},
    serde_big_array::BigArray,
    sha2::{Digest, Sha256},
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_signer::Signer,
    thiserror::Error,
};

#[derive(Error, Debug)]
pub enum VrfError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("randomness does not match proof")]
    RandomnessMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfOutput {
    /// 32 bytes of unbiasable randomness = SHA-256(proof).
    pub randomness: [u8; 32],
    /// The ed25519 signature bytes = the VRF proof.
    #[serde(with = "BigArray")]
    pub proof: [u8; 64],
    /// Validator pubkey, so verifiers don't need it out-of-band.
    pub pubkey: [u8; 32],
    /// Pass counter / slot this VRF was evaluated for.
    pub slot: u64,
    /// SHA-256 commit over the transaction set being ordered.
    pub commit: [u8; 32],
}

impl VrfOutput {
    fn message(slot: u64, commit: &[u8; 32]) -> [u8; 40] {
        let mut msg = [0u8; 40];
        msg[..8].copy_from_slice(&slot.to_le_bytes());
        msg[8..].copy_from_slice(commit);
        msg
    }

    /// Produce a VRF output by signing (slot || commit) with the
    /// validator's identity keypair. Only the validator holding the
    /// secret key can do this.
    pub fn evaluate(keypair: &Keypair, slot: u64, commit: [u8; 32]) -> Self {
        let msg = Self::message(slot, &commit);
        let signature = keypair.sign_message(&msg);
        let proof: [u8; 64] = signature.into();

        let mut hasher = Sha256::new();
        hasher.update(proof);
        let randomness: [u8; 32] = hasher.finalize().into();

        let pubkey_obj: Pubkey = keypair.pubkey();
        let pubkey: [u8; 32] = pubkey_obj.to_bytes();

        Self {
            randomness,
            proof,
            pubkey,
            slot,
            commit,
        }
    }

    /// Verify this VRF output. Any node can call this — no secret needed.
    pub fn verify(&self) -> Result<(), VrfError> {
        let signature = Signature::from(self.proof);
        let msg = Self::message(self.slot, &self.commit);

        if !signature.verify(&self.pubkey, &msg) {
            return Err(VrfError::BadSignature);
        }

        let mut hasher = Sha256::new();
        hasher.update(self.proof);
        let expected: [u8; 32] = hasher.finalize().into();
        if expected != self.randomness {
            return Err(VrfError::RandomnessMismatch);
        }
        Ok(())
    }
}

/// Compute a commit hash from a slice of byte buffers (tx signatures or IDs).
/// Sort-then-hash so the commit is independent of input order.
pub fn commit_hash(tx_signatures: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut sorted: Vec<&[u8]> = tx_signatures.to_vec();
    sorted.sort();
    for sig in sorted {
        hasher.update(sig);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_roundtrip() {
        let keypair = Keypair::new();
        let out = VrfOutput::evaluate(&keypair, 12345, [7u8; 32]);
        assert!(out.verify().is_ok());
    }

    #[test]
    fn vrf_tampered_randomness_fails() {
        let keypair = Keypair::new();
        let mut out = VrfOutput::evaluate(&keypair, 1, [0u8; 32]);
        out.randomness[0] ^= 1;
        assert!(matches!(out.verify(), Err(VrfError::RandomnessMismatch)));
    }

    #[test]
    fn vrf_tampered_proof_fails() {
        let keypair = Keypair::new();
        let mut out = VrfOutput::evaluate(&keypair, 1, [0u8; 32]);
        out.proof[0] ^= 1;
        assert!(out.verify().is_err());
    }

    #[test]
    fn vrf_is_deterministic() {
        let keypair = Keypair::new();
        let a = VrfOutput::evaluate(&keypair, 42, [9u8; 32]);
        let b = VrfOutput::evaluate(&keypair, 42, [9u8; 32]);
        assert_eq!(a.randomness, b.randomness);
    }

    #[test]
    fn commit_hash_order_independent() {
        let s1 = [1u8; 64];
        let s2 = [2u8; 64];
        let a = commit_hash(&[&s1[..], &s2[..]]);
        let b = commit_hash(&[&s2[..], &s1[..]]);
        assert_eq!(a, b);
    }
}
