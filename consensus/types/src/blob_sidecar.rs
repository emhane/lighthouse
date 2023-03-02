use crate::test_utils::TestRandom;
use crate::{BeaconBlockHeader, Blob, EthSpec, Hash256, SignedBeaconBlockHeader, SignedRoot, Slot};
use bls::Signature;
use derivative::Derivative;
use kzg::KzgProof;
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::{fmt::Debug, sync::Arc};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    Default,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
pub struct BlobSidecar<T: EthSpec> {
    pub beacon_block_root: Hash256,
    pub beacon_block_slot: Slot,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub block_parent_root: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub blob_index: u64,
    pub blob: Blob<T>,
    pub kzg_aggregated_proof: KzgProof,
}

impl<T: EthSpec> SignedRoot for BlobSidecar<T> {}

impl<T: EthSpec> BlobSidecar<T> {
    pub fn empty() -> Self {
        Self::default()
    }

    #[allow(clippy::integer_arithmetic)]
    pub fn max_size() -> usize {
        <BlobSidecar<T> as Encode>::ssz_fixed_len()
    }

    // todo(emhane)
    /*/// Returns a full `BeaconBlockHeader` of this blob.
    pub fn blob_sidecar_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.beacon_block_slot,
            proposer_index: self.proposer_index,
            parent_root: self.block_parent_root,
            //state_root: self.state_root(),
            body_root: self.beacon_block_root,
        }
    }*/
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
pub struct SignedBlobSidecar<T: EthSpec> {
    pub message: BlobSidecar<T>,
    pub signature: Signature,
}

impl<T: EthSpec> SignedBlobSidecar<T> {
    #[allow(clippy::integer_arithmetic)]
    pub fn max_size() -> usize {
        <SignedBlobSidecar<T> as Encode>::ssz_fixed_len()
    }
}

pub trait AsSignedBlobSidecar<E: EthSpec>: Debug {
    fn beacon_block_root(&self) -> Hash256;
    fn beacon_block_slot(&self) -> Slot;
    fn proposer_index(&self) -> u64;
    fn block_parent_root(&self) -> Hash256;
    fn blob_index(&self) -> u64;
    fn blob(&self) -> &Blob<E>;
    fn kzg_aggregated_proof(&self) -> KzgProof;
    // fn signed_block_header(&self) -> SignedBeaconBlockHeader;
    fn as_blob(&self) -> &SignedBlobSidecar<E>;
    fn blob_cloned(&self) -> Arc<SignedBlobSidecar<E>>;
}

impl<T: EthSpec> AsSignedBlobSidecar<T> for Arc<SignedBlobSidecar<T>> {
    fn beacon_block_root(&self) -> Hash256 {
        self.message.beacon_block_root
    }
    fn beacon_block_slot(&self) -> Slot {
        self.message.beacon_block_slot
    }
    fn proposer_index(&self) -> u64 {
        self.message.proposer_index
    }
    fn block_parent_root(&self) -> Hash256 {
        self.message.block_parent_root
    }
    fn blob_index(&self) -> u64 {
        self.message.blob_index
    }
    fn blob(&self) -> &Blob<T> {
        &self.message.blob
    }
    fn kzg_aggregated_proof(&self) -> KzgProof {
        self.message.kzg_aggregated_proof
    }
    // todo(emhane)
    /*/// Produce a signed beacon block header corresponding to this blob.
    pub fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        SignedBeaconBlockHeader {
            message: self.message().blob_sidecar_header(),
            signature: self.signature.clone(),
        }
    }*/
    fn as_blob(&self) -> &SignedBlobSidecar<T> {
        &*self
    }
    fn blob_cloned(&self) -> Arc<SignedBlobSidecar<T>> {
        self.clone()
    }
}
