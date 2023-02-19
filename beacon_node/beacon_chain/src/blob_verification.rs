use derivative::Derivative;
use kzg::Kzg;
use slot_clock::SlotClock;
use ssz_types::VariableList;
use std::{sync::Arc, task::Poll};
use store::blob_sidecar::SignedBlobSidecar;
use tokio::{
    sync::oneshot,
    task::JoinHandle,
    time::{timeout, Duration, Timeout},
};

use crate::beacon_chain::{BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use crate::block_verification::PayloadVerificationOutcome;
use crate::{kzg_utils, BeaconChainError, BlockError};
use state_processing::{
    per_block_processing::eip4844::eip4844::verify_kzg_commitments_against_transactions,
    ConsensusContext,
};
use types::signed_beacon_block::BlobReconstructionError;
use types::{
    BeaconBlockRef, BeaconStateError, EthSpec, Hash256, KzgCommitment, SignedBeaconBlock,
    SignedBeaconBlockHeader, SignedSignedBlobSidecar, Slot, Transactions,
};
use types::{Epoch, ExecPayload};

#[derive(Debug)]
pub enum BlobError {
    /// The blob sidecar is from a slot that is later than the current slot (with respect to the
    /// gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },

    /// The blob sidecar has a different slot than the block.
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    SlotMismatch {
        blob_slot: Slot,
        block_slot: Slot,
    },

    /// No kzg ccommitment associated with blob sidecar.
    KzgCommitmentMissing,

    /// No transactions in block
    TransactionsMissing,

    /// Blob transactions in the block do not correspond to the kzg commitments.
    TransactionCommitmentMismatch,

    TrustedSetupNotInitialized,

    InvalidKzgProof,

    KzgError(kzg::Error),

    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    BeaconChainError(BeaconChainError),
    /// No blobs for the specified block where we would expect blobs.
    UnavailableBlobs,
    /// Blobs are missing to verify availability.
    PendingAvailability,
    /// Blobs provided for a pre-Eip4844 fork.
    InconsistentFork,
    /// A cached pending-availability block failed to receive blobs.
    ReceiveBlobsFailed(String),
}

impl From<time::error::Elapsed> for BlobError {
    fn from(e: time::error::Elapsed) -> Self {
        BlobError::ReceiveBlobsFailed(e.into_string())
    }
}

impl From<oneshot::error::RecvError> for BlobError {
    fn from(e: oneshot::error::RecvError) -> Self {
        BlobError::ReceiveBlobsFailed(e.into_string())
    }
}

impl From<BlobReconstructionError> for BlobError {
    fn from(e: BlobReconstructionError) -> Self {
        match e {
            BlobReconstructionError::UnavailableBlobs => BlobError::UnavailableBlobs,
            BlobReconstructionError::InconsistentFork => BlobError::InconsistentFork,
        }
    }
}

impl From<BeaconChainError> for BlobError {
    fn from(e: BeaconChainError) -> Self {
        BlobError::BeaconChainError(e)
    }
}

impl From<BeaconStateError> for BlobError {
    fn from(e: BeaconStateError) -> Self {
        BlobError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

/// A wrapper around a [`SignedBlobSidecar`] that indicates it has been approved for re-gossiping
/// on the p2p network.
pub struct GossipVerifiedBlob<T: BeaconChainTypes> {
    pub blob: Arc<SignedBlobSidecar<T::EthSpec>>,
}

pub fn validate_blob_for_gossip<T: BeaconChainTypes>(
    blob: BlobWrapper<T::EthSpec>,
    block_root: Hash256,
    chain: &BeaconChain<T>,
) -> Result<GossipVerifiedBlob, BlobError> {
    let blob_slot = blobs_sidecar.beacon_block_slot;
    // Do not gossip or process blobs from future or past slots.
    let latest_permissible_slot = chain
        .slot_clock
        .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if blob_slot > latest_permissible_slot {
        return Err(BlobError::FutureSlot {
            message_slot: latest_permissible_slot,
            latest_permissible_slot: blob_slot,
        });
    }

    if blob_slot != block.slot() {
        return Err(BlobError::SlotMismatch {
            blob_slot,
            block_slot: block.slot(),
        });
    }
    GossipVerifiedBlob(blob)
}

fn verify_data_availability<T: BeaconChainTypes>(
    blob_sidecar: &VariableList<SignedBlobSideCar<T::EthSpec>>,
    kzg_commitments: &[KzgCommitment],
    transactions: &Transactions<T::EthSpec>,
    block_slot: Slot,
    block_root: Hash256,
    kzg: &Kzg,
) -> Result<(), BlobError> {
    if verify_kzg_commitments_against_transactions::<T::EthSpec>(transactions, kzg_commitments)
        .is_err()
    {
        return Err(BlobError::TransactionCommitmentMismatch);
    }

    // Validatate that the kzg proof is valid against the commitments and blobs
    let kzg = kzg.ok_or(BlobError::TrustedSetupNotInitialized)?;

    if !kzg_utils::validate_blobs_sidecar(
        kzg,
        block_slot,
        block_root,
        kzg_commitments,
        blob_sidecar,
    )
    .map_err(BlobError::KzgError)?
    {
        return Err(BlobError::InvalidKzgProof);
    }
    Ok(())
}

/// A wrapper over a [`SignedBeaconBlock`]. This makes no claims about data availability and
/// should not be used in consensus. This struct is useful in networking when we want to send
/// blocks around without consensus checks.
#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
pub struct BlockWrapper<E: EthSpec>(Arc<SignedBeaconBlock<E>>);

impl<E: EthSpec> From<Arc<SignedBeaconBlock<E>>> for BlockWrapper<E> {
    fn from(block: Arc<SignedBeaconBlock<E>>) -> Self {
        BlockWrapper(block)
    }
}

/// A wrapper over a [`SignedBlobSidecar`]. This makes no claims about data availability and
/// should not be used in consensus. This struct is useful in networking when we want to send
/// blocks around without consensus checks.
#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
pub struct BlobWrapper<E: EthSpec>(Arc<SignedSignedBlobSidecar<E>>);

impl<E: EthSpec> From<Arc<SignedSignedBlobSidecar<E>>> for BlobWrapper<E> {
    fn from(blob: Arc<SignedSignedBlobSidecar<E>>) -> Self {
        BlobWrapper(blob)
    }
}

#[derive(Copy, Clone)]
pub enum DataAvailabilityCheckRequired {
    Yes,
    No,
}

pub trait IntoAvailabilityPendingBlock<T: BeaconChainTypes> {
    fn into_availablilty_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> AvailablilityPendingBlock<T::EthSpec>;
}

impl<T: BeaconChainTypes> IntoAvailabilityPendingBlock<T> for BlockWrapper<T::EthSpec> {
    fn into_availablilty_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> AvailablilityPendingBlock<T::EthSpec> {
        let data_availability_boundary = chain.data_availability_boundary();
        let da_check_required =
            data_availability_boundary.map_or(DataAvailabilityCheckRequired::No, |boundary| {
                if self.slot().epoch(T::EthSpec::slots_per_epoch()) >= boundary {
                    DataAvailabilityCheckRequired::Yes
                } else {
                    DataAvailabilityCheckRequired::No
                }
            });
        Ok(AvailabilityPendingBlock {
            block,
            da_check_required,
        })
    }
}

#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
pub struct AvailabilityPendingBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    da_check_required: bool,
}

pub struct AvailabilityPendingBlob<E: EthSpec>(SignedBlobSidecar<E>);

/// Used to await blobs from the network.
type DataAvailabilityHandle<E> = TimeOut<Result<(), oneshot::RecvError>>;

/// A wrapper over a [`SignedBeaconBlock`] and its blobs if it has any. An [`AvailableBlock`] has
/// passed any required data availability checks and should be used in consensus. This newtype
/// wraps [`AvailableBlockInner`] to ensure data availability checks cannot be circumvented on
/// construction.
#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
pub struct AvailableBlock<E: EthSpec>(AvailableBlockInner<E>);

/// A wrapper over a [`SignedBeaconBlock`] or a [`SignedBeaconBlockAndBlobsSidecar`].
#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
enum AvailableBlockInner<E: EthSpec> {
    Block(Arc<SignedBeaconBlock<E>>),
    /// The container for any block which requires a data availability check at time of
    /// construction.
    BlockAndBlobs(
        AvailableBlockAndBlobs<E>,
        VariableList<SignedBlobSidecar<E>, E::MaxBlobsPerBlock>,
    ),
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn blobs(&self) -> Option<Arc<BlobsSidecar<E>>> {
        match &self.0 {
            AvailableBlockInner::Block(_) => None,
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => {
                Some(block_sidecar_pair.1.clone())
            }
        }
    }

    pub fn deconstruct(self) -> (Arc<SignedBeaconBlock<E>>, Option<Arc<BlobsSidecar<E>>>) {
        match self.0 {
            AvailableBlockInner::Block(block) => (block, None),
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => {
                (block_sidecar_pair.0, Some(block_sidecar_pair.1))
            }
        }
    }
}

pub trait TryIntoAvailableBlock<E> {
    /// Verifies blobs against kzg-commitments in block if data availability check is required.
    fn try_into(self, chain: &BeaconChain<E>) -> Result<AvailableBlock<E>, BlobError>;
}

impl<E: EthSpec> TryIntoAvailableBlock<E> for &AvailabilityPendingBlock<E> {
    fn try_into(self, chain: &BeaconChain<E>) -> Result<AvailableBlock<E>, BlobError> {
        let block = self.block;
        if self.da_check_required {
            let blobs = match chain.blobs_pending_availability_cache.get(&block_root) {
                Some(blobs) => {
                    self.verify_blobs(&blobs, chain.kzg)?;
                    blobs
                }
                None => VariableList::empty(),
            };
            Ok(AvailableBlock(AvailableBlockInner::BlockAndBlobs(
                block, blobs,
            )))
        } else {
            Ok(AvailableBlock(AvailableBlockInner::Block(block)))
        }
    }
}

/// The maximum time an [`AvailabilityPendingBlock`] is cached in seconds.
pub const AVAILABILITY_PENDING_BLOCK_CACHE_ITEM_TIMEOUT: u64 = 5;

/// A block that has passed payload verification and is waiting for its blobs.
pub struct ExecutedBlock<E: EthSpec> {
    block: AvailabilityPendingBlock<E>,
    data_availability_handle: DataAvailabilityHandle<E>,
    state: BeaconState<E>,
    confirmed_state_roots: Vec<Hash256>,
    payload_verification_status: PayloadVerificationStatus,
    count_unrealized: CountUnrealized,
    parent_block: SignedBeaconBlock,
    parent_eth1_finalization_data: Eth1FinalizationData,
    consensus_context: ConsensusContext<E>,
}

pub struct ExecutedBlockAvailabilityHandle {
    /// Sender to advance [`DataAvailabilityHandle`] in an [`ExecutedBlock`]'s
    /// [`AvailabilityPendingExecutedBlock`].
    tx: oneshot::Sender,
    /// The number of blobs to wait for before sending blobs on tx.
    expected_blobs: usize,
}

impl<E: EthSpec> AvailabilityPendingBlock<E> {
    pub fn verify_blobs(
        &self,
        blobs: &VariableList<SignedBlobSidecar<E>, E::MaxBlobsPerBlock>,
        kzg: &Kzg,
    ) -> Result<(), BlobError> {
        let kzg_commitments = block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_err(|_| BlobError::KzgCommitmentMissing)?;
        if kzg_commitments.len() != blobs.len() {
            return Err(BlobError::PendingAvailability);
        }
        let transactions = block
            .message()
            .body()
            .execution_payload_eip4844()
            .map(|payload| payload.transactions())
            .map_err(|_| BlobError::TransactionsMissing)?
            .ok_or(BlobError::TransactionsMissing)?;
        verify_data_availability(
            blobs,
            kzg_commitments,
            transactions,
            block.slot(),
            block_root,
            kzg,
        )
    }

    /// Converts an [`AvailabilityPendingBlock`] to a cache item that stalls until receiving blobs
    /// input from the network. Returns a pending-availability block cache item and a handle to
    /// send it blobs.
    pub fn cache_item(
        self,
        state: BeaconState<E>,
        confirmed_state_roots: Vec<Hash256>,
        payload_verification_status: PayloadVerificationStatus,
        count_unrealized: CountUnrealized,
        parent_block: SignedBeaconBlock,
        parent_eth1_finalization_data: Eth1FinalizationData,
        consensus_context: ConsensusContext<E>,
    ) -> (ExecutedBlock<E>, ExecutedBlockAvailabilityHandle) {
        let (tx, rx) = oneshot::channel::<()>();
        let data_availability_handle = Some(tokio::time::timeout(
            Duration::from_secs(AVAILABILITY_PENDING_BLOCK_CACHE_ITEM_TIMEOUT),
            rx,
        ));
        let expected_blobs = block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_err(|_| BlobError::KzgCommitmentMissing)?
            .len();
        (
            ExecutedBlock {
                block: self,
                data_availability_handle,
                state,
                confirmed_state_roots,
                payload_verification_status,
                count_unrealized,
                parent_block,
                parent_eth1_finalization_data,
                consensus_context,
            },
            ExecutedBlockAvailabilityHandle { tx, expected_blobs },
        )
    }
}

pub trait IntoBlockWrapper<E: EthSpec>: AsBlock<E> {
    fn into_block_wrapper(self) -> BlockWrapper<E>;
}

impl<E: EthSpec> IntoBlockWrapper<E> for BlockWrapper<E> {
    fn into_block_wrapper(self) -> BlockWrapper<E> {
        self
    }
}

impl<E: EthSpec> IntoBlockWrapper<E> for AvailabilityPendingBlock<E> {
    fn into_block_wrapper(self) -> BlockWrapper<E> {
        let (block, blobs) = self.deconstruct();
        if let Some(blobs) = blobs {
            BlockWrapper::BlockAndBlobs(block, blobs)
        } else {
            BlockWrapper::Block(block)
        }
    }
}

pub trait AsBlock<E: EthSpec> {
    fn slot(&self) -> Slot;
    fn epoch(&self) -> Epoch;
    fn parent_root(&self) -> Hash256;
    fn state_root(&self) -> Hash256;
    fn signed_block_header(&self) -> SignedBeaconBlockHeader;
    fn message(&self) -> BeaconBlockRef<E>;
    fn as_block(&self) -> &SignedBeaconBlock<E>;
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>>;
}

impl<E: EthSpec> AsBlock<E> for BlockWrapper<E> {
    fn slot(&self) -> Slot {
        match self {
            BlockWrapper::Block(block) => block.slot(),
            BlockWrapper::BlockAndBlobs(block, _) => block.slot(),
        }
    }
    fn epoch(&self) -> Epoch {
        match self {
            BlockWrapper::Block(block) => block.epoch(),
            BlockWrapper::BlockAndBlobs(block, _) => block.epoch(),
        }
    }
    fn parent_root(&self) -> Hash256 {
        match self {
            BlockWrapper::Block(block) => block.parent_root(),
            BlockWrapper::BlockAndBlobs(block, _) => block.parent_root(),
        }
    }
    fn state_root(&self) -> Hash256 {
        match self {
            BlockWrapper::Block(block) => block.state_root(),
            BlockWrapper::BlockAndBlobs(block, _) => block.state_root(),
        }
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        match &self {
            BlockWrapper::Block(block) => block.signed_block_header(),
            BlockWrapper::BlockAndBlobs(block, _) => block.signed_block_header(),
        }
    }
    fn message(&self) -> BeaconBlockRef<E> {
        match &self {
            BlockWrapper::Block(block) => block.message(),
            BlockWrapper::BlockAndBlobs(block, _) => block.message(),
        }
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            BlockWrapper::Block(block) => &block,
            BlockWrapper::BlockAndBlobs(block, _) => &block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            BlockWrapper::Block(block) => block.clone(),
            BlockWrapper::BlockAndBlobs(block, _) => block.clone(),
        }
    }
}

impl<E: EthSpec> AsBlock<E> for &BlockWrapper<E> {
    fn slot(&self) -> Slot {
        match self {
            BlockWrapper::Block(block) => block.slot(),
            BlockWrapper::BlockAndBlobs(block, _) => block.slot(),
        }
    }
    fn epoch(&self) -> Epoch {
        match self {
            BlockWrapper::Block(block) => block.epoch(),
            BlockWrapper::BlockAndBlobs(block, _) => block.epoch(),
        }
    }
    fn parent_root(&self) -> Hash256 {
        match self {
            BlockWrapper::Block(block) => block.parent_root(),
            BlockWrapper::BlockAndBlobs(block, _) => block.parent_root(),
        }
    }
    fn state_root(&self) -> Hash256 {
        match self {
            BlockWrapper::Block(block) => block.state_root(),
            BlockWrapper::BlockAndBlobs(block, _) => block.state_root(),
        }
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        match &self {
            BlockWrapper::Block(block) => block.signed_block_header(),
            BlockWrapper::BlockAndBlobs(block, _) => block.signed_block_header(),
        }
    }
    fn message(&self) -> BeaconBlockRef<E> {
        match &self {
            BlockWrapper::Block(block) => block.message(),
            BlockWrapper::BlockAndBlobs(block, _) => block.message(),
        }
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            BlockWrapper::Block(block) => &block,
            BlockWrapper::BlockAndBlobs(block, _) => &block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            BlockWrapper::Block(block) => block.clone(),
            BlockWrapper::BlockAndBlobs(block, _) => block.clone(),
        }
    }
}

impl<E: EthSpec> AsBlock<E> for AvailabilityPendingBlock<E> {
    fn slot(&self) -> Slot {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.slot(),
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => block_sidecar_pair.0.slot(),
        }
    }
    fn epoch(&self) -> Epoch {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.epoch(),
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => block_sidecar_pair.0.epoch(),
        }
    }
    fn parent_root(&self) -> Hash256 {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.parent_root(),
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => {
                block_sidecar_pair.0.parent_root()
            }
        }
    }
    fn state_root(&self) -> Hash256 {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.state_root(),
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => {
                block_sidecar_pair.0.state_root()
            }
        }
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.signed_block_header(),
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => {
                block_sidecar_pair.0.signed_block_header()
            }
        }
    }
    fn message(&self) -> BeaconBlockRef<E> {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.message(),
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => {
                block_sidecar_pair.0.message()
            }
        }
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self.0 {
            AvailableBlockInner::Block(block) => &block,
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => &block_sidecar_pair.0,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.clone(),
            AvailableBlockInner::BlockAndBlobs(block_sidecar_pair) => block_sidecar_pair.0.clone(),
        }
    }
}
