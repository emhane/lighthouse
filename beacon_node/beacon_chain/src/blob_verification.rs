use crate::beacon_chain::{BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use crate::block_verification::{GossipVerifiedBlock, SignatureVerifiedBlock};
use crate::{eth1_finalization_cache::Eth1FinalizationData, kzg_utils, BeaconChainError};
use core::future::Future;
use derivative::Derivative;
use fork_choice::{CountUnrealized, PayloadVerificationStatus};
use futures::channel::{
    mpsc,
    mpsc::{RecvError as RecvBlobError, SendError},
};
use kzg::Kzg;
use slot_clock::SlotClock;
use ssz_types::VariableList;
use state_processing::{
    per_block_processing::eip4844::eip4844::verify_kzg_commitments_against_transactions,
    ConsensusContext,
};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use task_executor::JoinHandle;
use tokio::time::{error::Elapsed as TimedOut, Duration};
use types::signed_beacon_block::BlobReconstructionError;
use types::{
    BeaconBlockRef, BeaconStateError, EthSpec, Hash256, KzgCommitment, SignedBeaconBlock,
    SignedBeaconBlockHeader, SignedBlobSidecar, Slot, Transactions,
};
use types::{BeaconState, Blob, Epoch, ExecPayload, KzgProof};

#[derive(Debug)]
pub enum BlobError<E: EthSpec> {
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
    /// Verifying availability of a block failed.
    DataAvailabilityFailed(DataAvailabilityFailed<E>),
}

#[derive(Debug)]
pub enum DataAvailabilityFailed<E: EthSpec> {
    /// Verifying availability of a block failed. Contains the blobs that have been received.
    Block(
        Arc<SignedBeaconBlock<E>>,
        VariableList<Arc<SignedBlobSidecar<E>>, E::MaxBlobsPerBlock>,
        DataAvailabilityError<E>,
    ),
    /// Verifying availability of a block that which already has a verified execution payload
    /// failed. Contains the blobs that have been received.
    ExecutedBlock(
        Arc<ExecutedBlock<E>>,
        VariableList<Arc<SignedBlobSidecar<E>>, E::MaxBlobsPerBlock>,
        DataAvailabilityError<E>,
    ),
}

#[derive(Debug)]
pub enum DataAvailabilityError<E: EthSpec> {
    /// Awaiting blobs over network timed out.
    TimedOut(TimedOut),
    /// Receiving an available block from pending-availability blobs cache failed.
    RecvBlobError(RecvBlobError),
    /// Sending an available block from pending-availability blobs cache failed.
    SendBlobError(SendError<Arc<SignedBlobSidecar<E>>>),
    // todo(emhane): move kzg error here to take care of blob or block
}

macro_rules! impl_from_error {
    ($error: ident, $parent_error: ident, $generic: ident) => {
        impl From<$error> for $parent_error<$generic> {
            fn from(e: $error) -> Self {
                Self::$error(e)
            }
        }
    };
}

impl_from_error!(TimedOut, DataAvailabilityError, EthSpec);
impl_from_error!(RecvBlobError, DataAvailabilityError, EthSpec);

impl From<SendError<Arc<SignedBlobSidecar<E>>>> for DataAvailabilityError<E> {
    fn from(e: BeaconChainError) -> Self {
        DataAvailabilityError::SendBlobError(e)
    }
}

impl<E: EthSpec> From<BlobReconstructionError> for BlobError<E> {
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
pub struct GossipVerifiedBlob<T: EthSpec>(Arc<SignedBlobSidecar<T>>);

impl<T: BeaconChainTypes> Into<Arc<SignedBlobSidecar<T>>> for GossipVerifiedBlob<T> {
    fn into(self) -> Arc<SignedBlobSidecar<T>> {
        self.0
    }
}

pub fn validate_blob_for_gossip<T: BeaconChainTypes, B: AsBlock<T>>(
    block: B,
    block_root: Hash256,
    chain: &BeaconChain<T>,
    blob_sidecar: SignedBlobSidecar<T>,
) -> Result<GossipVerifiedBlob, BlobError> {
    let blob_slot = blob_sidecar.beacon_block_slot();
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

    if blob_slot != block.blob_slot() {
        return Err(BlobError::SlotMismatch {
            blob_slot,
            block_slot: block.slot(),
        });
    }
    Ok(GossipVerifiedBlob(blob_sidecar))
}

fn verify_blobs<E: EthSpec, B: AsBlock<E>, Bs: AsBlobSidecar<E>>(
    block: B,
    blobs: VariableList<Bs, E::MaxBlobsPerBlock>,
    kzg: Option<&Kzg>,
) -> Result<(), BlobError> {
    let Some(kzg) = kzg else {
        return Err(BlobError::TrustedSetupNotInitialized)
    };
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
    verify_data_availability::<E>(
        blobs,
        kzg_commitments,
        transactions,
        block.slot(),
        block_root,
        kzg,
    )
}

fn verify_data_availability<T: EthSpec, Bs: AsBlobSidecar<T>>(
    blob_sidecars: VariableList<Bs, T::MaxBlobsPerBlock>,
    kzg_commitments: &[KzgCommitment],
    transactions: &Transactions<T>,
    block_slot: Slot,
    block_root: Hash256,
    kzg: &Kzg,
) -> Result<(), BlobError> {
    if verify_kzg_commitments_against_transactions::<T>(transactions, kzg_commitments).is_err() {
        return Err(BlobError::TransactionCommitmentMismatch);
    }

    // Validatate that the kzg proof is valid against the commitments and blobs
    let kzg = kzg.ok_or(BlobError::TrustedSetupNotInitialized)?;

    if !kzg_utils::validate_blob_sidecars(
        kzg,
        block_slot,
        block_root,
        kzg_commitments,
        blob_sidecars,
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

pub trait AsBlobSidecar<E: EthSpec> {
    fn beacon_block_root(&self) -> Hash256;
    fn beacon_block_slot(&self) -> Slot;
    fn proposer_index(&self) -> u64;
    fn block_parent_root(&self) -> Hash256;
    fn blob_index(&self) -> u64;
    fn blob(&self) -> Blob<E>;
    fn kzg_aggregated_proof(&self) -> KzgProof;
}

macro_rules! impl_as_blob_sidecar_fn_for_signed_sidecar {
    ($fn_name: ident, $return_type: ident) => {
        fn $fn_name() -> $return_type {
            Self::message().$fn_name()
        }
    };
}

impl<E: EthSpec> AsBlobSidecar<E> for Arc<SignedBlobSidecar<E>> {
    impl_as_blob_sidecar_fn_for_signed_sidecar!(beacon_block_root, Hash256);
    impl_as_blob_sidecar_fn_for_signed_sidecar!(beacon_block_slot, Slot);
    impl_as_blob_sidecar_fn_for_signed_sidecar!(proposer_index, u64);
    impl_as_blob_sidecar_fn_for_signed_sidecar!(block_parent_root, Hash256);
    impl_as_blob_sidecar_fn_for_signed_sidecar!(blob_index, u64);
    fn blob(&self) -> Blob<E> {
        self.message().blob()
    }
    impl_as_blob_sidecar_fn_for_signed_sidecar!(kzg_aggregated_proof, KzgProof);
}

#[derive(Copy, Clone)]
pub enum DataAvailabilityCheckRequired {
    Yes,
    No,
}

impl<T: BeaconChainTypes, B: AsBlock<T::EthSpec>> IntoAvailabilityPendingBlock<T, B>
    for GossipVerifiedBlock<T, B>
{
}
impl<T: BeaconChainTypes, B: AsBlock<T::EthSpec>> IntoAvailabilityPendingBlock<T, B>
    for SignatureVerifiedBlock<T, B>
{
}
impl<T: BeaconChainTypes, B: AsBlock<T::EthSpec>> IntoAvailabilityPendingBlock<T, B>
    for Arc<SignedBeaconBlock<T::EthSpec>>
{
}

impl<T: BeaconChainTypes, B: AsBlock<T::EthSpec>> IntoAvailabilityPendingBlock<T, B> for AvailabilityPendingBlock<T::EthSpec> {
    fn into_availablilty_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> AvailabilityPendingBlock<T::EthSpec> {
        self
    }
}
pub trait IntoAvailabilityPendingBlock<T: BeaconChainTypes, B: AsBlock<T::EthSpec>> {
    /// Takes a receiver as param, on which the availability-pending block receives kzg-verified
    /// blobs.
    fn into_availablilty_pending_block(
        self: B,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> AvailabilityPendingBlock<T::EthSpec> {
        // If a blob receiver exists for the block root, some blobs have already arrived.
        let existing_rx = chain.pending_blocks_rx.remove(&block_root);
        let rx = match existing_rx {
            Some(rx) => rx,
            None => {
                let (tx, rx) = mpsc::channel::<Arc<SignedBlobSidecar<T::EthSpec>>>(
                    T::EthSpec::MaxBlobsPerBlock,
                );
                chain.pending_blobs_tx.put(block_root, tx);
                rx
            }
        };

        let block = self.block;
        let Some(data_availability_boundary) = chain.data_availability_boundary() else {
            return Ok(AvailabilityPendingBlock {
                block,
                data_availability_handle:  async { Ok(AvailableBlock(AvailableBlockInner::Block(block))) },
            })
        };
        let data_availability_handle =
            if self.slot().epoch(T::EthSpec::slots_per_epoch()) >= data_availability_boundary {
                let kzg_commitments = self.message().body().kzg_commitments();
                let data_availability_handle = if kzg_commitments.is_empty() {
                    // check that txns match with empty kzg-commitments
                    verify_blobs(self.as_block(), VariableList::empty(), chain.kzg)?;
                    async { Ok(AvailableBlock(AvailableBlockInner::Block(block))) }
                } else {
                    let chain = chain.clone();
                    let block = block.clone();

                    let availability_handle = chain.task_executor.spwan_handle::<Result<
                        AvailableBlock<T::EthSpec>,
                        BlobError,
                    >>(
                        async move {
                            let blobs = VariableList::<
                                SignedBlobSidecar<T::EthSpec>,
                                T::EthSpec::MaxBlobsPerBlock,
                            >::with_capcity(
                                T::EthSpec::MaxBlobsPerBlock
                            );
                            loop {
                                match rx.try_recv() {
                                    Ok(Some(blob)) => {
                                        blobs.push(blob);
                                        if blobs.len() == kzg_commitments.len() {
                                            break;
                                        }
                                    }
                                    Ok(None) => {
                                        break;
                                    }
                                    Err(e) => {
                                        return BlobError::DataAvailabilityFailed(block, blobs, e)
                                    }
                                }
                            }
                            let kzg_handle = chain
                                .task_executor
                                .spawn_blocking_handle::<Result<(), BlobError>>(
                                    move || {
                                        verify_blobs(&block, blobs, chain.kzg).map_err(|e| {
                                            BlobError::DataAvailabilityFailed(block, blobs, e)
                                        })
                                    },
                                    &format!("verify_blobs_{block_root}"),
                                );
                            kzg_handle
                                .await
                                .map_err(|e| BlobError::DataAvailabilityFailed(block, blobs, e))?;
                            chain.pending_blobs_tx.remove(&block_root);
                            Ok(AvailableBlock(AvailableBlockInner::BlockAndBlobs(
                                block, blobs,
                            )))
                        },
                        format!("data_availability_block_{block_root}"),
                    );

                    tokio::time::timeout(
                        Duration::from_secs(AVAILABILITY_PENDING_CACHE_ITEM_TIMEOUT),
                        availability_handle,
                    )
                };
                data_availability_handle
            } else {
                async { Ok(AvailableBlock(AvailableBlockInner::Block(block))) }
            };
        Ok(AvailabilityPendingBlock {
            block,
            data_availability_handle,
        })
    }
}

#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
pub struct AvailabilityPendingBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    data_availability_handle: DataAvailabilityHandle<E>,
}

impl<E: EthSpec> Future for AvailabilityPendingBlock<E> {
    type Output = Result<AvailableBlock<E>, BlobError<E>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.data_availability_handle.poll()
    }
}

/// Used to await blobs from the network.
type DataAvailabilityHandle<E: EthSpec> =
    JoinHandle<Result<AvailableBlock<E>, DataAvailabilityFailed<E>>>;

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
    /// A blob that does not have blobs, regardless if data availability check is required or not.
    Block(Arc<SignedBeaconBlock<E>>),
    /// The container for any block which has blobs and the blobs have been verified.
    BlockAndBlobs(
        Arc<SignedBeaconBlock<E>>,
        VariableList<SignedBlobSidecar<E>, E::MaxBlobsPerBlock>,
    ),
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn blobs(&self) -> Option<Arc<SignedBlobSidecar<E>>> {
        match &self.0 {
            AvailableBlockInner::Block(_) => None,
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => {
                Some(block_blobs_pair.1.clone())
            }
        }
    }

    pub fn deconstruct(
        self,
    ) -> (
        Arc<SignedBeaconBlock<E>>,
        Option<Arc<SignedBlobsSidecar<E>>>,
    ) {
        match self.0 {
            AvailableBlockInner::Block(block) => (block, None),
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => {
                (block_blobs_pair.0, Some(block_blobs_pair.1))
            }
        }
    }
}

impl<E: EthSpec> TryInto<AvailableBlock<E>> for AvailableBlock<E> {
    type Error = BlobError<E>;
    fn try_into(self, chain: &BeaconChain<E>) -> Result<AvailableBlock<E>, Self::Error> {
        Ok(self)
    }
}

impl<E: EthSpec> TryInto<AvailableBlock<E>> for &AvailabilityPendingBlock<E> {
    type Error = BlobError<E>;
    fn try_into(self) -> Result<AvailableBlock<E>, Self::Error> {
        match self.poll() {
            Poll::Pending => Err(BlobError::PendingAvailability),
            Poll::Ready(Ok(available_block)) => Ok(available_block),
            Poll::Ready(Err(e)) => Err(e),
        }
    }
}

/// The maximum time an [`AvailabilityPendingBlock`] is cached in seconds.
pub const AVAILABILITY_PENDING_CACHE_ITEM_TIMEOUT: u64 = 5;

/// A block that has passed payload verification and is waiting for its blobs via the handle on
/// [`AvailabilityPendingBlock`].
pub struct ExecutedBlock<E: EthSpec> {
    block_root: Hash256,
    block: AvailabilityPendingBlock<E>,
    state: BeaconState<E>,
    confirmed_state_roots: Vec<Hash256>,
    payload_verification_status: PayloadVerificationStatus,
    count_unrealized: CountUnrealized,
    parent_block: SignedBeaconBlock<E>,
    parent_eth1_finalization_data: Eth1FinalizationData,
    consensus_context: ConsensusContext<E>,
}

impl<E: EthSpec, B: TryInto<AvailableBlock<E>>> Future for ExecutedBlock<E> {
    type Output = Result<Self, BlobError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let availability_state = self.block.poll();
        match availability_state {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(available_block)) => Poll::Ready(Ok(self)),
            Poll::Ready(Err(BlobError::DataAvailabilityFailed(DataAvailabilityFailed::Block(
                _,
                blobs,
                e,
            )))) => Poll::Ready(Err(BlobError::DataAvailabilityFailed(
                DataAvailabilityFailed::ExecutedBlock(self, blobs, e),
            ))),
        }
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

impl<E: EthSpec> AsBlock<E> for AvailableBlock<E> {
    fn slot(&self) -> Slot {
        match self {
            AvailableBlock::Block(block) => block.slot(),
            AvailableBlock::BlockAndBlobs(block, _) => block.slot(),
        }
    }
    fn epoch(&self) -> Epoch {
        match self {
            AvailableBlock::Block(block) => block.epoch(),
            AvailableBlock::BlockAndBlobs(block, _) => block.epoch(),
        }
    }
    fn parent_root(&self) -> Hash256 {
        match self {
            AvailableBlock::Block(block) => block.parent_root(),
            AvailableBlock::BlockAndBlobs(block, _) => block.parent_root(),
        }
    }
    fn state_root(&self) -> Hash256 {
        match self {
            AvailableBlock::Block(block) => block.state_root(),
            AvailableBlock::BlockAndBlobs(block, _) => block.state_root(),
        }
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        match &self {
            AvailableBlock::Block(block) => block.signed_block_header(),
            AvailableBlock::BlockAndBlobs(block, _) => block.signed_block_header(),
        }
    }
    fn message(&self) -> BeaconBlockRef<E> {
        match &self {
            AvailableBlock::Block(block) => block.message(),
            AvailableBlock::BlockAndBlobs(block, _) => block.message(),
        }
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            AvailableBlock::Block(block) => &block,
            AvailableBlock::BlockAndBlobs(block, _) => &block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            AvailableBlock::Block(block) => block.clone(),
            AvailableBlock::BlockAndBlobs(block, _) => block.clone(),
        }
    }
}

impl<E: EthSpec> AsBlock<E> for AvailabilityPendingBlock<E> {
    fn slot(&self) -> Slot {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.slot(),
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => block_blobs_pair.0.slot(),
        }
    }
    fn epoch(&self) -> Epoch {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.epoch(),
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => block_blobs_pair.0.epoch(),
        }
    }
    fn parent_root(&self) -> Hash256 {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.parent_root(),
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => {
                block_blobs_pair.0.parent_root()
            }
        }
    }
    fn state_root(&self) -> Hash256 {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.state_root(),
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => block_blobs_pair.0.state_root(),
        }
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.signed_block_header(),
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => {
                block_blobs_pair.0.signed_block_header()
            }
        }
    }
    fn message(&self) -> BeaconBlockRef<E> {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.message(),
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => block_blobs_pair.0.message(),
        }
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self.0 {
            AvailableBlockInner::Block(block) => &block,
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => &block_blobs_pair.0,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.clone(),
            AvailableBlockInner::BlockAndBlobs(block_blobs_pair) => block_blobs_pair.0.clone(),
        }
    }
}

impl<E: EthSpec> AsBlock<E> for Arc<SignedBeaconBlock<E>> {
    fn slot(&self) -> Slot {
        self.slot()
    }
    fn epoch(&self) -> Epoch {
        self.epoch()
    }
    fn parent_root(&self) -> Hash256 {
        self.parent_root()
    }
    fn state_root(&self) -> Hash256 {
        match self {
            BlockWrapper::Block(block) => block.state_root(),
            BlockWrapper::BlockAndBlobs(block, _) => block.state_root(),
        }
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.signed_block_headeR()
    }
    fn message(&self) -> BeaconBlockRef<E> {
        self.message()
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        &self
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.clone()
    }
}
