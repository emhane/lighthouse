use crate::beacon_chain::{
    BeaconChain, BeaconChainTypes, DEFAULT_BLOB_CHANNEL_CAPACITY, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
};
use crate::block_verification::{
    ExecutionPendingBlock, GossipVerifiedBlock, SignatureVerifiedBlock,
};
use crate::{eth1_finalization_cache::Eth1FinalizationData, kzg_utils, BeaconChainError};
use derivative::Derivative;
use fork_choice::{CountUnrealized, PayloadVerificationStatus};
use futures::{
    channel::{
        mpsc,
        mpsc::{TryRecvError, TrySendError},
        oneshot,
        oneshot::Canceled,
    },
    future::Future,
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

#[derive(Debug, Clone)]
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
    /// A blob for this index has already been seen.
    BlobAlreadyExistsAtIndex(Arc<SignedBlobSidecar<E>>),
    /// Error using one shot sender.
    SendOneshot(Arc<SignedBlobSidecar<E>>),
    /// Error using one shot receiver.
    RecvOneshot(Canceled),
    /// Awaiting blobs over network timed out.
    TimedOut(TimedOut),
    /// Receiving an available block from pending-availability blobs cache failed.
    RecvBlob(TryRecvError),
    /// Sending an available block from pending-availability blobs cache failed.
    SendBlob(TrySendError<E>),
    /// Spawning threads failed.
    TaskExecutor,
}

#[derive(Debug, Clone)]
pub enum DataAvailabilityFailure<E: EthSpec> {
    /// Verifying data availability of a block failed. Contains the blobs that have been received
    /// and the block if it has been received.
    Block(
        Option<Arc<SignedBeaconBlock<E>>>,
        VariableList<Arc<SignedBlobSidecar<E>>, E::MaxBlobsPerBlock>,
        BlobError<E>,
    ),
    /// Verifying data availability of a block that which already has a verified execution payload
    /// failed. The error contains the block and blobs that have been received.
    ExecutedBlock(
        Arc<ExecutedBlock<E>>,
        VariableList<Arc<SignedBlobSidecar<E>>, E::MaxBlobsPerBlock>,
        BlobError<E>,
    ),
}

#[macro_export]
macro_rules! impl_wrap_type_in_variant {
    ($(<$($generic: ident : $trait: ident$(<$($generic_two: ident,)+>)*,)+>)*, $from_type: ty, $to_type: ty, $to_type_variant: path) => {
        impl$(<$($generic: $trait$(<$($generic_two,)+>)*,)+>)* From<$from_type> for $to_type {
            fn from(e: $from_type) -> Self {
                $to_type_variant(e)
            }
        }
    };
}

impl_wrap_type_in_variant!(<E: EthSpec,>, kzg::Error, BlobError<E>, Self::KzgError);
impl_wrap_type_in_variant!(<E: EthSpec,>, BeaconChainError, BlobError<E>, Self::BeaconChainError);
impl_wrap_type_in_variant!(<E: EthSpec,>, Arc<SignedBlobSidecar<E>>, BlobError<E>, Self::BlobAlreadyExistsAtIndex);
impl_wrap_type_in_variant!(<E: EthSpec,>, Canceled, BlobError<E>, Self::RecvOneshot);
impl_wrap_type_in_variant!(<E: EthSpec,>, TimedOut, BlobError<E>, Self::TimedOut);
impl_wrap_type_in_variant!(<E: EthSpec,>, TryRecvError, BlobError<E>, Self::RecvBlob);
impl_wrap_type_in_variant!(<E: EthSpec,>, TrySendError<E>, BlobError<E>, Self::SendBlob);

impl<E: EthSpec> From<BlobReconstructionError> for BlobError<E> {
    fn from(e: BlobReconstructionError) -> Self {
        match e {
            BlobReconstructionError::UnavailableBlobs => BlobError::UnavailableBlobs,
            BlobReconstructionError::InconsistentFork => BlobError::InconsistentFork,
        }
    }
}

impl<E: EthSpec> From<BeaconStateError> for BlobError<E> {
    fn from(e: BeaconStateError) -> Self {
        BlobError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

/// A wrapper around a [`SignedBlobSidecar`] that indicates it has been approved for re-gossiping
/// on the p2p network.
pub struct GossipVerifiedBlob<T: EthSpec>(Arc<SignedBlobSidecar<T>>);

impl<E: EthSpec> From<Arc<SignedBlobSidecar<E>>> for GossipVerifiedBlob<E> {
    fn from(blob: Arc<SignedBlobSidecar<E>>) -> GossipVerifiedBlob<E> {
        GossipVerifiedBlob(blob)
    }
}

pub fn validate_blob_for_gossip<T: BeaconChainTypes, B: AsSignedBlock<T::EthSpec>>(
    block: B,
    block_root: Hash256,
    chain: &BeaconChain<T>,
    blob_sidecar: Arc<SignedBlobSidecar<T::EthSpec>>,
) -> Result<GossipVerifiedBlob<T::EthSpec>, BlobError<T::EthSpec>> {
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

    if blob_slot != block.slot() {
        return Err(BlobError::SlotMismatch {
            blob_slot,
            block_slot: block.slot(),
        });
    }
    Ok(GossipVerifiedBlob(blob_sidecar))
}

fn verify_blobs<E: EthSpec, B: AsSignedBlock<E>, Bs: AsBlobSidecar<E>>(
    block: B,
    blobs: VariableList<Bs, E::MaxBlobsPerBlock>,
    kzg: Option<Arc<Kzg>>,
) -> Result<(), BlobError<E>> {
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
    verify_data_availability::<E, Bs>(
        blobs,
        kzg_commitments,
        transactions,
        block.slot(),
        block.block_root(),
        kzg,
    )
}

fn verify_data_availability<T: EthSpec, Bs: AsBlobSidecar<T>>(
    blob_sidecars: VariableList<Bs, T::MaxBlobsPerBlock>,
    kzg_commitments: &[KzgCommitment],
    transactions: &Transactions<T>,
    block_slot: Slot,
    block_root: Hash256,
    kzg: Option<Arc<Kzg>>,
) -> Result<(), BlobError<T>> {
    if verify_kzg_commitments_against_transactions::<T>(transactions, kzg_commitments).is_err() {
        return Err(BlobError::TransactionCommitmentMismatch);
    }

    // Validatate that the kzg proof is valid against the commitments and blobs
    let kzg = kzg.ok_or(BlobError::TrustedSetupNotInitialized)?;

    if !kzg_utils::validate_blob_sidecars(
        &*kzg,
        block_slot,
        block_root,
        kzg_commitments,
        blob_sidecars,
    )? {
        return Err(BlobError::InvalidKzgProof);
    }
    Ok(())
}

/// A wrapper over a block in which a [`SignedBeaconBlock`] is nested. This makes no claims about
/// data availability and should not be used in consensus. This struct is useful in networking
/// when we want to send blocks around without consensus checks.
#[derive(Debug)]
pub enum BlockWrapper<E: EthSpec> {
    Block(AvailabilityPendingBlock<E>),
    ExecutedBlock(ExecutedBlock<E>),
}
// todo(emhane): which other blocks are passed to process_block?
impl_wrap_type_in_variant!(<E: EthSpec,>, AvailabilityPendingBlock<E>, BlockWrapper<E>, Self::Block);
impl_wrap_type_in_variant!(<E: EthSpec,>, ExecutedBlock<E>, BlockWrapper<E>, Self::ExecutedBlock);

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
    ($field: ident, $return_type: ty) => {
        fn $field(&self) -> $return_type {
            self.message().$field
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
        self.message().blob.clone()
    }
    impl_as_blob_sidecar_fn_for_signed_sidecar!(kzg_aggregated_proof, KzgProof);
}

#[derive(Copy, Clone)]
pub enum DataAvailabilityCheckRequired {
    Yes,
    No,
}

impl<
        T: BeaconChainTypes,
        B: IntoAvailabilityPendingBlock<T> + AsSignedBlock<T::EthSpec> + Send + Sync,
    > IntoWrappedAvailabilityPendingBlock<T> for ExecutionPendingBlock<T, B>
{
    type Block = ExecutionPendingBlock<T, B>;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Self::Block {
        if self.is_availability_pending() {
            return self;
        }
        let ExecutionPendingBlock {
            block,
            block_root,
            state,
            parent_block,
            parent_eth1_finalization_data,
            confirmed_state_roots,
            consensus_context,
            payload_verification_handle,
        } = self;
        // If this block is already wraps an availability-pending block nothing changes.
        let availability_pending_block = block.into_availability_pending_block(block_root, chain);
        ExecutionPendingBlock {
            block: availability_pending_block,
            block_root,
            state,
            parent_block,
            parent_eth1_finalization_data,
            confirmed_state_roots,
            consensus_context,
            payload_verification_handle,
        }
    }
}

impl<T: BeaconChainTypes> IntoWrappedAvailabilityPendingBlock<T> for ExecutedBlock<T::EthSpec> {
    type Block = ExecutedBlock<T::EthSpec>;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Self::Block {
        // Make a new data availability handle. Will use existing channel to receive blobs if one
        // exists.
        let availability_pending_block = self
            .block
            .block_cloned()
            .into_availability_pending_block(block_root, chain);
        self.block = availability_pending_block;
        self
    }
}

impl<
        T: BeaconChainTypes,
        B: IntoAvailabilityPendingBlock<T> + AsSignedBlock<T::EthSpec> + Send + Sync,
    > IntoWrappedAvailabilityPendingBlock<T> for SignatureVerifiedBlock<T, B>
{
    type Block = SignatureVerifiedBlock<T, B>;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Self::Block {
        if self.is_availability_pending() {
            return self;
        }
        let SignatureVerifiedBlock {
            block,
            block_root,
            parent,
            consensus_context,
        } = self;
        let availability_pending_block = block.into_availability_pending_block(block_root, chain);
        SignatureVerifiedBlock {
            block: availability_pending_block,
            block_root,
            parent,
            consensus_context,
        }
    }
}

impl<
        T: BeaconChainTypes,
        B: IntoAvailabilityPendingBlock<T> + AsSignedBlock<T::EthSpec> + Send + Sync,
    > IntoWrappedAvailabilityPendingBlock<T> for GossipVerifiedBlock<T, B>
{
    type Block = GossipVerifiedBlock<T, B>;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Self::Block {
        if self.is_availability_pending() {
            return self;
        }
        let GossipVerifiedBlock {
            block,
            block_root,
            parent,
            consensus_context,
        } = self;
        let availability_pending_block = block.into_availability_pending_block(block_root, chain);
        GossipVerifiedBlock {
            block: availability_pending_block,
            block_root,
            parent,
            consensus_context,
        }
    }
}

/// Reconstructs a block with metadata to update its inner block to an
/// [`AvailabilityPendingBlock`].
pub trait IntoWrappedAvailabilityPendingBlock<T: BeaconChainTypes> {
    type Block;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Self::Block;
}

impl<T: BeaconChainTypes> IntoAvailabilityPendingBlock<T> for AvailabilityPendingBlock<T::EthSpec> {
    fn into_availablilty_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, DataAvailabilityFailure<T::EthSpec>> {
        Ok(self)
    }
}

impl<
        T: BeaconChainTypes,
        B: IntoAvailabilityPendingBlock<T>
            + AsSignedBlock<T::EthSpec>
            + Send
            + Sync
            + NotYetAvailabilityPending,
    > IntoAvailabilityPendingBlock<T> for B
{
}

pub trait NotYetAvailabilityPending {}
impl<E: EthSpec> NotYetAvailabilityPending for Arc<SignedBeaconBlock<E>> {}

/// Consumes a block and wraps it in an [`AvailabilityPendingBlock`] with a
/// [`DataAvailabilityHandle`] to receive blobs on from the network and kzg-verify them, returning
/// an [`AvailableBlock`] on success, and on failure returns the parts that have been gathered so
/// far wrapped in a [`DataAvailabilityFailure::Block`] error variant upon failure.
pub trait IntoAvailabilityPendingBlock<T: BeaconChainTypes> {
    fn into_availablilty_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, DataAvailabilityFailure<T::EthSpec>> {
        // If a blob receiver exists for the block root, some blobs have already arrived.
        let existing_rx = chain.pending_blocks_rx.remove(&block_root);
        let rx = match existing_rx {
            Some(rx) => rx,
            None => {
                let (tx, rx) = mpsc::channel::<(
                    Arc<SignedBlobSidecar<T::EthSpec>>,
                    oneshot::Sender<Result<(), BlobError<T::EthSpec>>>,
                )>(T::EthSpec::max_blobs_per_block());
                chain.pending_blobs_tx.insert(block_root, tx);
                rx
            }
        };
        let block = self.block_cloned();
        let Some(data_availability_boundary) = chain.data_availability_boundary() else {
            let data_availability_handle = chain.task_executor.spawn_handle_mock(Ok(AvailableBlock(AvailableBlockInner::Block(block)))).ok_or(DataAvailabilityFailure::Block(None, VariableList::empty(), BlobError::TaskExecutor))?;

                return Ok(AvailabilityPendingBlock {
                    block,
                    data_availability_handle,
                })
            };
        let data_availability_handle = if self.slot().epoch(T::EthSpec::slots_per_epoch())
            >= data_availability_boundary
        {
            let kzg_commitments = self.message().body().blob_kzg_commitments()?;
            if kzg_commitments.is_empty() {
                // check that txns match with empty kzg-commitments
                verify_blobs(self.as_block(), VariableList::empty(), chain.kzg).map_err(|e| {
                    DataAvailabilityFailure::Block(Some(block), VariableList::empty(), e)
                })?;
                chain
                    .task_executor
                    .spawn_handle_mock(Ok(AvailableBlock(AvailableBlockInner::Block(block))))
                    .ok_or(DataAvailabilityFailure::Block(
                        Some(block),
                        VariableList::empty(),
                        BlobError::TaskExecutor,
                    ))
            } else {
                let chain = chain.clone();
                let block = block.clone();

                chain
                    .task_executor
                    .spawn_handle(
                        async move {
                            let blobs = VariableList::<
                                Arc<SignedBlobSidecar<T::EthSpec>>,
                                T::EthSpec::MaxBlobsPerBlock,
                            >::with_capcity(
                                T::EthSpec::max_blobs_per_block()
                            );

                            loop {
                                match rx.try_next() {
                                    Ok(Some((blob, tx))) => {
                                        if blobs.iter().find(|existing_blob| {
                                            existing_blob.blob_index() == blob.blob_index()
                                        }) {
                                            tx.send(Err(BlobError::BlobAlreadyExistsAtIndex(blob)))
                                                .map_err(|e| {
                                                    e.map_err(|e| {
                                                        DataAvailabilityFailure::Block(
                                                            Some(block),
                                                            blobs,
                                                            e,
                                                        )
                                                    })
                                                })?;
                                        } else {
                                            tx.send(Ok(())).map_err(|e| {
                                                e.map_err(|e| {
                                                    DataAvailabilityFailure::Block(
                                                        Some(block),
                                                        blobs,
                                                        e,
                                                    )
                                                })
                                            })?;
                                        }
                                        blobs.push(blob);
                                        if blobs.len() == kzg_commitments.len() {
                                            break;
                                        }
                                    }
                                    Ok(None) => {
                                        break;
                                    }
                                    Err(e) => {
                                        return Err(DataAvailabilityFailure::Block(
                                            Some(block),
                                            blobs,
                                            e.into(),
                                        ))
                                    }
                                }
                            }

                            let kzg_handle = chain.task_executor.spawn_blocking_handle(
                                move || {
                                    verify_blobs(&block, blobs, chain.kzg).map_err(|e| {
                                        DataAvailabilityFailure::Block(Some(block), blobs, e)
                                    })
                                },
                                &format!("verify_blobs_{block_root}"),
                            );
                            kzg_handle
                                .ok_or(DataAvailabilityFailure::Block(
                                    Some(block),
                                    VariableList::empty(),
                                    BlobError::TaskExecutor,
                                ))?
                                .await
                                .map_err(|e| {
                                    DataAvailabilityFailure::Block(
                                        Some(block),
                                        blobs,
                                        BlobError::TaskExecutor,
                                    )
                                })?;

                            chain.pending_blobs_tx.remove(&block_root);

                            Ok(AvailableBlock(AvailableBlockInner::BlockAndBlobs(
                                block, blobs,
                            )))
                        },
                        &format!("data_availability_block_{block_root}"),
                    )
                    .ok_or(DataAvailabilityFailure::Block(
                        Some(block),
                        VariableList::empty(),
                        BlobError::TaskExecutor,
                    ))
            }
        } else {
            chain
                .task_executor
                .spawn_handle_mock(Ok(AvailableBlock(AvailableBlockInner::Block(block))))
                .ok_or(DataAvailabilityFailure::Block(
                    None,
                    VariableList::empty(),
                    BlobError::TaskExecutor,
                ))
        }?;
        Ok(AvailabilityPendingBlock {
            block,
            data_availability_handle,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AvailabilityPendingBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    data_availability_handle: DataAvailabilityHandle<E>,
}

impl<E: EthSpec> Future for AvailabilityPendingBlock<E> {
    type Output = Result<AvailableBlock<E>, BlobError<E>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.data_availability_handle.try_poll()
    }
}

/// Used to await blobs from the network.
type DataAvailabilityHandle<E: EthSpec> =
    JoinHandle<Option<Result<AvailableBlock<E>, DataAvailabilityFailure<E>>>>;

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
        VariableList<Arc<SignedBlobSidecar<E>>, E::MaxBlobsPerBlock>,
    ),
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn blobs(&self) -> Option<VariableList<Arc<SignedBlobSidecar<E>>, E::MaxBlobsPerBlock>> {
        match &self.0 {
            AvailableBlockInner::Block(_) => None,
            AvailableBlockInner::BlockAndBlobs(_, blobs) => Some(blobs.clone()),
        }
    }

    pub fn deconstruct(
        self,
    ) -> (
        Arc<SignedBeaconBlock<E>>,
        Option<VariableList<SignedBlobSidecar<E>, E::MaxBlobsPerBlock>>,
    ) {
        match self.0 {
            AvailableBlockInner::Block(block) => (block, None),
            AvailableBlockInner::BlockAndBlobs(block, blobs) => (block, Some(blobs)),
        }
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
#[derive(Clone, Debug)]
pub struct ExecutedBlock<E: EthSpec> {
    block_root: Hash256,
    block: AvailabilityPendingBlock<E>,
    state: BeaconState<E>, // todo(emhane): is this send + sync?
    confirmed_state_roots: Vec<Hash256>,
    payload_verification_status: PayloadVerificationStatus,
    count_unrealized: CountUnrealized,
    parent_block: Arc<SignedBeaconBlock<E>>,
    parent_eth1_finalization_data: Eth1FinalizationData,
    consensus_context: ConsensusContext<E>,
}

impl<E: EthSpec> Future for ExecutedBlock<E> {
    type Output = Result<Arc<ExecutedBlock<E>>, DataAvailabilityFailure<E>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let availability_state = self.block.poll();
        match availability_state {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(available_block)) => Poll::Ready(Ok(Arc::new(self.clone()))),
            Poll::Ready(Err(DataAvailabilityFailure::Block(_, blobs, e))) => Poll::Ready(Err(
                DataAvailabilityFailure::ExecutedBlock(Arc::new(self.clone()), blobs, e),
            )),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

pub trait AsSignedBlock<E: EthSpec> {
    fn slot(&self) -> Slot;
    fn epoch(&self) -> Epoch;
    fn parent_root(&self) -> Hash256;
    fn state_root(&self) -> Hash256;
    fn signed_block_header(&self) -> SignedBeaconBlockHeader;
    fn message(&self) -> BeaconBlockRef<E>;
    fn as_block(&self) -> &SignedBeaconBlock<E>;
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>>;
    fn is_availability_pending(&self) -> bool;
}

#[macro_export]
macro_rules! impl_as_signed_block {
    ($fn_name: ident, $return_type: ty, $(.$field: tt)*) => {
        fn $fn_name(&self) -> $return_type {
            self$(.$field)*.$fn_name()
        }
    };
    ($fn_name: ident, $(.$field: tt)* $return_type: ty, $enum_variant_block: ident$(::$variant: ident)*, $enum_variant_block_and: ident$(::$variant_two: ident)*) => {
        fn $fn_name(&self) -> $return_type {
            match self$(.$field)* {
                $enum_variant_block$(::$variant)+(block) => block.$fn_name(),
                $enum_variant_block_and$(::$variant_two)+((block, _)) => block.$fn_name(),
            }
        }
    };
    ($type: ty, $(.$field: tt)* $(,$generic: ident: $trait: ident$(<$($generics: ident,)+>)*$(+ $traits: ident$(<$($generics_nested: ident,)+>)*)*)*) => {
        impl<E: EthSpec $(,$generic: $trait$(<$($generics,)+>)*$(+ $traits$(<$($generics_nested,)+>)*)*)*> AsSignedBlock<E> for $type {
            impl_as_signed_block!(slot, Slot, $(.$field)*);
            impl_as_signed_block!(epoch, Epoch, $(.$field)*);
            impl_as_signed_block!(parent_root, Hash256, $(.$field)*);
            impl_as_signed_block!(state_root, Hash256, $(.$field)*);
            impl_as_signed_block!(signed_block_header, SignedBeaconBlockHeader, $(.$field)*);
            impl_as_signed_block!(message, BeaconBlockRef<E>, $(.$field)*);
            impl_as_signed_block!(as_block, &SignedBeaconBlock<E>, $(.$field)*);
            impl_as_signed_block!(block_cloned, Arc<SignedBeaconBlock<E>>, $(.$field)*);
            impl_as_signed_block!(is_availability_pending, bool, $(.$field)*);
        }
    };
    ($type: ty, $(.$field: tt)* $enum_variant_block: ident$(::$variant: ident)*, $enum_variant_block_and: ident$(::$variant_two: ident)* $(,$generic: ident: $trait: ident$(<$($generics: ident,)+>)*$(+ $traits: ident$(<$($generics_nested: ident,)+>)*)*)*) => {
        impl<E: EthSpec $(,$generic: $trait$(<$($generics,)+>)*$(+ $traits$(<$($generics_nested,)+>)*)*)*> AsSignedBlock<E> for $type {
            impl_as_signed_block!(slot, Slot, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+);
            impl_as_signed_block!(epoch, Epoch, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+);
            impl_as_signed_block!(parent_root, Hash256, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+);
            impl_as_signed_block!(state_root, Hash256, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+);
            impl_as_signed_block!(signed_block_header, SignedBeaconBlockHeader, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+);
            impl_as_signed_block!(message, BeaconBlockRef<E>, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+);
            impl_as_signed_block!(as_block, &SignedBeaconBlock<E>, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+);
            impl_as_signed_block!(block_cloned, Arc<SignedBeaconBlock<E>>, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+);
            impl_as_signed_block!(is_availability_pending, bool,$enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+);
        }
    };
}

impl_as_signed_block!(GossipVerifiedBlock<T, B>, .block, T: BeaconChainTypes, B: IntoAvailabilityPendingBlock<T,> + SignedBlock<E,> + Send + Sync,);
impl_as_signed_block!(ExecutedBlock<E>, .block);
impl_as_signed_block!(BlockWrapper<E>, .0 Self::Block, Self::ExecutedBlock);
impl_as_signed_block!(AvailableBlock<E>, .0.0 AvailableBlockInner::Block, AvailableBlockInner::BlockAndBlobs);

impl<E: EthSpec> AsSignedBlock<E> for Arc<SignedBeaconBlock<E>> {
    impl_as_signed_block!(slot, Slot,);
    impl_as_signed_block!(epoch, Epoch,);
    impl_as_signed_block!(parent_root, Hash256,);
    impl_as_signed_block!(state_root, Hash256,);
    impl_as_signed_block!(signed_block_header, SignedBeaconBlockHeader,);
    impl_as_signed_block!(message, BeaconBlockRef<E>,);
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        &*self
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.clone()
    }
    fn is_availability_pending(&self) -> bool {
        false
    }
}

impl<E: EthSpec> AsSignedBlock<E> for AvailabilityPendingBlock<E> {
    impl_as_signed_block!(slot, Slot, .block);
    impl_as_signed_block!(epoch, Epoch, .block);
    impl_as_signed_block!(parent_root, Hash256, .block);
    impl_as_signed_block!(state_root, Hash256, .block);
    impl_as_signed_block!(signed_block_header, SignedBeaconBlockHeader, .block);
    impl_as_signed_block!(message, BeaconBlockRef<E>, .block);
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        &*self.block
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }
    fn is_availability_pending(&self) -> bool {
        true
    }
}
