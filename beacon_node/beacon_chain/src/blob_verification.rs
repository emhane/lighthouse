use crate::beacon_chain::{BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use crate::block_verification::{
    BlockError, ExecutionPendingBlock, GossipVerifiedBlock, SignatureVerifiedBlock,
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
    StreamExt,
};
use kzg::Kzg;
use slog::error;
use slot_clock::SlotClock;
use ssz_types::VariableList;
use state_processing::{
    per_block_processing::eip4844::eip4844::verify_kzg_commitments_against_transactions,
    ConsensusContext,
};
use std::{
    fmt::Debug,
    marker::Sized,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{task::JoinHandle, time::Duration};
use types::signed_beacon_block::BlobReconstructionError;
use types::{
    BeaconBlockRef, BeaconStateError, EthSpec, Hash256, KzgCommitment, SignedBeaconBlock,
    SignedBeaconBlockHeader, SignedBlobSidecar, Slot, Transactions,
};
use types::{BeaconState, Blob, Epoch, ExecPayload, KzgProof};

pub const DEFAULT_DATA_AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum BlobError<T: EthSpec> {
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
    BlobAlreadyExistsAtIndex(Arc<SignedBlobSidecar<T>>),
    /// Error using oneshot sender for blob pointing to given block root to notify blob sender.
    SendOneshot(Hash256),
    /// Error using oneshot receiver to get green light from blob receiver.
    RecvOneshot(Canceled),
    /// Awaiting data availability timed out.
    TimedOut(Duration),
    /// Receiving a blob failed.
    RecvBlob(TryRecvError),
    /// Sending a blob failed.
    SendBlob(TrySendError<Arc<SignedBlobSidecar<T>>>),
    /// Spawning threads failed.
    TaskExecutor,
}

#[derive(Debug)]
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
        ExecutedBlockInError<E>,
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

impl_wrap_type_in_variant!(<T: EthSpec,>, kzg::Error, BlobError<T>, Self::KzgError);
impl_wrap_type_in_variant!(<T: EthSpec,>, BeaconChainError, BlobError<T>, Self::BeaconChainError);
impl_wrap_type_in_variant!(<T: EthSpec,>, Arc<SignedBlobSidecar<T>>, BlobError<T>, Self::BlobAlreadyExistsAtIndex);
impl_wrap_type_in_variant!(<T: EthSpec,>, Canceled, BlobError<T>, Self::RecvOneshot);
impl_wrap_type_in_variant!(<T: EthSpec,>, TryRecvError, BlobError<T>, Self::RecvBlob);
impl_wrap_type_in_variant!(<T: EthSpec,>, TrySendError<Arc<SignedBlobSidecar<T>>>, BlobError<T>, Self::SendBlob);

impl<T: EthSpec> From<BlobReconstructionError> for BlobError<T> {
    fn from(e: BlobReconstructionError) -> Self {
        match e {
            BlobReconstructionError::UnavailableBlobs => BlobError::UnavailableBlobs,
            BlobReconstructionError::InconsistentFork => BlobError::InconsistentFork,
        }
    }
}

impl<T: EthSpec> From<BeaconStateError> for BlobError<T> {
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

pub fn validate_blob_for_gossip<T: BeaconChainTypes, B: AsSignedBlock<T>>(
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

fn verify_blobs<T: EthSpec>(
    block: &SignedBeaconBlock<T>,
    blobs: VariableList<Arc<SignedBlobSidecar<T>>, T::MaxBlobsPerBlock>,
    kzg: Option<Arc<Kzg>>,
) -> Result<(), BlobError<T>> {
    let Some(kzg) = kzg else {
        return Err(BlobError::TrustedSetupNotInitialized)
    };
    let kzg_commitments = block
        .message()
        .body()
        .blob_kzg_commitments()
        .map_err(|_| BlobError::KzgCommitmentMissing)?;
    let transactions = block
        .message()
        .body()
        .execution_payload_eip4844()
        .map(|payload| payload.transactions())
        .transpose()
        .ok_or(BlobError::TransactionsMissing)??;
    verify_data_availability::<T>(
        blobs,
        kzg_commitments,
        transactions,
        block.slot(),
        block.block_root(),
        kzg,
    )
}

fn verify_data_availability<T: EthSpec>(
    blob_sidecars: VariableList<Arc<SignedBlobSidecar<T>>, T::MaxBlobsPerBlock>,
    kzg_commitments: &[KzgCommitment],
    transactions: &Transactions<T>,
    block_slot: Slot,
    block_root: Hash256,
    kzg: Arc<Kzg>,
) -> Result<(), BlobError<T>> {
    if verify_kzg_commitments_against_transactions::<T>(transactions, kzg_commitments).is_err() {
        return Err(BlobError::TransactionCommitmentMismatch);
    }

    // Validatate that the kzg proof is valid against the commitments and blobs
    if !kzg_utils::validate_blob_sidecars(
        *kzg,
        block_slot,
        block_root,
        kzg_commitments,
        blob_sidecars
            .into_iter()
            .map(|blob| Arc::new(blob.message))
            .collect::<Vec<_>>()
            .into(),
    )? {
        return Err(BlobError::InvalidKzgProof);
    }
    Ok(())
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

impl<T: BeaconChainTypes, B: TryIntoAvailableBlock<T>> IntoWrappedAvailabilityPendingBlock<T>
    for ExecutionPendingBlock<T, B>
{
    type Block = ExecutionPendingBlock<T, AvailabilityPendingBlock<T::EthSpec>>;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Self::Block, DataAvailabilityFailure<T::EthSpec>> {
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
        let availability_pending_block = block.into_availability_pending_block(
            block_root,
            chain,
            Vec::with_capacity(T::EthSpec::max_blobs_per_block()).into(),
        )?;
        Ok(ExecutionPendingBlock {
            block: availability_pending_block,
            block_root,
            state,
            parent_block,
            parent_eth1_finalization_data,
            confirmed_state_roots,
            consensus_context,
            payload_verification_handle,
        })
    }
}

impl<T: BeaconChainTypes> IntoWrappedAvailabilityPendingBlock<T>
    for ExecutedBlock<T, AvailabilityPendingBlock<T::EthSpec>>
{
    type Block = Self;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Self::Block, DataAvailabilityFailure<T::EthSpec>> {
        // Make a new data availability handle with the blobs returned by data availability
        // failure. May for example be useful if data availability times out.
        let available_block = self.block.try_into_available_block(chain);
        match available_block {
            Err(BlockError::DataAvailability(DataAvailabilityFailure::ExecutedBlock(
                _,
                blobs,
                e,
            ))) => {
                error!(
                    chain.log, "Data Availability Failed";
                    "block_root" => %block_root,
                    "error" => ?e
                );
                let availability_pending_block = <ExecutedBlock<
                    T,
                    AvailabilityPendingBlock<T::EthSpec>,
                > as AsSignedBlock<T>>::block_cloned(
                    &self
                )
                .into_availability_pending_block(block_root, chain, blobs)?;
                self.block = availability_pending_block;
                Ok(self)
            }
            Ok(_) | Err(_) => Ok(self), // other error variant, with block without payload verification metadata, won't occur
        }
    }
}

impl<T: BeaconChainTypes, B: TryIntoAvailableBlock<T>> IntoWrappedAvailabilityPendingBlock<T>
    for SignatureVerifiedBlock<T, B>
{
    type Block = SignatureVerifiedBlock<T, AvailabilityPendingBlock<T::EthSpec>>;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Self::Block, DataAvailabilityFailure<T::EthSpec>> {
        let SignatureVerifiedBlock {
            block,
            block_root,
            parent,
            consensus_context,
        } = self;
        let availability_pending_block = block.into_availability_pending_block(
            block_root,
            chain,
            Vec::with_capacity(T::EthSpec::max_blobs_per_block()).into(),
        )?;
        Ok(SignatureVerifiedBlock {
            block: availability_pending_block,
            block_root,
            parent,
            consensus_context,
        })
    }
}

impl<T: BeaconChainTypes, B: TryIntoAvailableBlock<T>> IntoWrappedAvailabilityPendingBlock<T>
    for GossipVerifiedBlock<T, B>
{
    type Block = GossipVerifiedBlock<T, AvailabilityPendingBlock<T::EthSpec>>;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Self::Block, DataAvailabilityFailure<T::EthSpec>> {
        let GossipVerifiedBlock {
            block,
            block_root,
            parent,
            consensus_context,
        } = self;
        let availability_pending_block = block.into_availability_pending_block(
            block_root,
            chain,
            Vec::with_capacity(T::EthSpec::max_blobs_per_block()).into(),
        )?;
        Ok(GossipVerifiedBlock {
            block: availability_pending_block,
            block_root,
            parent,
            consensus_context,
        })
    }
}

/// Reconstructs a block with metadata to update its inner block to an
/// [`AvailabilityPendingBlock`].
pub trait IntoWrappedAvailabilityPendingBlock<T: BeaconChainTypes>: AsSignedBlock<T> {
    type Block;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Self::Block, DataAvailabilityFailure<T::EthSpec>>;
}

#[derive(Debug)]
pub struct AvailabilityPendingBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    data_availability_handle: DataAvailabilityHandle<E>,
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

/// A wrapper over only a [`SignedBeaconBlock`] or with all its kzg-verified
/// [`SignedBlobSidecar<E>`]s.
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
        Option<VariableList<Arc<SignedBlobSidecar<E>>, E::MaxBlobsPerBlock>>,
    ) {
        match self.0 {
            AvailableBlockInner::Block(block) => (block, None),
            AvailableBlockInner::BlockAndBlobs(block, blobs) => (block, Some(blobs)),
        }
    }
}

impl<T: BeaconChainTypes> TryIntoAvailableBlock<T> for AvailableBlock<T::EthSpec> {
    fn try_into_available_block(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<AvailableBlock<T::EthSpec>, BlockError<T::EthSpec>> {
        Ok(self.clone())
    }
    fn into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
        blobs: VariableList<
            Arc<SignedBlobSidecar<T::EthSpec>>,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxBlobsPerBlock,
        >,
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, DataAvailabilityFailure<T::EthSpec>> {
        let block =
            <AvailableBlock<<T as BeaconChainTypes>::EthSpec> as AsSignedBlock<T>>::block_cloned(
                &self,
            );
        let data_availability_handle = chain.task_executor.spawn_handle_mock(Ok(self)).ok_or(
            DataAvailabilityFailure::Block(
                Some(block),
                VariableList::empty(),
                BlobError::TaskExecutor,
            ),
        )?;
        Ok(AvailabilityPendingBlock {
            block,
            data_availability_handle,
        })
    }
}

impl<T: BeaconChainTypes> TryIntoAvailableBlock<T> for AvailabilityPendingBlock<T::EthSpec> {
    fn try_into_available_block(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<AvailableBlock<T::EthSpec>, BlockError<T::EthSpec>> {
        let _cx: &mut Context<'_>;
        let data_availability_handle = self.data_availability_handle; // if this panics it is due to a bad impl of the trait AvailabilityPending
        tokio::pin!(data_availability_handle);
        match data_availability_handle.poll(_cx) {
            Poll::Pending => Err(BlockError::BlobValidation(BlobError::PendingAvailability)),
            Poll::Ready(Ok(Some(Ok(available_block)))) => Ok(available_block),
            Poll::Ready(Err(_)) | Poll::Ready(Ok(None)) => Err(BlockError::DataAvailability(
                DataAvailabilityFailure::Block(
                    None,
                    VariableList::empty(),
                    BlobError::TaskExecutor,
                ),
            )),
            Poll::Ready(Ok(Some(Err(DataAvailabilityFailure::Block(block, blobs, e))))) => {
                let channels = chain.pending_blocks_tx_rx.write();
                let block_root =
                    match block {
                        Some(block) => <Arc<
                            SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>,
                        > as AsSignedBlock<T>>::block_root(
                            &block
                        ),
                        None => match blobs.get(0) {
                            Some(blob) => blob.beacon_block_root(),
                            None => {
                                return Err(BlockError::DataAvailability(
                                    DataAvailabilityFailure::Block(block, blobs, e),
                                ))
                            }
                        },
                    };
                match channels.remove(&block_root) {
                    Some((_, Some(rx))) => {
                        loop {
                            match rx.try_next() {
                                Ok(Some((blob, _))) => {
                                    blobs.push(blob); // rescue any blobs that may have been sent on the channel.
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    error!(
                                        chain.log, "Error while adding blobs to Data Availability Failure";
                                        "block_root" => %block_root,
                                        "error" => %e
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    None | Some((_, None)) => {}
                }
                drop(channels);
                Err(BlockError::DataAvailability(
                    DataAvailabilityFailure::Block(block, blobs, e),
                ))
            }
            Poll::Ready(Ok(Some(Err(DataAvailabilityFailure::ExecutedBlock(block, blobs, e))))) => {
                let channels = chain.pending_blocks_tx_rx.write();
                let block_root = <ExecutedBlockInError<<T as BeaconChainTypes>::EthSpec> as AsSignedBlock<T>>::block_root(&block);
                match channels.remove(&block_root) {
                    Some((_, Some(rx))) => {
                        loop {
                            match rx.try_next() {
                                Ok(Some((blob, _))) => {
                                    blobs.push(blob); // rescue any blobs that may have been sent on the channel.
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    error!(
                                        chain.log, "Error while adding blobs to Data Availability Failure";
                                        "block_root" => %block_root,
                                        "error" => %e
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    None | Some((_, None)) => {}
                }
                drop(channels);
                Err(BlockError::DataAvailability(
                    DataAvailabilityFailure::ExecutedBlock(block, blobs, e),
                ))
            }
        }
    }

    fn into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
        blobs: VariableList<
            Arc<SignedBlobSidecar<T::EthSpec>>,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxBlobsPerBlock,
        >,
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, DataAvailabilityFailure<T::EthSpec>> {
        Ok(self)
    }
}

impl<T: BeaconChainTypes> TryIntoAvailableBlock<T> for Arc<SignedBeaconBlock<T::EthSpec>> {}

/// The default implementation of this trait is coded for an
/// [`Arc<SignedBeaconBlock<T::EthSpec>>`].
pub trait TryIntoAvailableBlock<T: BeaconChainTypes>:
    AsSignedBlock<T> + Sized + AsSignedBlock<T> + Send + Sync + Debug
{
    fn try_into_available_block(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<AvailableBlock<T::EthSpec>, BlockError<T::EthSpec>> {
        TryIntoAvailableBlock::into_availability_pending_block(
            self.block_cloned(),
            self.block_root(),
            chain,
            VariableList::empty(),
        )?
        .try_into_available_block(chain)
    }

    /// Consumes a block and wraps it in an [`AvailabilityPendingBlock`] with a
    /// [`DataAvailabilityHandle`] to receive blobs on from the network and kzg-verify them.
    /// Calling `try_into` on an [`AvailabilityPendingBlock`] returns an [`AvailableBlock`] on
    /// success, and on failure returns the parts that have been gathered so far returned wrapped
    /// in a [`DataAvailabilityFailure::Block`] error variant.
    fn into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
        blobs: VariableList<
            Arc<SignedBlobSidecar<T::EthSpec>>,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxBlobsPerBlock,
        >, // allow for restarting with blobs obtained in error.
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, DataAvailabilityFailure<T::EthSpec>> {
        let block = self.block_cloned();
        let Some(data_availability_boundary) = chain.data_availability_boundary() else {
            let data_availability_handle = chain.task_executor.spawn_handle_mock(Ok(AvailableBlock(AvailableBlockInner::Block(block)))).ok_or(DataAvailabilityFailure::Block(Some(block), VariableList::empty(), BlobError::TaskExecutor))?;

                return Ok(AvailabilityPendingBlock {
                    block,
                    data_availability_handle,
                })
            };
        let data_availability_handle = if self.slot().epoch(T::EthSpec::slots_per_epoch())
            >= data_availability_boundary
        {
            let kzg_commitments = self.message().body().blob_kzg_commitments().map_err(|e| {
                DataAvailabilityFailure::Block(Some(block), blobs, BlobError::KzgCommitmentMissing)
            })?;
            if kzg_commitments.is_empty() {
                // check that txns match with empty kzg-commitments
                verify_blobs::<T::EthSpec>(
                    <Arc<SignedBeaconBlock<T::EthSpec>> as AsSignedBlock<T>>::as_block(&block),
                    VariableList::empty(),
                    chain.kzg,
                )
                .map_err(|e| {
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
                let time_out = tokio::time::sleep(DEFAULT_DATA_AVAILABILITY_TIMEOUT);
                let channels = chain.pending_blocks_tx_rx.write();
                // Remove the blocks blob receiver and put back sender.
                let (tx, rx) = match channels.remove(&block_root) {
                    Some((tx, Some(rx))) => (tx, rx),
                    None => mpsc::channel::<(
                        Arc<SignedBlobSidecar<T::EthSpec>>,
                        Option<oneshot::Sender<Result<(), BlobError<T::EthSpec>>>>,
                    )>(T::EthSpec::max_blobs_per_block()),
                };
                channels.insert(block_root, (tx, None));
                drop(channels);

                chain.task_executor
                    .spawn_handle(
                        async move {
                        tokio::pin!(time_out);
                        tokio::pin!(rx);
                        loop {
                            tokio::select!{
                                blob_received = rx.next() => {
                                    match blob_received {
                                        Some((blob, notify_success_tx)) => {
                                            if let Some(tx) = notify_success_tx {
                                                // index filtering hasn't already occured for 
                                                // blob
                                                let res = if blobs.iter().find(|existing_blob|
                                                    existing_blob.blob_index() == blob.blob_index()).is_some()
                                                {
                                                    Err(
                                                        BlobError::BlobAlreadyExistsAtIndex(
                                                            blob
                                                        ),
                                                    )
                                                } else {
                                                    Ok(())
                                                };
                                                tx.send(res).map_err(|_| {
                                                    DataAvailabilityFailure::Block(
                                                        Some(block),
                                                        blobs,
                                                        BlobError::SendOneshot(block_root),
                                                    )}
                                                )?;
                                            }
                                            blobs.push(blob);
                                            if blobs.len() == kzg_commitments.len() {
                                                break;
                                            }
                                        }
                                        Some((blob, None)) => {
                                            // blob has already been filtered on index before 
                                            // block arrived
                                            blobs.push(blob);
                                            if blobs.len() == kzg_commitments.len() {
                                                break;
                                            }
                                        }
                                        None => {
                                            break;
                                        }
                                    }
                                }
                                _ = time_out => {
                                    return Err(DataAvailabilityFailure::Block(
                                        Some(block),
                                        blobs,
                                        BlobError::TimedOut(DEFAULT_DATA_AVAILABILITY_TIMEOUT),
                                    ))
                                }
                            }
                        }

                        let kzg_handle = chain.task_executor.spawn_blocking_handle(
                            move || {
                                verify_blobs::<T::EthSpec>(<Arc<SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>> as AsSignedBlock<T>>::as_block(&block), blobs, chain.kzg).map_err(|e| {
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
                                }
                            )?;
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

/// The maximum time an [`AvailabilityPendingBlock`] is cached in seconds.
pub const AVAILABILITY_PENDING_CACHE_ITEM_TIMEOUT: u64 = 5;

// todo(emhane): temp fix to avoid rewriting beacon chain test harnesss due to propagation of
// generic BeaconChainTypes via BlockError
struct ExecutedBlockInError<E: EthSpec> {
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<E>>,
    state: BeaconState<E>, // todo(emhane): is this send + sync?
    confirmed_state_roots: Vec<Hash256>,
    payload_verification_status: PayloadVerificationStatus,
    count_unrealized: CountUnrealized,
    parent_block: Arc<SignedBeaconBlock<E>>,
    parent_eth1_finalization_data: Eth1FinalizationData,
    consensus_context: ConsensusContext<E>,
}

/// A block that has passed payload verification and is waiting for its blobs via the handle on
/// [`AvailabilityPendingBlock`].
#[derive(Debug)]
pub struct ExecutedBlock<T: BeaconChainTypes, B: TryIntoAvailableBlock<T>> {
    block_root: Hash256,
    block: B,
    state: BeaconState<T::EthSpec>, // todo(emhane): is this send + sync?
    confirmed_state_roots: Vec<Hash256>,
    payload_verification_status: PayloadVerificationStatus,
    count_unrealized: CountUnrealized,
    parent_block: Arc<SignedBeaconBlock<T::EthSpec>>,
    parent_eth1_finalization_data: Eth1FinalizationData,
    consensus_context: ConsensusContext<T::EthSpec>,
}

impl<T: BeaconChainTypes> Future for ExecutedBlock<T, AvailabilityPendingBlock<T::EthSpec>> {
    type Output =
        Result<ExecutedBlock<T, AvailableBlock<T::EthSpec>>, DataAvailabilityFailure<T::EthSpec>>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let data_availability_handle = self.block.data_availability_handle;
        tokio::pin!(data_availability_handle);
        match (&mut data_availability_handle).poll(_cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(Ok(available_block)))) => Poll::Ready(Ok(ExecutedBlock {
                block_root: self.block_root,
                block: available_block,
                state: self.state,
                confirmed_state_roots: self.confirmed_state_roots,
                payload_verification_status: self.payload_verification_status,
                count_unrealized: self.count_unrealized,
                parent_block: self.parent_block,
                parent_eth1_finalization_data: self.parent_eth1_finalization_data,
                consensus_context: self.consensus_context,
            })),
            Poll::Ready(Ok(Some(Err(DataAvailabilityFailure::Block(Some(block), blobs, e))))) => {
                Poll::Ready(Err(DataAvailabilityFailure::ExecutedBlock(
                    ExecutedBlockInError {
                        block_root: self.block_root,
                        block,
                        state: self.state,
                        confirmed_state_roots: self.confirmed_state_roots,
                        payload_verification_status: self.payload_verification_status,
                        count_unrealized: self.count_unrealized,
                        parent_block: self.parent_block,
                        parent_eth1_finalization_data: self.parent_eth1_finalization_data,
                        consensus_context: self.consensus_context,
                    },
                    blobs,
                    e,
                )))
            }
            Poll::Ready(Err(_))
            | Poll::Ready(Ok(None))
            | Poll::Ready(Ok(Some(Err(_))))
            | Poll::Ready(Ok(Some(Err(DataAvailabilityFailure::Block(None, _, _))))) => {
                Poll::Ready(Err(DataAvailabilityFailure::Block(
                    None,
                    VariableList::empty(),
                    BlobError::TaskExecutor,
                )))
            }
        }
    }
}

pub trait AsSignedBlock<T: BeaconChainTypes> {
    fn block_root(&self) -> Hash256;
    fn slot(&self) -> Slot;
    fn epoch(&self) -> Epoch;
    fn parent_root(&self) -> Hash256;
    fn state_root(&self) -> Hash256;
    fn signed_block_header(&self) -> SignedBeaconBlockHeader;
    fn message(&self) -> BeaconBlockRef<<T as BeaconChainTypes>::EthSpec>;
    fn as_block(&self) -> &SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>;
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>>;
}

#[macro_export]
macro_rules! impl_as_signed_block {
    ($block: ty, $fn_name: ident, $return_type: ty, $(.$field: tt)*) => {
        fn $fn_name(&self) -> $return_type {
            <$block as AsSignedBlock<T>>::$fn_name(&self$(.$field)*)
        }
    };
    ($block: ty, $block_two: ty, $fn_name: ident, $return_type: ty, $(.$field: tt)*, $enum_variant_block: ident$(::$variant: ident)*, $enum_variant_block_and: ident$(::$variant_two: ident)* $(,$inner: tt)*) => {
        fn $fn_name(&self) -> $return_type {
            match self$(.$field)* {
                $enum_variant_block$(::$variant)+(block) => <$block as AsSignedBlock<T>>::$fn_name(&block),
                $enum_variant_block_and$(::$variant_two)+(block$(, $inner)*) => <$block_two as AsSignedBlock<T>>::$fn_name(&block),
            }
        }
    };
    ($block: ty, $type: ty, $(.$field: tt)* $(,$generic: ident: $trait: ident$(<$($generics: ident,)+>)*$(+ $traits: ident$(<$($generics_nested: ident,)+>)*)*)*) => {
        impl<T: BeaconChainTypes $(,$generic: $trait$(<$($generics,)+>)*$(+ $traits$(<$($generics_nested,)+>)*)*)*> AsSignedBlock<T> for $type {
            impl_as_signed_block!($block, block_root, Hash256, $(.$field)*);
            impl_as_signed_block!($block, slot, Slot, $(.$field)*);
            impl_as_signed_block!($block, epoch, Epoch, $(.$field)*);
            impl_as_signed_block!($block, parent_root, Hash256, $(.$field)*);
            impl_as_signed_block!($block, state_root, Hash256, $(.$field)*);
            impl_as_signed_block!($block, signed_block_header, SignedBeaconBlockHeader, $(.$field)*);
            impl_as_signed_block!($block, message, BeaconBlockRef<<T as BeaconChainTypes>::EthSpec>, $(.$field)*);
            impl_as_signed_block!($block, as_block, &SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>, $(.$field)*);
            impl_as_signed_block!($block, block_cloned, Arc<SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>>, $(.$field)*);
        }
    };
    ($block: ty, $block_two: ty, $type: ty, $(.$field: tt)*, $enum_variant_block: ident$(::$variant: ident)*, $enum_variant_block_and: ident$(::$variant_two: ident)* $(,$inner: tt)* $(,$generic: ident: $trait: ident$(<$($generics: ident,)+>)*$(+ $traits: ident$(<$($generics_nested: ident,)+>)*)*)*) => {
        impl<T: BeaconChainTypes $(,$generic: $trait$(<$($generics,)+>)*$(+ $traits$(<$($generics_nested,)+>)*)*)*> AsSignedBlock<T> for $type {
            impl_as_signed_block!($block, $block_two, block_root, Hash256, $(.$field)*, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+ $(, $inner)*);
            impl_as_signed_block!($block, $block_two, slot, Slot, $(.$field)*, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+ $(, $inner)*);
            impl_as_signed_block!($block, $block_two, epoch, Epoch, $(.$field)*, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+ $(, $inner)*);
            impl_as_signed_block!($block, $block_two, parent_root, Hash256, $(.$field)*, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+ $(, $inner)*);
            impl_as_signed_block!($block, $block_two, state_root, Hash256, $(.$field)*, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+ $(, $inner)*);
            impl_as_signed_block!($block, $block_two, signed_block_header, SignedBeaconBlockHeader, $(.$field)*, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+ $(, $inner)*);
            impl_as_signed_block!($block, $block_two, message, BeaconBlockRef<<T as BeaconChainTypes>::EthSpec>, $(.$field)*, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+ $(, $inner)*);
            impl_as_signed_block!($block, $block_two, as_block, &SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>, $(.$field)*, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+ $(, $inner)*);
            impl_as_signed_block!($block, $block_two, block_cloned, Arc<SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>>, $(.$field)*, $enum_variant_block$(::$variant)+, $enum_variant_block_and$(::$variant_two)+ $(, $inner)*);
        }
    };
}

impl_as_signed_block!(B, ExecutionPendingBlock<T, B>, .block, B: TryIntoAvailableBlock<T,>);
impl_as_signed_block!(B, GossipVerifiedBlock<T, B>, .block, B: TryIntoAvailableBlock<T,>);
impl_as_signed_block!(B, ExecutedBlock<T, B>, .block, B: TryIntoAvailableBlock<T,>);
impl_as_signed_block!(Arc<SignedBeaconBlock<T::EthSpec>>, AvailabilityPendingBlock<T::EthSpec>, .block);
impl_as_signed_block!(Arc<SignedBeaconBlock<T::EthSpec>>, ExecutedBlockInError<T::EthSpec>, .block);
impl_as_signed_block!(
    Arc<SignedBeaconBlock<T::EthSpec>>,
    &Arc<SignedBeaconBlock<T::EthSpec>>,
);
impl_as_signed_block!(Arc<SignedBeaconBlock<T::EthSpec>>, Arc<SignedBeaconBlock<T::EthSpec>>, AvailableBlock<T::EthSpec>, .0, AvailableBlockInner::Block, AvailableBlockInner::BlockAndBlobs, _);

impl<T: BeaconChainTypes> AsSignedBlock<T> for Arc<SignedBeaconBlock<T::EthSpec>> {
    impl_as_signed_block!(Self, block_root, Hash256,);
    impl_as_signed_block!(Self, slot, Slot,);
    impl_as_signed_block!(Self, epoch, Epoch,);
    impl_as_signed_block!(Self, parent_root, Hash256,);
    impl_as_signed_block!(Self, state_root, Hash256,);
    impl_as_signed_block!(Self, signed_block_header, SignedBeaconBlockHeader,);
    impl_as_signed_block!(
        Self,
        message,
        BeaconBlockRef<<T as BeaconChainTypes>::EthSpec>,
    );
    fn as_block(&self) -> &SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec> {
        &*self
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>> {
        self.clone()
    }
}
