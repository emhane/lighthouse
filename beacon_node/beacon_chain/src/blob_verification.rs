use crate::beacon_chain::{BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use crate::block_verification::{BlockError, IntoExecutionPendingBlock};
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
    FutureExt, StreamExt,
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
use types::{BeaconState, Blob, Epoch, ExecPayload, KzgProof, SignedBlindedBeaconBlock};

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
    PendingAvailability(AvailabilityPendingBlock<T>),
    /// Blobs provided for a pre-Eip4844 fork.
    InconsistentFork,
    /// A blob for this index has already been seen.
    BlobAlreadyExistsAtIndex(Arc<SignedBlobSidecar<T>>),
    /// Error notifying sender of blob with oneshot sender. Contains block hash that blob points
    /// to.
    SendOneshot(Hash256),
    /// Error using oneshot receiver to get green light from blob receiver.
    RecvOneshot(Canceled),
    /// Awaiting data availability timed out.
    TimedOut(Duration),
    /// Receiving a blob failed.
    RecvBlob(TryRecvError),
    /// Sending a blob failed.
    SendBlob(TrySendError<Arc<SignedBlobSidecar<T>>>),
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
    /// Verifying data availability of a block which already has a verified execution payload
    /// failed. The error contains the block and blobs that have been received.
    ExecutedBlock(
        ExecutedBlockInError<E>,
        VariableList<Arc<SignedBlobSidecar<E>>, E::MaxBlobsPerBlock>,
        BlobError<E>,
    ),
}

#[macro_export]
macro_rules! impl_from {
    ($(<$($generic: ident : $trait: ident$(<$($generic_two: ident,)+>)*,)+>)*, $from_type: ty, $to_type: ty, $to_type_variant: path) => {
        impl$(<$($generic: $trait$(<$($generic_two,)+>)*,)+>)* From<$from_type> for $to_type {
            fn from(e: $from_type) -> Self {
                $to_type_variant(e)
            }
        }
    };
}

impl_from!(<T: EthSpec,>, kzg::Error, BlobError<T>, Self::KzgError);
impl_from!(<T: EthSpec,>, BeaconChainError, BlobError<T>, Self::BeaconChainError);
impl_from!(<T: EthSpec,>, Arc<SignedBlobSidecar<T>>, BlobError<T>, Self::BlobAlreadyExistsAtIndex);
impl_from!(<T: EthSpec,>, Canceled, BlobError<T>, Self::RecvOneshot);
impl_from!(<T: EthSpec,>, TryRecvError, BlobError<T>, Self::RecvBlob);
impl_from!(<T: EthSpec,>, TrySendError<Arc<SignedBlobSidecar<T>>>, BlobError<T>, Self::SendBlob);

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

impl_from!(<T: EthSpec,>, Arc<SignedBlobSidecar<T>>, GossipVerifiedBlob<T>, GossipVerifiedBlob);

pub fn validate_blob_for_gossip<T: BeaconChainTypes, B: AsSignedBlock<T>>(
    block: B,
    block_root: Hash256,
    chain: &Arc<BeaconChain<T>>,
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
    kzg: &Option<Arc<Kzg>>,
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
    kzg: &Arc<Kzg>,
) -> Result<(), BlobError<T>> {
    if verify_kzg_commitments_against_transactions::<T>(transactions, kzg_commitments).is_err() {
        return Err(BlobError::TransactionCommitmentMismatch);
    }

    //todo(emhane)
    // Validatate that the kzg proof is valid against the commitments and blobs
    /* if !kzg_utils::validate_blob_sidecars(
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
    }*/
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

/// Used in crate::test_utils.
impl<T: BeaconChainTypes> IntoWrappedAvailabilityPendingBlock<T>
    for Arc<SignedBeaconBlock<T::EthSpec>>
{
    type Block = AvailabilityPendingBlock<T::EthSpec>;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &Arc<BeaconChain<T>>,
    ) -> Result<Self::Block, DataAvailabilityFailure<T::EthSpec>> {
        self.into_availability_pending_block(block_root, chain, VariableList::empty())
    }
}

/// Reconstructs a block with metadata to update its inner block to an
/// [`AvailabilityPendingBlock`].
pub trait IntoWrappedAvailabilityPendingBlock<T: BeaconChainTypes>: AsSignedBlock<T> {
    type Block: IntoExecutionPendingBlock<T, AvailabilityPendingBlock<T::EthSpec>>
        + AsSignedBlock<T>;
    fn wrap_into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &Arc<BeaconChain<T>>,
    ) -> Result<Self::Block, DataAvailabilityFailure<T::EthSpec>>;
}

#[derive(Debug)]
pub struct AvailabilityPendingBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    data_availability_handle: DataAvailabilityHandle<E>,
}

/// Used to await blobs from the network.
type DataAvailabilityHandle<E> =
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
        self,
        chain: &Arc<BeaconChain<T>>,
    ) -> Result<
        JoinHandle<Option<Result<AvailableBlock<T::EthSpec>, BlockError<T::EthSpec>>>>,
        BlockError<T::EthSpec>,
    > {
        match chain.task_executor.spawn_handle_mock(Ok(self)) {
            Some(data_availability_handle) => Ok(data_availability_handle),
            None => Err(BeaconChainError::RuntimeShutdown)?,
        }
    }
    fn into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &Arc<BeaconChain<T>>,
        blobs: VariableList<
            Arc<SignedBlobSidecar<T::EthSpec>>,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxBlobsPerBlock,
        >,
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, DataAvailabilityFailure<T::EthSpec>> {
        let block =
            <AvailableBlock<<T as BeaconChainTypes>::EthSpec> as AsSignedBlock<T>>::block_cloned(
                &self,
            );
        let data_availability_handle = match chain.task_executor.spawn_handle_mock(Ok(self)) {
            Some(handle) => handle,
            None => {
                return Err(DataAvailabilityFailure::Block(
                    Some(block),
                    VariableList::empty(),
                    BlobError::BeaconChainError(BeaconChainError::RuntimeShutdown),
                ))
            }
        };
        Ok(AvailabilityPendingBlock {
            block,
            data_availability_handle,
        })
    }
}

impl<T: BeaconChainTypes> TryIntoAvailableBlock<T> for AvailabilityPendingBlock<T::EthSpec> {
    fn try_into_available_block(
        self,
        chain: &Arc<BeaconChain<T>>,
    ) -> Result<
        JoinHandle<Option<Result<AvailableBlock<T::EthSpec>, BlockError<T::EthSpec>>>>,
        BlockError<T::EthSpec>,
    > {
        let finished = self.data_availability_handle.is_finished();
        if finished {
            return Err(BlockError::BlobValidation(BlobError::PendingAvailability(
                self,
            )));
        }
        let block_root = <AvailabilityPendingBlock<<T as BeaconChainTypes>::EthSpec> as AsSignedBlock<T>>::block_root(&self);
        let chain_cloned = chain.clone();
        let availability_result_handle = chain.task_executor.spawn_handle(async move {
            match self.data_availability_handle.await {
                Ok(Some(Ok(available_block))) => Ok(available_block),
                Err(_) | Ok(None) => Err(
                    DataAvailabilityFailure::Block(
                        None,
                        VariableList::empty(),
                        BlobError::BeaconChainError(
                            BeaconChainError::RuntimeShutdown
                        ),
                    ),
                )?,
                Ok(Some(Err(DataAvailabilityFailure::Block(block, mut blobs, e)))) => {
                    let mut channels = chain_cloned.pending_blocks_tx_rx.write();
                    let block_root =
                        match block {
                            Some(ref block) => <Arc<
                                SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>,
                            > as AsSignedBlock<T>>::block_root(
                                &block
                            ),
                            None => match blobs.get(0) {
                                Some(blob) => blob.beacon_block_root(),
                                None => {
                                    return Err(BlockError::DataAvailability(DataAvailabilityFailure::Block(block, blobs, e)))
                                }
                            },
                        };
                    match channels.remove(&block_root) {
                        Some((_, Some(mut rx))) => {
                            loop {
                                match rx.try_next() {
                                    Ok(Some((blob, _))) => {
                                        blobs.push(blob); // rescue any blobs that may have been sent on the channel.
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        error!(
                                            chain_cloned.log, "Error while adding blobs to Data Availability Failure";
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
                    Err(DataAvailabilityFailure::Block(block, blobs, e))?
                }
                Ok(Some(Err(DataAvailabilityFailure::ExecutedBlock(block, mut blobs, e)))) => {
                    let mut channels = chain_cloned.pending_blocks_tx_rx.write();
                    let block_root = <ExecutedBlockInError<<T as BeaconChainTypes>::EthSpec> as AsSignedBlock<T>>::block_root(&block);
                    match channels.remove(&block_root) {
                        Some((_, Some(mut rx))) => {
                            loop {
                                match rx.try_next() {
                                    Ok(Some((blob, _))) => {
                                        blobs.push(blob); // rescue any blobs that may have been sent on the channel.
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        error!(
                                            chain_cloned.log, "Error while adding blobs to Data Availability Failure";
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
                    Err(DataAvailabilityFailure::ExecutedBlock(block, blobs, e))?
                }
            }
        }, "try_into_available_block");
        match availability_result_handle {
            Some(handle) => Ok(handle),
            None => Err(BeaconChainError::RuntimeShutdown)?,
        }
    }

    fn into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &Arc<BeaconChain<T>>,
        blobs: VariableList<
            Arc<SignedBlobSidecar<T::EthSpec>>,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxBlobsPerBlock,
        >,
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, DataAvailabilityFailure<T::EthSpec>> {
        Ok(self)
    }
}

// todo(emhane): why is load_parent check done before block is verified as ready for import to
// fork choice?
#[derive(Debug)]
pub enum SomeAvailabilityBlock<T: EthSpec> {
    Available(AvailableBlock<T>),
    AvailabilityPending(AvailabilityPendingBlock<T>),
    RawBlock(Arc<SignedBeaconBlock<T>>),
}

impl_from!(<T: EthSpec,>, AvailableBlock<T>, SomeAvailabilityBlock<T>, Self::Available);
impl_from!(<T: EthSpec,>, AvailabilityPendingBlock<T>, SomeAvailabilityBlock<T>, Self::AvailabilityPending);
impl_from!(<T: EthSpec,>, Arc<SignedBeaconBlock<T>>, SomeAvailabilityBlock<T>, Self::RawBlock);

impl<T: BeaconChainTypes> TryIntoAvailableBlock<T> for SomeAvailabilityBlock<T::EthSpec> {
    fn try_into_available_block(
        self,
        chain: &Arc<BeaconChain<T>>,
    ) -> Result<
        JoinHandle<Option<Result<AvailableBlock<T::EthSpec>, BlockError<T::EthSpec>>>>,
        BlockError<T::EthSpec>,
    > {
        match self {
            Self::Available(available_block) => available_block.try_into_available_block(chain),
            Self::AvailabilityPending(availability_pending_block) => {
                availability_pending_block.try_into_available_block(chain)
            }
            Self::RawBlock(block) => block.try_into_available_block(chain),
        }
    }
    fn into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &Arc<BeaconChain<T>>,
        mut blobs: VariableList<
            Arc<SignedBlobSidecar<T::EthSpec>>,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxBlobsPerBlock,
        >,
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, DataAvailabilityFailure<T::EthSpec>> {
        match self {
            Self::Available(available_block) => {
                available_block.into_availability_pending_block(block_root, chain, blobs)
            }
            Self::AvailabilityPending(availability_pending_block) => {
                availability_pending_block.into_availability_pending_block(block_root, chain, blobs)
            }
            Self::RawBlock(block) => {
                block.into_availability_pending_block(block_root, chain, blobs)
            }
        }
    }
}

impl<T: BeaconChainTypes> TryIntoAvailableBlock<T> for Arc<SignedBeaconBlock<T::EthSpec>> {}

/// The default implementation of this trait is coded for an
/// [`Arc<SignedBeaconBlock<T::EthSpec>>`]. This trait is not safe to implement on any types
/// wrapping metadata along with a block implementing this trait, for that use the trait
/// [`IntoWrappedAvailabilityPendingBlock`] as otherwise the metadata will be lost.
pub trait TryIntoAvailableBlock<T: BeaconChainTypes>:
    AsSignedBlock<T>
    + Sized
    + AsSignedBlock<T>
    + Send
    + Sync
    + Debug
    + Into<SomeAvailabilityBlock<T::EthSpec>>
{
    /// Use with caution. Block in [`BlobError::PendingAvailability`] error
    /// variant must be used since arriving blobs will use its channel. Consumes self and returns
    /// an [`AvailableBlock`] on success or an [`AvailabilityPendingBlock`] wrapped in the
    /// [`BlobError::PendingAvailability`] error variant. On errror the parts that have been
    /// gathered so far by the`data_availability_handle` are returned wrapped in the
    /// [`DataAvailabilityFailure::Block`] error variant. Block must be available before importing
    /// to fork choice, but musn't before.
    fn try_into_available_block(
        self,
        chain: &Arc<BeaconChain<T>>,
    ) -> Result<
        JoinHandle<Option<Result<AvailableBlock<T::EthSpec>, BlockError<T::EthSpec>>>>,
        BlockError<T::EthSpec>,
    > {
        let block_root = self.block_root();
        Err(BlobError::PendingAvailability(
            self.into_availability_pending_block(block_root, chain, VariableList::empty())?,
        ))?
    }

    /// Consumes selfs and wraps the block in an [`AvailabilityPendingBlock`] with a
    /// [`DataAvailabilityHandle`] to receive blobs on from the network and kzg-verify them.
    /// Use the blobs param to start the `data_availability_handle` again with any blobs returned
    /// in the previous error, for example after time out waiting for blobs from gossip and this
    /// time tell an rpc worker to send the missing blobs on the handle's blob channel.
    fn into_availability_pending_block(
        self,
        block_root: Hash256,
        chain: &Arc<BeaconChain<T>>,
        mut blobs: VariableList<
            Arc<SignedBlobSidecar<T::EthSpec>>,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxBlobsPerBlock,
        >,
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, DataAvailabilityFailure<T::EthSpec>> {
        let block = self.block_cloned();
        let Some(data_availability_boundary) = chain.data_availability_boundary() else {
            match chain.task_executor.spawn_handle_mock(Ok(AvailableBlock(AvailableBlockInner::Block(block.clone())))) {
                Some(data_availability_handle) => return Ok(AvailabilityPendingBlock {
                    block,
                    data_availability_handle,
                }),
                None => return Err(DataAvailabilityFailure::Block(Some(block), VariableList::empty(), BlobError::BeaconChainError(BeaconChainError::RuntimeShutdown
                )))
            }
        };
        let data_availability_handle = if self.slot().epoch(T::EthSpec::slots_per_epoch())
            >= data_availability_boundary
        {
            let kzg_commitments_len = self
                .message()
                .body()
                .blob_kzg_commitments()
                .map_err(|_| {
                    DataAvailabilityFailure::Block(
                        Some(block.clone()),
                        blobs.clone(),
                        BlobError::KzgCommitmentMissing,
                    )
                })?
                .len();
            if kzg_commitments_len == 0 {
                // check that txns match with empty kzg-commitments
                if let Err(e) =
                    verify_blobs::<T::EthSpec>(self.as_block(), VariableList::empty(), &chain.kzg)
                {
                    return Err(DataAvailabilityFailure::Block(
                        Some(block),
                        VariableList::empty(),
                        e,
                    ));
                }
                return Ok(AvailabilityPendingBlock {
                    block: block.clone(),
                    data_availability_handle: chain
                        .task_executor
                        .spawn_handle_mock(Ok(AvailableBlock(AvailableBlockInner::Block(
                            block.clone(),
                        ))))
                        .ok_or(DataAvailabilityFailure::Block(
                            Some(block),
                            VariableList::empty(),
                            BlobError::BeaconChainError(BeaconChainError::RuntimeShutdown),
                        ))?,
                });
            } else {
                let time_out = tokio::time::sleep(DEFAULT_DATA_AVAILABILITY_TIMEOUT);
                let mut channels = chain.pending_blocks_tx_rx.write();
                // Remove the blocks blob receiver and put back sender.
                let (tx, rx) = match channels.remove(&block_root) {
                    Some((tx, Some(rx))) => (tx, rx),
                    None => mpsc::channel::<(
                        Arc<SignedBlobSidecar<T::EthSpec>>,
                        Option<oneshot::Sender<Result<(), BlobError<T::EthSpec>>>>,
                    )>(T::EthSpec::max_blobs_per_block()),
                    Some((_, None)) => panic!(), // receiver has been picked up already this should not happen with RwLock, on failure entry is deleted in `try_into_available_block`
                };
                channels.insert(block_root, (tx, None));
                drop(channels);
                let chain_cloned = chain.clone();
                let data_availability_handle = chain.clone().task_executor
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
                                                    let e = Err(
                                                        BlobError::BlobAlreadyExistsAtIndex(
                                                            blob.clone()
                                                        ),
                                                    );
                                                    error!(
                                                        chain_cloned.log,
                                                        "Received duplicate for a blob index";
                                                        "beacon_block_root" => %blob.beacon_block_root(),
                                                        "error" => ?e,
                                                    );
                                                    e
                                                } else {
                                                    Ok(())
                                                };
                                                if tx.send(res).is_err() {
                                                    return Err(DataAvailabilityFailure::Block(
                                                        Some(block.clone()),
                                                        blobs,
                                                        BlobError::SendOneshot(block_root),
                                                    ))
                                                }
                                            }
                                            blobs.push(blob);
                                            if blobs.len() == kzg_commitments_len {
                                                break;
                                            }
                                        }
                                        None => {
                                            break;
                                        }
                                    }
                                }
                                _ = &mut time_out => {
                                    return Err(DataAvailabilityFailure::Block(
                                        Some(block),
                                        blobs,
                                        BlobError::TimedOut(DEFAULT_DATA_AVAILABILITY_TIMEOUT),
                                    ))
                                }
                            }
                        }
                        let kzg = chain_cloned.kzg.clone();
                        let block_cloned = block.clone();
                        let blobs_cloned = blobs.clone();
                        let kzg_handle = chain_cloned.task_executor.spawn_blocking_handle(
                            move || {
                                verify_blobs::<T::EthSpec>(&*block_cloned, blobs_cloned, &kzg)
                            },
                            "kzg_verification",
                        );
                        match kzg_handle {
                            Some(handle) => {
                                match handle.await {
                                    Ok(res) => {
                                        if let Err(e) = res {
                                            return Err(DataAvailabilityFailure::Block(
                                                Some(block),
                                                blobs,
                                                e,
                                            ))
                                        }
                                    }
                                    Err(_) => return Err(DataAvailabilityFailure::Block(
                                        Some(block),
                                        blobs,
                                        BlobError::BeaconChainError(BeaconChainError::RuntimeShutdown),
                                    ))
                                }
                            }
                            None => return Err(DataAvailabilityFailure::Block(
                                Some(block),
                                blobs,
                                BlobError::BeaconChainError(BeaconChainError::RuntimeShutdown),
                            ))
                        }
                        Ok(AvailableBlock(AvailableBlockInner::BlockAndBlobs(
                            block, blobs,
                        )))
                    },
                    "availability_pending_block"
                );

                match data_availability_handle {
                    Some(data_availability_handle) => data_availability_handle,
                    None => {
                        return Err(DataAvailabilityFailure::Block(
                            Some(self.block_cloned()),
                            VariableList::empty(),
                            BlobError::BeaconChainError(BeaconChainError::RuntimeShutdown),
                        ))
                    }
                }
            }
        } else {
            let data_availability_handle = chain
                .task_executor
                .spawn_handle_mock(Ok(AvailableBlock(AvailableBlockInner::Block(block))));
            match data_availability_handle {
                Some(data_availability_handle) => data_availability_handle,
                None => {
                    return Err(DataAvailabilityFailure::Block(
                        None,
                        VariableList::empty(),
                        BlobError::BeaconChainError(BeaconChainError::RuntimeShutdown),
                    ))
                }
            }
        };
        Ok(AvailabilityPendingBlock {
            block: self.block_cloned(),
            data_availability_handle,
        })
    }
}

/// The maximum time an [`AvailabilityPendingBlock`] is cached in seconds.
pub const AVAILABILITY_PENDING_CACHE_ITEM_TIMEOUT: u64 = 5;

// todo(emhane): temp fix to avoid rewriting beacon chain test harnesss due to propagation of
// generic BeaconChainTypes via BlockError
#[derive(Debug)]
pub struct ExecutedBlockInError<E: EthSpec> {
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<E>>,
    state: BeaconState<E>, // todo(emhane): is this send + sync?
    confirmed_state_roots: Vec<Hash256>,
    payload_verification_status: PayloadVerificationStatus,
    count_unrealized: CountUnrealized,
    parent_block: Arc<SignedBlindedBeaconBlock<E>>,
    parent_eth1_finalization_data: Eth1FinalizationData,
    consensus_context: ConsensusContext<E>,
}

/// A block that has passed payload verification and is waiting for its blobs via the handle on
/// [`AvailabilityPendingBlock`].
#[derive(Debug)]
pub struct ExecutedBlock<T: BeaconChainTypes, B: TryIntoAvailableBlock<T>> {
    pub block_root: Hash256,
    pub block: B,
    pub state: BeaconState<T::EthSpec>,
    pub confirmed_state_roots: Vec<Hash256>,
    pub payload_verification_status: PayloadVerificationStatus,
    pub count_unrealized: CountUnrealized,
    pub parent_block: Arc<SignedBlindedBeaconBlock<T::EthSpec>>,
    pub parent_eth1_finalization_data: Eth1FinalizationData,
    pub consensus_context: ConsensusContext<T::EthSpec>,
}

pub struct AvailabilityPendingExecutedBlock<T: BeaconChainTypes>(
    Box<ExecutedBlock<T, AvailabilityPendingBlock<T::EthSpec>>>,
);

impl_from!(<T: BeaconChainTypes,>, Box<ExecutedBlock<T, AvailabilityPendingBlock<T::EthSpec>>>, AvailabilityPendingExecutedBlock<T>, AvailabilityPendingExecutedBlock);

impl<T: BeaconChainTypes> Future for AvailabilityPendingExecutedBlock<T> {
    type Output =
        Result<ExecutedBlock<T, AvailableBlock<T::EthSpec>>, DataAvailabilityFailure<T::EthSpec>>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let block = &mut self.0;
        let poll = block.block.data_availability_handle.poll_unpin(cx);
        match poll {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(Ok(available_block)))) => Poll::Ready(Ok(ExecutedBlock {
                block_root: block.block_root,
                block: available_block,
                state: block.state.clone(),
                confirmed_state_roots: block.confirmed_state_roots.clone(),
                payload_verification_status: block.payload_verification_status,
                count_unrealized: block.count_unrealized,
                parent_block: block.parent_block.clone(),
                parent_eth1_finalization_data: block.parent_eth1_finalization_data.clone(),
                consensus_context: block.consensus_context.clone(),
            })),
            Poll::Ready(Ok(Some(Err(DataAvailabilityFailure::Block(
                Some(availability_pending_block),
                blobs,
                e,
            ))))) => Poll::Ready(Err(DataAvailabilityFailure::ExecutedBlock(
                ExecutedBlockInError {
                    block_root: block.block_root,
                    block: availability_pending_block,
                    state: block.state.clone(),
                    confirmed_state_roots: block.confirmed_state_roots.clone(),
                    payload_verification_status: block.payload_verification_status,
                    count_unrealized: block.count_unrealized,
                    parent_block: block.parent_block.clone(),
                    parent_eth1_finalization_data: block.parent_eth1_finalization_data.clone(),
                    consensus_context: block.consensus_context.clone(),
                },
                blobs,
                e,
            ))),
            Poll::Ready(Err(_)) | Poll::Ready(Ok(None)) | Poll::Ready(Ok(Some(Err(_)))) => {
                Poll::Ready(Err(DataAvailabilityFailure::Block(
                    None,
                    VariableList::empty(),
                    BlobError::BeaconChainError(BeaconChainError::RuntimeShutdown),
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
                $enum_variant_block$(::$variant)+(ref block) => <$block as AsSignedBlock<T>>::$fn_name(block),
                $enum_variant_block_and$(::$variant_two)+(ref block$(, $inner)*) => <$block_two as AsSignedBlock<T>>::$fn_name(block),
            }
        }
    };
    ($block: ty, $block_two: ty, $block_three: ty, $fn_name: ident, $return_type: ty, $(.$field: tt)*, $enum_variant: path, $enum_variant_two: path, $enum_variant_three: path) => {
        fn $fn_name(&self) -> $return_type {
            match self$(.$field)* {
                $enum_variant(ref block) => <$block as AsSignedBlock<T>>::$fn_name(block),
                $enum_variant_two(ref block) => <$block_two as AsSignedBlock<T>>::$fn_name(block),
                $enum_variant_three(ref block) => <$block_three as AsSignedBlock<T>>::$fn_name(block),
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
    ($block: ty, $block_two: ty, $block_three: ty, $type: ty, $(.$field: tt)*, $enum_variant: path, $enum_variant_two: path, $enum_variant_three: path $(,$generic: ident: $trait: ident$(<$($generics: ident,)+>)*$(+ $traits: ident$(<$($generics_nested: ident,)+>)*)*)*) => {
        impl<T: BeaconChainTypes $(,$generic: $trait$(<$($generics,)+>)*$(+ $traits$(<$($generics_nested,)+>)*)*)*> AsSignedBlock<T> for $type {
            impl_as_signed_block!($block, $block_two, $block_three, block_root, Hash256, $(.$field)*, $enum_variant, $enum_variant_two, $enum_variant_three);
            impl_as_signed_block!($block, $block_two, $block_three, slot, Slot, $(.$field)*, $enum_variant, $enum_variant_two, $enum_variant_three);
            impl_as_signed_block!($block, $block_two, $block_three, epoch, Epoch, $(.$field)*, $enum_variant, $enum_variant_two, $enum_variant_three);
            impl_as_signed_block!($block, $block_two, $block_three, parent_root, Hash256, $(.$field)*, $enum_variant, $enum_variant_two, $enum_variant_three);
            impl_as_signed_block!($block, $block_two, $block_three, state_root, Hash256, $(.$field)*, $enum_variant, $enum_variant_two, $enum_variant_three);
            impl_as_signed_block!($block, $block_two, $block_three, signed_block_header, SignedBeaconBlockHeader, $(.$field)*, $enum_variant, $enum_variant_two, $enum_variant_three);
            impl_as_signed_block!($block, $block_two, $block_three, message, BeaconBlockRef<<T as BeaconChainTypes>::EthSpec>, $(.$field)*, $enum_variant, $enum_variant_two, $enum_variant_three);
            impl_as_signed_block!($block, $block_two, $block_three, as_block, &SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>, $(.$field)*, $enum_variant, $enum_variant_two, $enum_variant_three);
            impl_as_signed_block!($block, $block_two, $block_three, block_cloned, Arc<SignedBeaconBlock<<T as BeaconChainTypes>::EthSpec>>, $(.$field)*, $enum_variant, $enum_variant_two, $enum_variant_three);
        }
    };
}
impl_as_signed_block!(B, ExecutedBlock<T, B>, .block, B: TryIntoAvailableBlock<T,>);
impl_as_signed_block!(Arc<SignedBeaconBlock<T::EthSpec>>, AvailabilityPendingBlock<T::EthSpec>, .block);
impl_as_signed_block!(Arc<SignedBeaconBlock<T::EthSpec>>, ExecutedBlockInError<T::EthSpec>, .block);
impl_as_signed_block!(
    Arc<SignedBeaconBlock<T::EthSpec>>,
    &Arc<SignedBeaconBlock<T::EthSpec>>,
);
impl_as_signed_block!(Arc<SignedBeaconBlock<T::EthSpec>>, Arc<SignedBeaconBlock<T::EthSpec>>, AvailableBlock<T::EthSpec>, .0, AvailableBlockInner::Block, AvailableBlockInner::BlockAndBlobs, _);
impl_as_signed_block!(AvailableBlock<T::EthSpec>, AvailabilityPendingBlock<T::EthSpec>, Arc<SignedBeaconBlock<T::EthSpec>>, SomeAvailabilityBlock<T::EthSpec>,, Self::Available, Self::AvailabilityPending, Self::RawBlock);

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
