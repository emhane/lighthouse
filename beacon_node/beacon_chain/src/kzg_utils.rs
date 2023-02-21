use kzg::{Error as KzgError, Kzg, BYTES_PER_BLOB};
use types::{Blob, BlobsSidecar, EthSpec, Hash256, KzgCommitment, KzgProof, Slot};

fn ssz_blob_to_crypto_blob<T: EthSpec>(blob: Blob<T>) -> kzg::Blob {
    let blob_vec: Vec<u8> = blob.into();
    let mut arr = [0; BYTES_PER_BLOB];
    arr.copy_from_slice(&blob_vec);
    arr.into()
}

pub fn validate_blob_sidecars<T: EthSpec>(
    kzg: &Kzg,
    slot: Slot,
    beacon_block_root: Hash256,
    expected_kzg_commitments: &[KzgCommitment],
    blob_sidecars: VariableList<BlobSidecar<T>, T::MaxBlobsPerBlock>,
) -> Result<bool, KzgError> {
    if slot != blob_sidecars.beacon_block_slot
        || beacon_block_root != blob_sidecars.beacon_block_root
        || blob_sidecars.len() != expected_kzg_commitments.len()
    {
        return Ok(false);
    }

    blobs.sort_by(|a, b| a.index().partial_cmp(b.index()).unwrap());
    let blobs = blob_sidecars
        .into_iter()
        .map(|blob| ssz_blob_to_crypto_blob::<T>(blob.blob.clone())) // TODO(pawan): avoid this clone
        .collect::<Vec<_>>();

    kzg.verify_aggregate_kzg_proof(
        &blobs,
        expected_kzg_commitments,
        blob_sidecars.kzg_aggregated_proof,
    )
}

pub fn compute_aggregate_kzg_proof<T: EthSpec>(
    kzg: &Kzg,
    blobs: &[Blob<T>],
) -> Result<KzgProof, KzgError> {
    let blobs = blobs
        .into_iter()
        .map(|blob| ssz_blob_to_crypto_blob::<T>(blob.clone())) // TODO(pawan): avoid this clone
        .collect::<Vec<_>>();

    kzg.compute_aggregate_kzg_proof(&blobs)
}

pub fn blob_to_kzg_commitment<T: EthSpec>(kzg: &Kzg, blob: Blob<T>) -> KzgCommitment {
    let blob = ssz_blob_to_crypto_blob::<T>(blob);
    kzg.blob_to_kzg_commitment(blob)
}
