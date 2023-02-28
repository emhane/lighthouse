use kzg::{Error as KzgError, Kzg, KzgProof, BYTES_PER_BLOB};
use ssz_types::VariableList;
use std::sync::Arc;
use types::{Blob, BlobSidecar, EthSpec, Hash256, KzgCommitment, Slot};

fn ssz_blob_to_crypto_blob<T: EthSpec>(blob: Blob<T>) -> kzg::Blob {
    let blob_vec: Vec<u8> = blob.into();
    let mut arr = [0; BYTES_PER_BLOB];
    arr.copy_from_slice(&blob_vec);
    arr.into()
}

pub fn validate_blob_sidecars<T: EthSpec>(
    kzg: Kzg,
    slot: Slot,
    beacon_block_root: Hash256,
    expected_kzg_commitments: &[KzgCommitment],
    mut blob_sidecars: VariableList<Arc<BlobSidecar<T>>, T::MaxBlobsPerBlock>,
) -> Result<bool, KzgError> {
    if blob_sidecars.len() != expected_kzg_commitments.len() {
        return Ok(false);
    }
    for blob_sidecar in blob_sidecars.iter() {
        if slot != blob_sidecar.beacon_block_slot
            || beacon_block_root != blob_sidecar.beacon_block_root
        {
            return Ok(false);
        }
    }

    blob_sidecars.sort_by(|a, b| a.blob_index.partial_cmp(&b.blob_index).unwrap());
    let (blobs, kzg_aggregate_proofs): (Vec<_>, Vec<_>) = blob_sidecars
        .into_iter()
        .map(|blob| {
            (
                ssz_blob_to_crypto_blob::<T>(blob.blob.clone()),
                blob.kzg_aggregated_proof,
            )
        }) // TODO(pawa(n): avoid this clone
        .unzip();
    Ok(true)
    //kzg.verify_aggregate_kzg_proof(&blobs, expected_kzg_commitments, kzg_aggregate_proofs)
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
