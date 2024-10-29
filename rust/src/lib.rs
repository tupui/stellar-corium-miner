use hex::encode;
use pyo3::prelude::*;
use sha3::Digest;

pub fn is_difficulty_correct(hash: &[u8], difficulty: &u8) -> bool {
    let mut hex = encode(hash);
    hex.truncate(*difficulty as usize);
    let mut total_zeroes: u8 = 0;

    for char in hex.chars() {
        if char as u32 != 48 {
            break;
        } else {
            total_zeroes += 1;
        }
    }

    &total_zeroes == difficulty
}

/// Find a block of a certain difficulty
#[pyfunction]
fn dig(
    idx_message_prev_hash_nonce_xdr_const_: &[u8],
    miner_: &[u8],
    mut nonce: u64,
    difficulty: u8,
) -> (bool, [u8; 32], u64) {
    let mut result = [1u8; 32];
    let mut hasher = sha3::Keccak256::new();

    while !is_difficulty_correct(&result, &difficulty) {
        nonce += 1;

        if nonce % 5000000 == 0 {
            return (false, result, nonce);
        }

        let nonce_: [u8; 8] = nonce.to_be_bytes();

        let data_hash = [idx_message_prev_hash_nonce_xdr_const_, &nonce_, miner_].concat();

        hasher.update(data_hash);
        hasher.finalize_into_reset((&mut result).into());
    }

    (true, result, nonce)
}

/// A Python module implemented in Rust.
#[pymodule]
fn rs_corium_digger(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(dig, m)?)?;
    Ok(())
}
