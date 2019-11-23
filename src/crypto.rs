use crate::ffi::ResultLogExt;
use std::os::raw::c_char;
use crypto_api_osrandom::OsRandom;
use crypto_api_blake2::Blake2b;
use crypto_api_chachapoly::ChachaPolyIetf;


const OVERHEAD: usize = 16 + 12 + 16;

const ERR_OSRANDOM: *const c_char = b"OsRandom failed to generate data\0".as_ptr().cast();
const ERR_KDF: *const c_char = b"Blake2b-KDF failed to derive a key\0".as_ptr().cast();
const ERR_SEAL: *const c_char = b"ChachaPolyIetf failed to seal some data\0".as_ptr().cast();
const ERR_TRUNCATED: *const c_char = b"The capsule is truncated/damaged\0".as_ptr().cast();
const ERR_OPEN: *const c_char = b"ChachaPolyIetf failed to open some data\0".as_ptr().cast();


fn random(buf: &mut[u8]) -> Result<(), *const c_char> {
	OsRandom::secure_rng().random(buf).log_map_err(ERR_OSRANDOM)
}
fn kdf(base_key: &[u8], salt: &[u8]) -> Result<Vec<u8>, *const c_char> {
	let mut buf = vec![0; 32];
	Blake2b::kdf().derive(&mut buf, base_key, salt, b"")
		.map(|_| buf).log_map_err(ERR_KDF)
}

pub fn protect(key: &[u8], data: &[u8]) -> Result<Vec<u8>, *const c_char> {
	// Create and reference buffer
	let mut capsule = vec![0; data.len() + OVERHEAD];
	let (salt, buf) = capsule.split_at_mut(16);
	let (nonce, buf) = buf.split_at_mut(12);
	
	// Generate salt, nonce and key
	random(salt)?;
	random(nonce)?;
	let key = kdf(key, &salt)?;
	
	// Seal the data
	ChachaPolyIetf::aead_cipher().seal_to(buf, data, b"", &key, nonce)
		.map(|_| capsule).log_map_err(ERR_SEAL)
}

pub fn recover(key: &[u8], data: &[u8]) -> Result<Vec<u8>, *const c_char> {
	// Ensure the minimum length
	if data.len() < OVERHEAD {
		Err(ERR_TRUNCATED)?
	}
	
	// Reference data and create buffer
	let (salt, data) = data.split_at(16);
	let (nonce, data) = data.split_at(12);
	let mut buf = vec![0; data.len()];
	
	// Generate key and open data
	let key = kdf(key, &salt)?;
	let len = ChachaPolyIetf::aead_cipher().open_to(&mut buf, data, b"", &key, nonce)
		.log_map_err(ERR_OPEN)?;
	
	// Truncate buffer
	buf.truncate(len);
	Ok(buf)
}