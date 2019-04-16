/// Ensures that `expr` is true
macro_rules! ensure {
    ($expr:expr) => ({
    	if !$expr {
    		if crate::LOG_LEVEL.load(::std::sync::atomic::Ordering::SeqCst) > 0 {
    			eprintln!("Assertion failed @{}:{} (`{}`)", file!(), line!(), stringify!($expr))
    		}
    		::std::process::abort()
    	}
    });
}
/// Ensures that `$ptr` is not `NULL`
macro_rules! not_null {
    ($($ptr:expr),*) => ($( ensure!(!$ptr.is_null()); )*);
}


// Mods and includes
mod misc;

use crate::misc::{ SliceExt, MutSliceExt, ErrorExt, error_t };
use crypto_api_osrandom::OsRandom;
use crypto_api_blake2::Blake2b;
use crypto_api_chachapoly::ChachaPolyIetf;
use std::{
	slice,
	sync::atomic::{ Ordering, AtomicU8 }
};


// Constants and global log level
const API_VERSION: u8 = 1;
const UID: &[u8] = b"de.KizzyCode.RawKey.7ABD7A67-49EC-46B6-B881-1B6FD7E03E01";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MAC_LEN: usize = 16;
const OVERHEAD: usize = SALT_LEN + NONCE_LEN + MAC_LEN;

static LOG_LEVEL: AtomicU8 = AtomicU8::new(0);


/// Initializes the plugin and sets the `log_level`
#[no_mangle]
pub extern "C" fn init(api_version: *mut u8, log_level: u8) {
	not_null!(api_version);
	
	LOG_LEVEL.store(log_level, Ordering::SeqCst);
	unsafe{ *api_version = API_VERSION }
}

/// Computes the buffer size necessary for a call to `fn_name` which will process `input_len` bytes
/// of input and writes the result to `buf_len`
#[no_mangle]
pub extern "C" fn buf_len(buf_len: *mut usize, fn_name: *const u8, fn_name_len: usize,
	input_len: usize)
{
	not_null!(buf_len, fn_name);
	
	// Get the function name
	let fn_name = unsafe{ slice::from_raw_parts(fn_name, fn_name_len) };
	let len = match fn_name {
		b"capsule_format_uid" => UID.len(),
		b"crypto_item_ids" => 0,
		b"seal" => input_len + OVERHEAD,
		b"open" => input_len,
		_ => 0
	};
	unsafe{ *buf_len = len }
}

/// Writes the plugin UID to `uid`
#[no_mangle]
pub extern "C" fn capsule_format_uid(uid: *mut u8, uid_written: *mut usize) {
	not_null!(uid, uid_written);
	
	// Copy the UID
	let uid = unsafe{ slice::from_raw_parts_mut(uid, UID.len()) };
	uid.copy_from_slice(UID);
	unsafe{ *uid_written = UID.len() }
}


/// Writes all crypto item IDs as `\0`-terminated, concatenated UTF-8 strings to `_buf`
#[no_mangle]
pub extern "C" fn crypto_item_ids(_buf: *mut u8, _buf_written: *mut usize) -> *const error_t {
	not_null!(_buf, _buf_written);
	
	error_t::enotfound().set_desc(b"This plugin does not support multiple crypto items")
}


/// Seals `key` into `buf`
///
/// ## Algorithm
/// 1. Create a secure random 16 byte KDF `salt` and a secure random 12 byte ChachaPoly `nonce`
/// 2. Derive a ChachaPoly `aead_key` by using Blake2b as KDF with the `user_secret` as key and
///    `salt` as salt
/// 3. Seal `key` using ChachaPoly with `aead_key` as key and `nonce` as nonce
///
/// ## Format
/// `salt[16] || nonce[12] || chacha_ciphertext* || poly_tag[16]`
///
/// (`||` denotes concatenation)
#[no_mangle]
pub extern "C" fn seal(buf: *mut u8, buf_written: *mut usize, key: *const u8, key_len: usize,
	crypto_item_id: *const u8, _crypto_item_id_len: usize, user_secret: *const u8,
	user_secret_len: usize) -> *const error_t
{
	not_null!(buf, buf_written, key);
	
	// Create slices
	match crypto_item_id.is_null() {
		true => (),
		false => return error_t::einval(4).set_desc(b"Invalid crypto item")
	};
	let user_secret = match user_secret.is_null() {
		true => return error_t::eperm(true).set_desc(b"Missing user secret"),
		false => match user_secret_len {
			1..=64 => unsafe{ slice::from_raw_parts(user_secret, user_secret_len) },
			_ => return error_t::einval(6).set_desc(b"Unsupported user secret length")
		}
	};
	let key = unsafe{ slice::from_raw_parts(key, key_len) };
	let buf = unsafe{ slice::from_raw_parts_mut(buf, key_len + OVERHEAD) };
	
	
	// Create a salt, nonce and derive the key
	let (salt, buf) = buf.split_off_mut(SALT_LEN);
	ensure!(OsRandom::secure_rng().random(salt).is_ok());
	
	let (nonce, buf) = buf.split_off_mut(NONCE_LEN);
	ensure!(OsRandom::secure_rng().random(nonce).is_ok());
	
	let mut aead_key = vec![0; 32];
	ensure!(Blake2b::kdf().derive(&mut aead_key, user_secret, salt, b"").is_ok());
	
	
	// Encrypt the key
	ensure!(ChachaPolyIetf::aead_cipher().seal_to(buf, key, b"", &aead_key, nonce).is_ok());
	unsafe{ *buf_written = key_len + OVERHEAD }
	error_t::ok()
}


/// Opens `capsule` into `buf`
///
/// ## Algorithm
/// 1. Create a secure random 16 byte KDF `salt` and a secure random 12 byte ChachaPoly `nonce`
/// 2. Derive a ChachaPoly `aead_key` by using Blake2b as KDF with the `user_secret` as key and
///    `salt` as salt
/// 3. Seal `key` using ChachaPoly with `aead_key` as key and `nonce` as nonce
///
/// ## Format
/// `salt[16] || nonce[12] || chacha_ciphertext* || poly_tag[16]`
///
/// (`||` denotes concatenation)
#[no_mangle]
pub extern "C" fn open(buf: *mut u8, buf_written: *mut usize, capsule: *const u8,
	capsule_len: usize, user_secret: *const u8, user_secret_len: usize) -> *const error_t
{
	not_null!(buf, buf_written, capsule);
	
	// Create slices
	let capsule = match capsule_len >= OVERHEAD {
		true => unsafe{ slice::from_raw_parts(capsule, capsule_len) },
		false => return error_t::eilseq().set_desc(b"Truncated capsule")
	};
	let user_secret = match user_secret.is_null() {
		true => return error_t::eperm(true).set_desc(b"Missing user secret"),
		false => match user_secret_len {
			1..=64 => unsafe{ slice::from_raw_parts(user_secret, user_secret_len) },
			_ => return error_t::einval(6).set_desc(b"Unsupported user secret length")
		}
	};
	let buf = unsafe{ slice::from_raw_parts_mut(buf, capsule_len) };
	
	
	// Derive key
	let (salt, capsule) = capsule.split_off(SALT_LEN);
	let (nonce, ciphertext) = capsule.split_off(NONCE_LEN);
	
	let mut aead_key = vec![0; 32];
	ensure!(Blake2b::kdf().derive(&mut aead_key, user_secret, salt, b"").is_ok());
	
	
	// Decrypt the capsule
	match ChachaPolyIetf::aead_cipher().open_to(buf, ciphertext, b"", &aead_key, nonce) {
		Ok(_) => {
			unsafe{ *buf_written = capsule_len - OVERHEAD }
			error_t::ok()
		}
		Err(e) => {
			eprintln!("{}", e);
			error_t::eilseq().set_desc(b"Invalid capsule")
		}
	}
}