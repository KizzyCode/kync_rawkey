//mod misc;
mod ffi;
mod crypto;

use ffi::{ MutPtrExt, SliceTExt, WriteTExt, sys };
use std::{
	ptr, os::raw::c_char,
	sync::atomic::{ AtomicU8, Ordering::SeqCst }
};


// Use MAProper if the feature is enabled
#[cfg(any(feature = "use-maproper", feature = "use-maproper-volatile"))]
#[global_allocator]
static MA_PROPER: ma_proper::MAProper = ma_proper::MAProper;


// Constants and global log level
const API: u16 = 0x01_00;
const UID: &[u8] = b"de.KizzyCode.RawKey.2C24B914-C9E9-41B3-8033-6B0364BCBA2E";
const CONFIG_BLAKE2B_CHACHAPOLY_IETF: &[u8] = b"Blake2b-ChaChaPolyIETF";
static LOG_LEVEL: AtomicU8 = AtomicU8::new(0);


const ERR_INVALID_API: *const c_char = b"Unsupported API version\0".as_ptr().cast();
const ERR_INVALID_CONFIG: *const c_char = b"Invalid config\0".as_ptr().cast();
const ERR_MISSING_AUTH: *const c_char = b"Missing required authentication data".as_ptr().cast();


/// Logs some text
#[allow(unused)]
fn log(s: impl AsRef<str>) {
	if LOG_LEVEL.load(SeqCst) > 0 {
		eprintln!("{}", s.as_ref())
	}
}

/// Converts a `Result<(), *const c_char>>` to a nullable error pointer
fn try_catch(f: impl FnOnce() -> Result<(), *const c_char>) -> *const c_char {
	f().err().unwrap_or(ptr::null())
}


/// Initializes the library with a specific API version and a logging level
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
pub extern "C" fn init(api: u16, log_level: u8) -> *const c_char {
	LOG_LEVEL.store(log_level, SeqCst);
	match api {
		API => ptr::null(),
		_ => ERR_INVALID_API
	}
}


/// Queries the plugin/format ID
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
pub extern "C" fn id(sink: *mut sys::write_t) -> *const c_char {
	try_catch(|| sink.checked_write(UID))
}


/// Queries all possible configs and writes them as separate segments
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
pub extern "C" fn configs(sink: *mut sys::write_t) -> *const c_char {
	try_catch(|| sink.checked_write(CONFIG_BLAKE2B_CHACHAPOLY_IETF))
}


/// Sets an optional application specific context if supported (useful to name the keys better etc.)
///
/// Returns `NULL` on success/if unsupported or a pointer to a static error description if a context
/// is supported by the plugin but could not be set
#[no_mangle]
pub extern "C" fn set_context(_context: *const sys::slice_t) -> *const c_char {
	ptr::null()
}


/// Queries the authentication requirements to protect a secret for a specific config
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn auth_info_protect(is_required: *mut u8, retries: *mut u64,
	config: *const sys::slice_t) -> *const c_char
{
	try_catch(|| {
		// Validate the passed config
		if config.checked_slice()? != CONFIG_BLAKE2B_CHACHAPOLY_IETF {
			Err(ERR_INVALID_CONFIG)?
		}
		
		// Set info
		is_required.checked_set(1)?;
		retries.checked_set(u64::max_value())?;
		Ok(())
	})
}


/// Queries the authentication requirements to recover a secret for a specific config
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn auth_info_recover(is_required: *mut u8, retries: *mut u64,
	config: *const sys::slice_t) -> *const c_char
{
	try_catch(|| {
		// Validate the passed config
		if config.checked_slice()? != CONFIG_BLAKE2B_CHACHAPOLY_IETF {
			Err(ERR_INVALID_CONFIG)?
		}
		
		// Set info
		is_required.checked_set(1)?;
		retries.checked_set(u64::max_value())?;
		Ok(())
	})
}


/// Protects some data
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
extern "C" fn protect(sink: *mut sys::write_t, data: *const sys::slice_t,
	config: *const sys::slice_t, auth: *const sys::slice_t) -> *const c_char
{
	try_catch(|| {
		// Validate the passed config
		if config.checked_slice()? != CONFIG_BLAKE2B_CHACHAPOLY_IETF {
			Err(ERR_INVALID_CONFIG)?
		}
		
		// Protect the key
		let auth = auth.checked_slice().map_err(|_| ERR_MISSING_AUTH)?;
		let protected = crypto::protect(auth, data.checked_slice()?)?;
		Ok(sink.checked_write(&protected)?)
	})
}


/// Recovers some data
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn recover(sink: *mut sys::write_t, data: *const sys::slice_t, auth: *const sys::slice_t)
	-> *const c_char
{
	try_catch(|| {
		// Recover the key
		let auth = auth.checked_slice().map_err(|_| ERR_MISSING_AUTH)?;
		let recovered = crypto::recover(auth, data.checked_slice()?)?;
		Ok(sink.checked_write(&recovered)?)
	})
}


/// Test the function signatures
#[test]
fn test_types() {
	struct Fns {
		_init: sys::init,
		_id: sys::id,
		_configs: sys::configs,
		_set_context: sys::set_context,
		_auth_info_protect: sys::auth_info_protect,
		_auth_info_recover: sys::auth_info_recover,
		_protect: sys::protect,
		_recover: sys::recover
	}
	let _fns = Fns {
		_init: Some(init),
		_id: Some(id),
		_configs: Some(configs),
		_set_context: Some(set_context),
		_auth_info_protect: Some(auth_info_protect),
		_auth_info_recover: Some(auth_info_recover),
		_protect: Some(protect),
		_recover: Some(recover)
	};
}