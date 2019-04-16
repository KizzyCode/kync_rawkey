use kync::{
	Plugin,
	plugin::{ os_default_prefix, os_default_suffix }
};
use std::{ u128, error::Error, path::PathBuf };
use crypto_api_osrandom::OsRandom;


/// A helper trait to extend our Argon2 plugin
trait RawkeyPluginExt {
	/// Loads the `rawkey` plugin
	fn rawkey_load() -> Self;
	
	/// Seals `key` using `preset` and `password`
	fn rawkey_seal(&self, key: &[u8], user_secret: &[u8])
		-> Result<Vec<u8>, Box<dyn Error + 'static>>;
	/// Opens `capsule` using `password`
	fn rawkey_open(&self, capsule: &[u8], user_secret: &[u8])
		-> Result<Vec<u8>, Box<dyn Error + 'static>>;
}
impl RawkeyPluginExt for Plugin {
	fn rawkey_load() -> Self {
		// Create path
		let mut path = PathBuf::new();
		path.push("target");
		path.push(if cfg!(debug_assertions) { "debug" } else { "release" });
		path.push(format!("{}kync_rawkey.{}", os_default_prefix(), os_default_suffix()));
		
		// Load plugin
		Plugin::load(path).unwrap()
	}
	fn rawkey_seal(&self, key: &[u8], user_secret: &[u8])
		-> Result<Vec<u8>, Box<dyn Error + 'static>>
	{
		let mut buf = vec![0; self.seal_buf_len(key.len())];
		let buf_len =
			self.seal(&mut buf, key, None, Some(user_secret))?;
		buf.truncate(buf_len);
		Ok(buf)
	}
	fn rawkey_open(&self, capsule: &[u8], user_secret: &[u8])
		-> Result<Vec<u8>, Box<dyn Error + 'static>>
	{
		let mut buf = vec![0; self.open_buf_len(capsule.len())];
		let buf_len = self.open(&mut buf, capsule, Some(user_secret))?;
		buf.truncate(buf_len);
		Ok(buf)
	}
}


/// Implements some helper methods for random test parameters
struct Random;
impl Random {
	/// Creates a new `len`-sized vector filled with random bytes
	pub fn vec(len: usize) -> Vec<u8> {
		let mut buf = vec![0; len];
		OsRandom::secure_rng().random(&mut buf).unwrap();
		buf
	}
	/// Creates a uniform distributed random number in `[0, max)`
	pub fn num(max: u128) -> u128 {
		// Create a random number
		fn rand() -> u128 {
			let mut buf = [0; 16];
			OsRandom::secure_rng().random(&mut buf).unwrap();
			u128::from_be_bytes(buf)
		}
		
		// Compute the limit
		let limit = u128::MAX - (u128::MAX % max);
		
		// Get a random number in range
		let mut value = rand();
		while value >= limit { value = rand() }
		
		value % max
	}
	/// Creates a uniform random length in `[1, 64)`
	pub fn len() -> usize {
		const MAX: u128 = 63;
		Self::num(MAX) as usize + 1
	}
}


/// A test vector to perform randomized tests
struct RandomizedTestVector;
impl RandomizedTestVector {
	/// Run a randomized tests
	pub fn test(&self, plugin: &Plugin) {
		// Generate random password and key and select a random preset
		let (key, password) =
			(Random::vec(Random::len()), Random::vec(Random::len()));
		
		// Seal the key
		println!(
			"*> Performing `seal->open`-test with a {} byte key and a {} byte password...",
			key.len(), password.len()
		);
		let capsule = plugin.rawkey_seal(&key, &password).unwrap();
		
		// Open capsule and compare keys
		let opened = plugin.rawkey_open(&capsule, &password).unwrap();
		assert_eq!(key, opened)
	}
}


/// Test a random batch
#[test]
fn test() {
	let plugin = Plugin::rawkey_load();
	for _ in 0..64 { RandomizedTestVector.test(&plugin) }
}


/// Tests a predefined capsule
#[test]
fn test_predefined() {
	const KEY: &[u8] = b"Testolope";
	const USER_SECRET: &[u8] = b"oGKqY-Yx8wR-HFCMv-Y9Smh-N6oZb-p7ekX-tY3c5-ExCSY-vCG6c";
	const CAPSULE: &[u8] = b"\x14\x2e\x97\xb3\xaf\x8a\x4a\x10\x64\xaa\x67\x2b\x28\xce\x6d\x27\x39\x7e\x8e\x21\xf1\xef\x56\xa5\x61\x2c\xe2\xda\x1c\xc6\x6a\x92\x58\x7d\x12\x7f\xf1\xf5\xde\x71\xc3\x0e\x71\xbd\x7d\xd3\xed\xfb\x32\xb4\xc2\xb6\x2c";
	
	let plugin = Plugin::rawkey_load();
	let key = plugin.rawkey_open(CAPSULE, USER_SECRET).unwrap();
	assert_eq!(key, KEY);
}