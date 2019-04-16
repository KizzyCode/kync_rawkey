use std::{ ptr, u64, ops::DerefMut, cell::RefCell };


/// Some extension for `&[u8]`
pub trait SliceExt {
	/// Splits the first `len` bytes off from the front of `self`
	fn split_off(&self, len: usize) -> (&Self, &Self);
}
impl SliceExt for [u8] {
	fn split_off(&self, len: usize) -> (&Self, &Self) {
		// Validate length and split `self`
		ensure!(self.len() >= len);
		self.split_at(len)
	}
}


/// Some extension for `&mut[u8]`
pub trait MutSliceExt {
	/// Splits the first `len` bytes off from the front of `self` and returns `(front, remaining)`
	fn split_off_mut(&mut self, len: usize) -> (&mut Self, &mut Self);
}
impl MutSliceExt for [u8] {
	fn split_off_mut(&mut self, len: usize) -> (&mut Self, &mut Self) {
		// Validate length and split `self`
		ensure!(self.len() >= len);
		self.split_at_mut(len)
	}
}


/// A trait to extend `*mut error_t`
pub trait ErrorExt {
	/// Sets the description if `self` is not `NULL`
	fn set_desc(self, d: &'static[u8]) -> Self;
}
impl ErrorExt for *mut error_t {
	fn set_desc(self, d: &'static[u8]) -> Self {
		if !self.is_null() {
			unsafe{ (*self).description = d.as_ptr() }
			unsafe{ (*self).description_len = d.len() }
		}
		self
	}
}


/// The thread local error
thread_local! {
	static THREAD_LOCAL_ERR: RefCell<error_t> = RefCell::new(error_t {
		error_type: ptr::null(), error_type_len: 0,
		description: ptr::null(), description_len: 0,
		info: 0
	});
}
/// The type of a thread-local error
#[repr(C)] #[allow(non_camel_case_types)]
pub struct error_t {
	/// The error type (one of the predefined identifiers) or empty in case no error occurred (yet)
	error_type: *const u8,
	error_type_len: usize,
	/// The error description or empty
	description: *const u8,
	description_len: usize,
	/// Some error specific info
	info: u64
}
impl error_t {
	/// Creates a new error with `t` as error type and `i` as info
	fn set(t: &'static [u8], i: u64) -> *mut Self {
		THREAD_LOCAL_ERR.with(|e| {
			e.borrow_mut().error_type = t.as_ptr();
			e.borrow_mut().error_type_len = t.len();
			e.borrow_mut().description = ptr::null();
			e.borrow_mut().description_len = 0;
			e.borrow_mut().info = i;
			e.borrow_mut().deref_mut() as *mut Self
		})
	}
	
	/// Creates a new `error_t` that signalizes that no error occurred
	pub fn ok() -> *const Self {
		ptr::null()
	}
	/// Creates an `EPERM` error
	pub fn eperm(required_authentication: bool) -> *mut Self {
		Self::set(b"EPERM", if required_authentication { 1 } else { 0 })
	}
	/// Creates an `EACCES` error
	pub fn eacces(retries_left: Option<u64>) -> *mut Self {
		Self::set(b"EACCES", retries_left.unwrap_or(u64::MAX))
	}
	/// Creates an `EIO` error
	pub fn eio() -> *mut Self {
		Self::set(b"EIO", 0)
	}
	/// Creates an `EILSEQ` error
	pub fn eilseq() -> *mut Self {
		Self::set(b"EILSEQ", 0)
	}
	/// Creates an `ENOTFOUND` error
	pub fn enotfound() -> *mut Self {
		Self::set(b"ENOTFOUND", 0)
	}
	/// Creates an `EINVAL` error
	pub fn einval(index: u64) -> *mut Self {
		Self::set(b"EINVAL", index)
	}
	/// Creates an `ECANCELED` error
	pub fn ecanceled() -> *mut Self {
		Self::set(b"ECANCELED", 0)
	}
	/// Creates an `ETIMEDOUT` error
	pub fn etimedout() -> *mut Self {
		Self::set(b"ETIMEDOUT", 0)
	}
	/// Creates an `EOTHER` error
	pub fn eother(errno: u64) -> *mut Self {
		Self::set(b"EOTHER", errno)
	}
}
#[test]
fn bindgen_test_layout_error_t() {
	use std::{
		ptr::null,
		mem::{ align_of, size_of }
	};
	
	assert_eq!(size_of::<error_t>(), 40usize, concat!("Size of: ", stringify!(error_t)));
	assert_eq!(align_of::<error_t>(), 8usize, concat!("Alignment of ", stringify!(error_t)));
	assert_eq!(
		unsafe { &(*(null::<error_t>())).error_type as *const _ as usize }, 0usize,
		concat!("Offset of field: ", stringify!(error_t), "::", stringify!(error_type))
	);
	assert_eq!(
		unsafe { &(*(null::<error_t>())).error_type_len as *const _ as usize }, 8usize,
		concat!("Offset of field: ", stringify!(error_t), "::", stringify!(error_type_len))
	);
	assert_eq!(
		unsafe { &(*(null::<error_t>())).description as *const _ as usize }, 16usize,
		concat!("Offset of field: ", stringify!(error_t), "::", stringify!(description))
	);
	assert_eq!(
		unsafe { &(*(null::<error_t>())).description_len as *const _ as usize }, 24usize,
		concat!("Offset of field: ", stringify!(error_t), "::", stringify!(description_len))
	);
	assert_eq!(
		unsafe { &(*(null::<error_t>())).info as *const _ as usize }, 32usize,
		concat!("Offset of field: ", stringify!(error_t), "::", stringify!(info))
	);
}