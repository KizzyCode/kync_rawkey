#![allow(non_camel_case_types)]
use crate::log;
use std::{ slice, fmt::Display, os::raw::c_char };


/// An error string indicating a NULL pointer error
const ERR_NULLPTR: *const c_char = b"Unexpected NULL pointer\n".as_ptr().cast();


/// Some `Result` extensions
pub trait ResultLogExt<T, E: Display> {
	/// Checks if a result contains an error and logs it
	fn log_err(self) -> Result<T, E>;
	/// Checks if a result contains an error, logs it and maps it afterwards
	fn log_map_err<M>(self, m: M) -> Result<T, M>;
}
impl<T, E: Display> ResultLogExt<T, E> for Result<T, E> {
	fn log_err(self) -> Result<T, E> {
		self.map_err(|e| { log(e.to_string()); e })
	}
	fn log_map_err<M>(self, m: M) -> Result<T, M> {
		self.map_err(|e| { log(e.to_string()); m })
	}
}


/// An extension to work with statically allocated constant C strings
pub trait StaticCharPtrExt {
	/// Checks if there is an non-`NULL` error pointer
	fn check(self) -> Result<(), *const c_char>;
}
impl StaticCharPtrExt for *const c_char {
	fn check(self) -> Result<(), *const c_char> {
		match self.is_null() {
			true => Ok(()),
			false => Err(self)
		}
	}
}


/// An extension to check and assign to a mutable pointer
pub trait MutPtrExt<T: Copy> {
	/// Checks and assigns a value to a `*mut T`
	fn checked_set(self, v: T) -> Result<(), *const c_char>;
}
impl<T: Copy> MutPtrExt<T> for *mut T {
	fn checked_set(self, v: T) -> Result<(), *const c_char> {
		let this = unsafe{ self.as_mut() }.ok_or(ERR_NULLPTR)?;
		Ok(*this = v)
	}
}


/// The sys bindings
pub mod sys {
	#![allow(unused)]
	include!("sys.rs");
}


/// An extension to check and deref the slice type
pub trait SliceTExt {
	/// Checks and wraps a `*const sys::slice_t`
	fn checked_slice<'a>(self) -> Result<&'a[u8], *const c_char>;
}
impl SliceTExt for *const sys::slice_t {
	fn checked_slice<'a>(self) -> Result<&'a[u8], *const c_char> {
		let this = unsafe{ self.as_ref() }.ok_or(ERR_NULLPTR)?;
		match this.ptr.is_null() {
			false => Ok(unsafe{ slice::from_raw_parts(this.ptr, this.len) }),
			true => Err(ERR_NULLPTR)
		}
	}
}


/// An extension to check and write to the write callback
pub trait WriteTExt {
	/// Checks and writes a segment to a `*const sys::write_t`
	fn checked_write(self, data: impl AsRef<[u8]>) -> Result<(), *const c_char>;
}
impl WriteTExt for *mut sys::write_t {
	fn checked_write(self, data: impl AsRef<[u8]>) -> Result<(), *const c_char> {
		let data = data.as_ref();
		let slice = sys::slice_t{ ptr: data.as_ptr(), len: data.len() };
		
		let this = unsafe{ self.as_mut() }.ok_or(ERR_NULLPTR)?;
		match this.handle.is_null() {
			false => unsafe{ this.write.unwrap()(this.handle, &slice) }.check(),
			true => Err(ERR_NULLPTR)
		}
	}
}
