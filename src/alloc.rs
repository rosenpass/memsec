//! alloc

#![cfg(feature = "alloc")]

extern crate rand;

use core::mem;
use core::ptr::{ self, NonNull };
use self::rand::{ Rng, OsRng };
use self::raw_alloc::*;

#[cfg(not(target_arch = "wasm32"))] use std::sync::Once;
#[cfg(target_arch = "wasm32")] use self::once::Once;
#[cfg(not(feature = "nightly"))] use std::process::abort;
#[cfg(feature = "nightly")] use core::intrinsics::abort;


const GARBAGE_VALUE: u8 = 0xd0;
const CANARY_SIZE: usize = 16;
static ALLOC_INIT: Once = Once::new();
static mut PAGE_SIZE: usize = 0;
static mut PAGE_MASK: usize = 0;
static mut CANARY: [u8; CANARY_SIZE] = [0; CANARY_SIZE];


// -- alloc init --

#[cfg(target_arch = "wasm32")]
mod once {
    use core::sync::atomic::{ AtomicBool, Ordering };

    pub struct Once(AtomicBool);

    impl Once {
        pub const fn new() -> Self {
            Once(AtomicBool::new(false))
        }

        pub fn call_once<F>(&self, f: F)
            where F: FnOnce()
        {
            if !self.0.fetch_or(true, Ordering::SeqCst) {
                f();
            }
        }
    }
}

#[inline]
unsafe fn alloc_init() {
    #[cfg(unix)] {
        PAGE_SIZE = ::libc::sysconf(::libc::_SC_PAGESIZE) as usize;
    }

    #[cfg(windows)] {
        let mut si = mem::uninitialized();
        ::winapi::um::sysinfoapi::GetSystemInfo(&mut si);
        PAGE_SIZE = si.dwPageSize as usize;
    }

    #[cfg(target_arch = "wasm32")]
    #[cfg_attr(feature = "cargo-clippy", allow(decimal_literal_representation))]
    {
        PAGE_SIZE = 4096;
    }

    #[cfg(not(any(unix, windows, target_arch = "wasm32")))]
    compile_error!("not support system/arch");

    if PAGE_SIZE < CANARY_SIZE || PAGE_SIZE < mem::size_of::<usize>() {
        abort();
    }

    PAGE_MASK = PAGE_SIZE - 1;

    // TODO wasm support
    OsRng::new().unwrap().fill_bytes(&mut CANARY);
}


// -- aligned alloc / aligned free --

#[cfg(not(feature = "nightly"))]
mod raw_alloc {
    use super::*;

    #[cfg(unix)]
    #[inline]
    pub unsafe fn alloc_aligned(size: usize) -> Option<NonNull<u8>> {
        let mut memptr = mem::uninitialized();
        match ::libc::posix_memalign(&mut memptr, PAGE_SIZE, size) {
            0 => Some(NonNull::new_unchecked(memptr as *mut u8)),
            ::libc::EINVAL => abort(),
            ::libc::ENOMEM => None,
            _ => unreachable!()
        }
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn alloc_aligned(size: usize) -> Option<NonNull<u8>> {
        let memptr = ::winapi::um::memoryapi::VirtualAlloc(
            ptr::null_mut(),
            size as ::winapi::shared::basetsd::SIZE_T,
            ::winapi::um::winnt::MEM_COMMIT | ::winapi::um::winnt::MEM_RESERVE,
            ::winapi::um::winnt::PAGE_READWRITE
        );

        NonNull::new(memptr as *mut u8)
    }

    #[cfg(unix)]
    #[inline]
    pub unsafe fn free_aligned(memptr: *mut u8, _size: usize) {
        ::libc::free(memptr as *mut ::libc::c_void);
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn free_aligned(memptr: *mut u8, _size: usize) {
        ::winapi::um::memoryapi::VirtualFree(
            memptr as ::winapi::shared::minwindef::LPVOID,
            0,
            ::winapi::um::winnt::MEM_RELEASE
        );
    }
}

#[cfg(feature = "nightly")]
mod raw_alloc {
    extern crate alloc;

    use self::alloc::heap::{ Alloc, Layout, Heap };
    use super::*;

    #[inline]
    pub unsafe fn alloc_aligned(size: usize) -> Option<NonNull<u8>> {
        Heap.alloc(Layout::from_size_align_unchecked(size, PAGE_SIZE))
            .map(|ptr| NonNull::new_unchecked(ptr))
            .ok()
    }

    #[inline]
    pub unsafe fn free_aligned(memptr: *mut u8, size: usize) {
        Heap.dealloc(memptr, Layout::from_size_align_unchecked(size, PAGE_SIZE));
    }
}


// -- mprotect --

/// Prot enum.
#[cfg(unix)]
#[allow(non_snake_case, non_upper_case_globals)]
pub mod Prot {
    pub use ::libc::c_int as Ty;

    pub const NoAccess: Ty = ::libc::PROT_NONE;
    pub const ReadOnly: Ty = ::libc::PROT_READ;
    pub const WriteOnly: Ty = ::libc::PROT_WRITE;
    pub const ReadWrite: Ty = (::libc::PROT_READ | ::libc::PROT_WRITE);
    pub const Execute: Ty = ::libc::PROT_EXEC;
    pub const ReadExec: Ty = (::libc::PROT_READ | ::libc::PROT_EXEC);
    pub const WriteExec: Ty = (::libc::PROT_WRITE | ::libc::PROT_EXEC);
    pub const ReadWriteExec: Ty = (::libc::PROT_READ | ::libc::PROT_WRITE | ::libc::PROT_EXEC);
}

/// Prot enum.
#[cfg(windows)]
#[allow(non_snake_case, non_upper_case_globals)]
pub mod Prot {
    pub use ::winapi::shared::minwindef::DWORD as Ty;

    pub const NoAccess: Ty = ::winapi::um::winnt::PAGE_NOACCESS;
    pub const ReadOnly: Ty = ::winapi::um::winnt::PAGE_READONLY;
    pub const ReadWrite: Ty = ::winapi::um::winnt::PAGE_READWRITE;
    pub const WriteCopy: Ty = ::winapi::um::winnt::PAGE_WRITECOPY;
    pub const Execute: Ty = ::winapi::um::winnt::PAGE_EXECUTE;
    pub const ReadExec: Ty = ::winapi::um::winnt::PAGE_EXECUTE_READ;
    pub const ReadWriteExec: Ty = ::winapi::um::winnt::PAGE_EXECUTE_READWRITE;
    pub const WriteCopyExec: Ty = ::winapi::um::winnt::PAGE_EXECUTE_WRITECOPY;
    pub const Guard: Ty = ::winapi::um::winnt::PAGE_GUARD;
    pub const NoCache: Ty = ::winapi::um::winnt::PAGE_NOCACHE;
    pub const WriteCombine: Ty = ::winapi::um::winnt::PAGE_WRITECOMBINE;
    pub const RevertToFileMap: Ty = ::winapi::um::winnt::PAGE_REVERT_TO_FILE_MAP;
    pub const TargetsInvalid: Ty = ::winapi::um::winnt::PAGE_TARGETS_INVALID;

    // ::winapi::um::winnt::PAGE_TARGETS_INVALID == ::winapi::um::winnt::PAGE_TARGETS_NO_UPDATE
    // pub const TargetsNoUpdate: Ty = ::winapi::um::winnt::PAGE_TARGETS_NO_UPDATE;
}

/// Dummy Prot enum.
#[cfg(not(any(unix, windows)))]
#[allow(non_snake_case, non_upper_case_globals)]
pub mod Prot {
    #[derive(Copy, Clone)] pub struct Ty();

    pub const NoAccess: Ty = Ty();
    pub const ReadOnly: Ty = Ty();
    pub const ReadWrite: Ty = Ty();
}


/// Unix `mprotect`.
#[cfg(unix)]
#[inline]
pub unsafe fn _mprotect(ptr: *mut u8, len: usize, prot: Prot::Ty) -> bool {
    ::libc::mprotect(ptr as *mut ::libc::c_void, len, prot as ::libc::c_int) == 0
}

/// Windows `VirtualProtect`.
#[cfg(windows)]
#[inline]
pub unsafe fn _mprotect(ptr: *mut u8, len: usize, prot: Prot::Ty) -> bool {
    let mut old = mem::uninitialized();
    ::winapi::um::memoryapi::VirtualProtect(
        ptr as ::winapi::shared::minwindef::LPVOID,
        len as ::winapi::shared::basetsd::SIZE_T,
        prot as ::winapi::shared::minwindef::DWORD,
        &mut old as ::winapi::shared::minwindef::PDWORD
    ) != 0
}

#[cfg(not(any(unix, windows)))]
unsafe fn _mprotect(_: *mut u8, _: usize, _: Prot::Ty) -> bool { false }


/// Secure `mprotect`.
#[cfg(any(unix, windows))]
pub unsafe fn mprotect<T>(memptr: NonNull<T>, prot: Prot::Ty) -> bool {
    let memptr = memptr.as_ptr() as *mut u8;

    let unprotected_ptr = unprotected_ptr_from_user_ptr(memptr);
    let base_ptr = unprotected_ptr.offset(-(PAGE_SIZE as isize * 2));
    let unprotected_size = ptr::read(base_ptr as *const usize);
    _mprotect(unprotected_ptr, unprotected_size, prot)
}

/// Dummy `mprotect`.
#[cfg(not(any(unix, windows)))]
pub unsafe fn mprotect<T>(_: NonNull<T>, _: Prot::Ty) -> bool { false }


// -- malloc / free --

#[inline]
unsafe fn page_round(size: usize) -> usize {
    (size + PAGE_MASK) & !PAGE_MASK
}

#[inline]
unsafe fn unprotected_ptr_from_user_ptr(memptr: *const u8) -> *mut u8 {
    let canary_ptr = memptr.offset(-(CANARY_SIZE as isize));
    let unprotected_ptr_u = canary_ptr as usize & !PAGE_MASK;
    if unprotected_ptr_u <= PAGE_SIZE * 2 {
        abort();
    }
    unprotected_ptr_u as *mut u8
}

unsafe fn _malloc<T>() -> Option<NonNull<T>> {
    ALLOC_INIT.call_once(|| alloc_init());

    let size = mem::size_of::<T>();

    if size >= ::core::usize::MAX - PAGE_SIZE * 4 {
        return None;
    }

    // aligned alloc ptr
    let size_with_canary = CANARY_SIZE + size;
    let unprotected_size = page_round(size_with_canary);
    let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;
    let base_ptr = alloc_aligned(total_size)?.as_ptr();
    let unprotected_ptr = base_ptr.offset(PAGE_SIZE as isize * 2);

    // mprotect ptr
    _mprotect(base_ptr.offset(PAGE_SIZE as isize), PAGE_SIZE, Prot::NoAccess);

    #[cfg(not(any(unix, windows)))]
    ptr::copy_nonoverlapping(CANARY.as_ptr(), unprotected_ptr.offset(unprotected_size as isize), CANARY_SIZE);

    _mprotect(unprotected_ptr.offset(unprotected_size as isize), PAGE_SIZE, Prot::NoAccess);

    #[cfg(any(unix, windows))]
    ::mlock(unprotected_ptr, unprotected_size);

    let canary_ptr = unprotected_ptr.offset(unprotected_size as isize - size_with_canary as isize);
    let user_ptr = canary_ptr.offset(CANARY_SIZE as isize);
    ptr::copy_nonoverlapping(CANARY.as_ptr(), canary_ptr, CANARY_SIZE);
    ptr::write_unaligned(base_ptr as *mut usize, unprotected_size);
    _mprotect(base_ptr, PAGE_SIZE, Prot::ReadOnly);

    assert_eq!(unprotected_ptr_from_user_ptr(user_ptr), unprotected_ptr);

    Some(NonNull::new_unchecked(user_ptr as *mut T))
}

/// Secure `malloc`.
#[inline]
pub unsafe fn malloc<T>() -> Option<NonNull<T>> {
    _malloc()
        .map(|memptr| {
            ptr::write_bytes(memptr.as_ptr() as *mut u8, GARBAGE_VALUE, mem::size_of::<T>());
            memptr
        })
}

/// Secure `free`.
pub unsafe fn free<T>(memptr: NonNull<T>) {
    let memptr = memptr.as_ptr() as *mut u8;

    // get unprotected ptr
    let canary_ptr = memptr.offset(-(CANARY_SIZE as isize));
    let unprotected_ptr = unprotected_ptr_from_user_ptr(memptr);
    let base_ptr = unprotected_ptr.offset(-(PAGE_SIZE as isize * 2));
    let unprotected_size = ptr::read(base_ptr as *const usize);

    // check
    assert!(::memeq(canary_ptr as *const u8, CANARY.as_ptr(), CANARY_SIZE));

    #[cfg(not(any(unix, windows)))]
    assert!(::memeq(unprotected_ptr.offset(unprotected_size as isize), CANARY.as_ptr(), CANARY_SIZE));

    // free
    let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;
    _mprotect(base_ptr, total_size, Prot::ReadWrite);

    #[cfg(any(unix, windows))] ::munlock(unprotected_ptr, unprotected_size);
    #[cfg(not(any(unix, windows)))] ::memzero(unprotected_ptr, unprotected_size);

    free_aligned(base_ptr, total_size);
}
