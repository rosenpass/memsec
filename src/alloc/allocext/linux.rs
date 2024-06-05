extern crate std;
use self::std::process::abort;
use crate::{alloc::*, Prot};
use core::mem::{self, size_of};
use core::ptr::{self, NonNull};
use core::slice;

use self::memfd_secret_alloc::*;

static MEMFD_ALLOC_INIT: Once = Once::new();

// -- alloc init --

#[inline]
unsafe fn memfd_alloc_init() {
    let mut rlimit_struct: libc::rlimit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let r = libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlimit_struct as *mut libc::rlimit);

    if r < 0 {
        //Print erno
        let err = std::io::Error::last_os_error();
        log::debug!("getrlimit errno: {:?}", err);
    }

    log::debug!("rlimit_struct: cur: {}, max: {}", rlimit_struct.rlim_cur, rlimit_struct.rlim_max);

    rlimit_struct.rlim_cur = rlimit_struct.rlim_max;

    let r = libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit_struct as *const libc::rlimit);

    if r < 0 {
        //Print erno
        let err = std::io::Error::last_os_error();
        log::debug!("setrlimit errno: {:?}", err);
    }
}

mod memfd_secret_alloc {
    use super::*;
    use core::convert::TryInto;

    #[inline]
    pub unsafe fn alloc_memfd_secret(size: usize) -> Option<(NonNull<u8>, libc::c_int)> {
        log::debug!("alloc_memfd_secret: size: {}", size);
        let fd: Result<libc::c_int, _> = libc::syscall(libc::SYS_memfd_secret, 0).try_into();

        log::debug!("syscall fd: {:?}", fd);

        if fd.is_err() {
            log::debug!("Fd is err: {:?}", fd);
        }

        if fd.unwrap() < 0 {
            //Print errno
            log::debug!("errno: {:?}", std::io::Error::last_os_error());
        }

        let fd = fd.ok().filter(|&fd| fd >= 0)?;

        log::debug!("set filesize");
        // File size is set using ftruncate
        let r = libc::ftruncate(fd, size as libc::off_t);
        log::debug!("ftruncate: {:?}", r);

        log::debug!("ptr mmap");
        let ptr = libc::mmap(
            ptr::null_mut(),
            size,
            Prot::ReadWrite,
            libc::MAP_SHARED,
            fd,
            0,
        );

        log::debug!("ptr mmap: {:?}", ptr);
        if ptr == libc::MAP_FAILED {
            log::debug!("ptr mmap failed");
            //Print errno
            let error = std::io::Error::last_os_error();
            log::debug!("errno: {:?}, raw: {}", error, error.raw_os_error().unwrap());

            if error.raw_os_error().unwrap() == libc::EAGAIN {
                for i in 0..3 {
                    log::debug!("ptr mmap retry: {}", i);

                    let ptr = libc::mmap(
                        ptr::null_mut(),
                        size,
                        Prot::ReadWrite,
                        libc::MAP_SHARED,
                        fd,
                        0,
                    );

                    log::debug!("ptr mmap: {:?}", ptr);
                    if ptr != libc::MAP_FAILED {
                        return NonNull::new(ptr as *mut u8).map(|ptr| (ptr, fd));
                    } else {
                        //Print errno
                        let error = std::io::Error::last_os_error();
                        log::debug!("errno: {:?}, raw: {}", error, error.raw_os_error().unwrap());

                        if error.raw_os_error().unwrap() != libc::EAGAIN {
                            break;
                        }
                    }
                }
            }
            return None;
        }

        NonNull::new(ptr as *mut u8).map(|ptr| (ptr, fd))
    }
}

unsafe fn _memfd_secret(size: usize) -> Option<*mut u8> {
    log::debug!("Getting page size");
    ALLOC_INIT.call_once(|| alloc_init());
    MEMFD_ALLOC_INIT.call_once(|| memfd_alloc_init());

    log::debug!("Assert");
    //Assert size of unprotected_size (usize) and fd (i32) is less than PAGE_SIZE before allocating memory
    assert!(size_of::<usize>() + size_of::<i32>() <= PAGE_SIZE);

    if size >= ::core::usize::MAX - PAGE_SIZE * 4 {
        return None;
    }

    log::debug!("calculate sizes");
    // aligned alloc ptr
    let size_with_canary = CANARY_SIZE + size;
    let unprotected_size = page_round(size_with_canary);
    let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;

    log::debug!("attempt alloc memfd_secret {} bytes", total_size);
    let (base_ptr, fd) = alloc_memfd_secret(total_size)?;

    log::debug!("set pointers");
    let base_ptr = base_ptr.as_ptr();
    let fd_ptr = base_ptr.add(size_of::<usize>());
    let unprotected_ptr = base_ptr.add(PAGE_SIZE * 2);

    log::debug!("mprotect");
    // mprotect can be used to change protection flag after mmap setup
    // https://www.gnu.org/software/libc/manual/html_node/Memory-Protection.html#index-mprotect
    _mprotect(base_ptr.add(PAGE_SIZE), PAGE_SIZE, Prot::NoAccess);
    _mprotect(
        unprotected_ptr.add(unprotected_size),
        PAGE_SIZE,
        Prot::NoAccess,
    );

    let canary_ptr = unprotected_ptr.add(unprotected_size - size_with_canary);
    let user_ptr = canary_ptr.add(CANARY_SIZE);
    ptr::copy_nonoverlapping(CANARY.as_ptr(), canary_ptr, CANARY_SIZE);
    ptr::write_unaligned(base_ptr as *mut usize, unprotected_size);
    ptr::write_unaligned(fd_ptr as *mut libc::c_int, fd);
    _mprotect(base_ptr, PAGE_SIZE, Prot::ReadOnly);

    assert_eq!(unprotected_ptr_from_user_ptr(user_ptr), unprotected_ptr);

    log::debug!("return");
    Some(user_ptr)
}

/// Linux specific `memfd_secret` backed allocation
#[inline]
pub unsafe fn memfd_secret<T>() -> Option<NonNull<T>> {
    _memfd_secret(mem::size_of::<T>()).map(|memptr| {
        ptr::write_bytes(memptr, GARBAGE_VALUE, mem::size_of::<T>());
        NonNull::new_unchecked(memptr as *mut T)
    })
}

/// Linux specific `memfd_secret` backed `sized` allocation
#[inline]
pub unsafe fn memfd_secret_sized(size: usize) -> Option<NonNull<[u8]>> {
    _memfd_secret(size).map(|memptr| {
        ptr::write_bytes(memptr, GARBAGE_VALUE, size);
        NonNull::new_unchecked(slice::from_raw_parts_mut(memptr, size))
    })
}

/// Secure `free` for memfd_secret allocations,
/// i.e. provides read write access back to mprotect guard pages
/// and unmaps mmaped secrets
pub unsafe fn free_memfd_secret<T: ?Sized>(memptr: NonNull<T>) {
    use libc::c_void;

    let memptr = memptr.as_ptr() as *mut u8;

    // get unprotected ptr
    let canary_ptr = memptr.sub(CANARY_SIZE);
    let unprotected_ptr = unprotected_ptr_from_user_ptr(memptr);
    let base_ptr = unprotected_ptr.sub(PAGE_SIZE * 2);
    let fd_ptr = base_ptr.add(size_of::<usize>()) as *mut libc::c_int;
    let unprotected_size = ptr::read(base_ptr as *const usize);
    let fd = ptr::read(fd_ptr);

    // check
    if !crate::memeq(canary_ptr as *const u8, CANARY.as_ptr(), CANARY_SIZE) {
        abort();
    }

    // free
    let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;
    _mprotect(base_ptr, total_size, Prot::ReadWrite);

    crate::memzero(unprotected_ptr, unprotected_size);

    let res = libc::munmap(base_ptr as *mut c_void, total_size);
    if res < 0 {
        abort();
    }

    let res = libc::close(fd);
    if res < 0 {
        abort();
    }
}
