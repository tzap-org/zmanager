//! Native URL activation, without shell command-line interpretation.
#![allow(unsafe_code)]

use std::io;
use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize};
use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub(super) fn open(url: &str) -> io::Result<()> {
    if url.contains('\0') {
        return Err(io::Error::other("invalid browser URL"));
    }
    let url = url.to_owned();
    // Other CLI libraries may already have initialized COM differently.
    std::thread::spawn(move || open_on_sta(&url)).join().map_err(|_| io::Error::other("browser launcher thread failed"))?
}

fn open_on_sta(url: &str) -> io::Result<()> {
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
    let initialized = unsafe { CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).cast_unsigned()) };
    if initialized < 0 {
        return Err(io::Error::other("browser launcher COM initialization failed"));
    }
    let _apartment = Apartment;
    let target: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let verb: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
    let mut info = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).map_err(|_| io::Error::other("invalid browser launcher structure size"))?,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: target.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    // Buffers and the COM apartment remain alive until activation returns.
    if unsafe { ShellExecuteExW(&raw mut info) } == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
