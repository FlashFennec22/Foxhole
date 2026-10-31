//! The tray icon's exit signal, shared by foxhole.exe and foxhole-tray.exe.
//!
//! Before foxhole-tray.exe can be replaced or deleted, every running tray icon (in any session)
//! has to exit. Each tray waits on a manual-reset event in the Global namespace; the (elevated)
//! installer sets it, waits for the trays to go away, then resets it. Exiting this way lets the
//! tray remove its notification-area icon, unlike killing the process.

use std::{io, mem::size_of, os::windows::io::{FromRawHandle, OwnedHandle}, ptr};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    System::Threading::{CreateEventExW, CREATE_EVENT_MANUAL_RESET},
};

const EXIT_EVENT: &str = r"Global\FoxholeTrayExit";
/// SYSTEM and Administrators may signal the event; interactive users (the trays) may only wait on it.
const EXIT_EVENT_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;IU)";

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Creates (or opens, if it already exists) the exit event, requesting `access` rights.
pub fn exit_event(access: u32) -> io::Result<OwnedHandle> {
    let sddl = wide(EXIT_EVENT_SDDL);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, ptr::null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
    let name = wide(EXIT_EVENT);
    let h = unsafe { CreateEventExW(&sa, name.as_ptr(), CREATE_EVENT_MANUAL_RESET, access) };
    let err = io::Error::last_os_error();
    unsafe { LocalFree(sd) };
    if h.is_null() {
        Err(err)
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }
}
