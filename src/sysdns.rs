//! Points Windows' adapters at 127.0.0.1 / ::1 and restores them afterwards.
//!
//! Uses the IP Helper API directly (GetAdaptersAddresses, Get/SetInterfaceDnsSettings; Windows 10
//! 2004+). The original per-adapter *static* DNS servers are saved to
//! %ProgramData%\Foxhole\dns-state.json *before* any change, so `restore()` also works after a crash
//! or from `foxhole off`. An empty saved list means "the adapter used DHCP".

#[cfg(windows)]
pub use win::{apply, restore, Watcher};
#[cfg(not(windows))]
pub use stub::{apply, restore, Watcher};

#[cfg(not(windows))]
mod stub {
    pub fn apply(_ipv6: bool) -> anyhow::Result<()> { Ok(()) }
    pub fn restore() -> anyhow::Result<()> { Ok(()) }

    /// Never fires: there are no adapters to manage off Windows.
    pub struct Watcher(tokio::sync::Notify);
    impl Watcher {
        pub fn new() -> anyhow::Result<Self> { Ok(Self(tokio::sync::Notify::new())) }
        pub async fn changed(&self) { self.0.notified().await }
    }
}

#[cfg(windows)]
mod win {
    use crate::config::data_dir;
    use anyhow::{bail, Context, Result};
    use serde::{Deserialize, Serialize};
    use std::{ffi::c_void, path::PathBuf, ptr, sync::Arc};
    use tokio::sync::Notify;
    use tracing::{info, warn};
    use windows_sys::{
        core::GUID,
        Win32::{
            Foundation::{ERROR_BUFFER_OVERFLOW, HANDLE, NO_ERROR},
            NetworkManagement::{
                IpHelper::{
                    CancelMibChangeNotify2, FreeInterfaceDnsSettings, GetAdaptersAddresses, GetInterfaceDnsSettings,
                    NotifyIpInterfaceChange, NotifyUnicastIpAddressChange, SetInterfaceDnsSettings,
                    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
                    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
                    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH, MIB_IPINTERFACE_ROW,
                    MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
                },
                Ndis::IfOperStatusUp,
            },
            Networking::WinSock::AF_UNSPEC,
        },
    };

    const OURS_V4: &str = "127.0.0.1";
    const OURS_V6: &str = "::1";

    #[link(name = "dnsapi", kind = "raw-dylib")]
    extern "system" {
        /// Undocumented but stable since Windows 2000; it is what `ipconfig /flushdns` calls.
        fn DnsFlushResolverCache() -> i32;
    }

    #[derive(Serialize, Deserialize, Clone)]
    struct Saved {
        /// Interface GUID, e.g. "{4D36E972-...}". Stable across reboots, unlike `index`.
        /// Empty in state files written by older versions, which only stored the index.
        #[serde(default)]
        guid: String,
        index: u32,
        name: String,
        /// Static IPv4 DNS servers the adapter had before. Empty = it used DHCP.
        original: Vec<String>,
        /// Static IPv6 DNS servers before, if we replaced them. None = IPv6 DNS was left alone.
        #[serde(default)]
        original_v6: Option<Vec<String>>,
    }

    struct Adapter {
        index: u32,
        guid_str: String,
        guid: GUID,
        name: String,
    }

    fn state_path() -> PathBuf {
        data_dir().join("dns-state.json")
    }

    fn load_state() -> Vec<Saved> {
        std::fs::read_to_string(state_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    fn save_state(saved: &[Saved]) -> Result<()> {
        if saved.is_empty() {
            let _ = std::fs::remove_file(state_path());
            return Ok(());
        }
        std::fs::create_dir_all(data_dir())?;
        std::fs::write(state_path(), serde_json::to_string_pretty(saved)?).context("writing dns-state.json")
    }

    fn parse_guid(s: &str) -> Option<GUID> {
        let hex: String = s.chars().filter(|c| !matches!(c, '{' | '}' | '-')).collect();
        if hex.len() != 32 {
            return None;
        }
        u128::from_str_radix(&hex, 16).ok().map(GUID::from_u128)
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    unsafe fn from_wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }

    /// Adapters that are up, excluding loopback and tunnel pseudo-interfaces.
    fn adapters() -> Result<Vec<Adapter>> {
        let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 16 * 1024;
        for _ in 0..4 {
            // u64 storage keeps the buffer 8-byte aligned, as IP_ADAPTER_ADDRESSES requires.
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            let first = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let rc = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, ptr::null(), first, &mut size) };
            if rc == ERROR_BUFFER_OVERFLOW {
                continue; // `size` now holds the required length
            }
            if rc != NO_ERROR {
                bail!("GetAdaptersAddresses failed: error {rc}");
            }
            let mut out = Vec::new();
            let mut p = first;
            while !p.is_null() {
                let a = unsafe { &*p };
                p = a.Next;
                if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == IF_TYPE_TUNNEL {
                    continue;
                }
                let guid_str = unsafe { std::ffi::CStr::from_ptr(a.AdapterName.cast()) }.to_string_lossy().into_owned();
                let Some(guid) = parse_guid(&guid_str) else { continue };
                out.push(Adapter {
                    index: unsafe { a.Anonymous1.Anonymous.IfIndex },
                    guid_str,
                    guid,
                    name: unsafe { from_wide(a.FriendlyName) },
                });
            }
            return Ok(out);
        }
        bail!("GetAdaptersAddresses kept asking for a bigger buffer")
    }

    fn family_flag(v6: bool) -> u64 {
        if v6 { DNS_SETTING_IPV6 as u64 } else { 0 }
    }

    /// The adapter's *static* DNS servers for one address family (empty = DHCP / automatic).
    fn get_static(guid: GUID, v6: bool) -> Result<Vec<String>> {
        let mut s: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
        s.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        s.Flags = DNS_SETTING_NAMESERVER as u64 | family_flag(v6);
        let rc = unsafe { GetInterfaceDnsSettings(guid, &mut s) };
        if rc != NO_ERROR {
            bail!("GetInterfaceDnsSettings failed: error {rc}");
        }
        let servers = unsafe { from_wide(s.NameServer) };
        unsafe { FreeInterfaceDnsSettings(&mut s) };
        Ok(servers.split([',', ' ']).filter(|x| !x.is_empty()).map(String::from).collect())
    }

    /// Replaces the adapter's static DNS servers for one family. An empty list means DHCP / automatic.
    fn set_static(guid: GUID, v6: bool, servers: &[String]) -> Result<()> {
        // Only IP literals are ever written (never the contents of a corrupted state file).
        let list: Vec<&str> = servers.iter().map(String::as_str).filter(|s| s.parse::<std::net::IpAddr>().is_ok()).collect();
        let mut text = wide(&list.join(","));
        let mut s: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
        s.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        s.Flags = DNS_SETTING_NAMESERVER as u64 | family_flag(v6);
        s.NameServer = text.as_mut_ptr();
        let rc = unsafe { SetInterfaceDnsSettings(guid, &s) };
        if rc != NO_ERROR {
            bail!("SetInterfaceDnsSettings failed: error {rc}");
        }
        Ok(())
    }

    fn without(servers: Vec<String>, ours: &str) -> Vec<String> {
        servers.into_iter().filter(|s| s != ours).collect()
    }

    fn flush() {
        unsafe { DnsFlushResolverCache() };
    }

    /// Idempotent: only touches adapters that don't already point (only) at us.
    pub fn apply(ipv6: bool) -> Result<()> {
        let mut saved = load_state();
        let mut todo = Vec::new();
        for a in adapters()? {
            let current = || -> Result<_> {
                Ok((get_static(a.guid, false)?, if ipv6 { Some(get_static(a.guid, true)?) } else { None }))
            };
            let (v4, v6) = match current() {
                Ok(c) => c,
                Err(e) => { warn!(adapter = %a.name, error = %e, "could not read DNS settings"); continue; }
            };
            let set_v4 = v4 != [OURS_V4];
            let set_v6 = v6.as_ref().is_some_and(|v| v != &[OURS_V6]);
            if !set_v4 && !set_v6 {
                continue;
            }
            // Whatever is configured now (minus our own addresses) is the user's setting: remember it.
            let i = match saved.iter().position(|s| s.guid == a.guid_str || (s.guid.is_empty() && s.index == a.index)) {
                Some(i) => i,
                None => {
                    saved.push(Saved { guid: a.guid_str.clone(), index: a.index, name: a.name.clone(), original: vec![], original_v6: None });
                    saved.len() - 1
                }
            };
            let s = &mut saved[i];
            s.guid = a.guid_str.clone();
            s.index = a.index;
            if set_v4 {
                s.original = without(v4, OURS_V4);
            }
            if let (true, Some(v6)) = (set_v6, v6) {
                s.original_v6 = Some(without(v6, OURS_V6));
            }
            todo.push((a, set_v4, set_v6));
        }
        if todo.is_empty() {
            return Ok(());
        }

        // Save originals first, so a crash mid-way can still be undone.
        save_state(&saved)?;
        for (a, set_v4, set_v6) in &todo {
            let mut r = Ok(());
            if *set_v4 { r = set_static(a.guid, false, &[OURS_V4.into()]); }
            if *set_v6 && r.is_ok() { r = set_static(a.guid, true, &[OURS_V6.into()]); }
            match r {
                Ok(()) => info!(adapter = %a.name, "DNS now points at Foxhole"),
                Err(e) => warn!(adapter = %a.name, error = %e, "could not set DNS"),
            }
        }
        flush();
        Ok(())
    }

    pub fn restore() -> Result<()> {
        let live = adapters().unwrap_or_default();
        let mut failed = Vec::new();
        for s in load_state() {
            // State files from older versions only have the interface index.
            let guid = parse_guid(&s.guid).or_else(|| live.iter().find(|a| a.index == s.index).map(|a| a.guid));
            let Some(guid) = guid else {
                warn!(adapter = %s.name, "adapter not present; will retry restoring it later");
                failed.push(s);
                continue;
            };
            let r = set_static(guid, false, &s.original)
                .and_then(|_| s.original_v6.as_ref().map_or(Ok(()), |v6| set_static(guid, true, v6)));
            match r {
                Ok(()) => info!(adapter = %s.name, "DNS restored"),
                Err(e) => { warn!(adapter = %s.name, error = %e, "could not restore DNS"); failed.push(s); }
            }
        }
        // Safety sweep: nothing may be left pointing at loopback (e.g. the state file was lost),
        // or the machine would be left with a dead resolver once we stop.
        for a in &live {
            for (v6, ours) in [(false, OURS_V4), (true, OURS_V6)] {
                let Ok(cur) = get_static(a.guid, v6) else { continue };
                if cur.iter().any(|s| s == ours) {
                    match set_static(a.guid, v6, &without(cur, ours)) {
                        Ok(()) => info!(adapter = %a.name, ipv6 = v6, "removed leftover loopback DNS server"),
                        Err(e) => warn!(adapter = %a.name, error = %e, "could not reset DNS"),
                    }
                }
            }
        }
        save_state(&failed)?;
        flush();
        Ok(())
    }

    /// Wakes up whenever an IP interface or address changes (adapter connected, Wi-Fi switch, VPN up,
    /// DHCP lease, ...), so new adapters are pointed at us right away instead of on the next poll.
    pub struct Watcher {
        notify: Arc<Notify>,
        handles: Vec<HANDLE>,
    }

    // The handles are only used to cancel the registrations, which is thread-safe.
    unsafe impl Send for Watcher {}
    unsafe impl Sync for Watcher {}

    unsafe extern "system" fn on_interface(ctx: *const c_void, _: *const MIB_IPINTERFACE_ROW, _: MIB_NOTIFICATION_TYPE) {
        (*(ctx as *const Notify)).notify_one();
    }

    unsafe extern "system" fn on_address(ctx: *const c_void, _: *const MIB_UNICASTIPADDRESS_ROW, _: MIB_NOTIFICATION_TYPE) {
        (*(ctx as *const Notify)).notify_one();
    }

    impl Watcher {
        pub fn new() -> Result<Self> {
            let mut w = Watcher { notify: Arc::new(Notify::new()), handles: Vec::new() };
            let ctx = Arc::as_ptr(&w.notify) as *const c_void;
            let mut h: HANDLE = ptr::null_mut();
            let rc = unsafe { NotifyIpInterfaceChange(AF_UNSPEC, Some(on_interface), ctx, 0, &mut h) };
            if rc != NO_ERROR {
                bail!("NotifyIpInterfaceChange failed: error {rc}");
            }
            w.handles.push(h);
            let mut h: HANDLE = ptr::null_mut();
            let rc = unsafe { NotifyUnicastIpAddressChange(AF_UNSPEC, Some(on_address), ctx, 0, &mut h) };
            if rc != NO_ERROR {
                bail!("NotifyUnicastIpAddressChange failed: error {rc}"); // Drop cancels the first one
            }
            w.handles.push(h);
            Ok(w)
        }

        pub async fn changed(&self) {
            self.notify.notified().await
        }
    }

    impl Drop for Watcher {
        fn drop(&mut self) {
            // Blocks until any running callback has returned, so `notify` outlives every use of `ctx`.
            for h in self.handles.drain(..) {
                unsafe { CancelMibChangeNotify2(h) };
            }
        }
    }
}
