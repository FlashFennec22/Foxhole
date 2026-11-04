//! Locks down %ProgramData%\Foxhole: SYSTEM and Administrators may write, other users may only read.
//!
//! The folder otherwise inherits ProgramData's ACL, which lets any user create files and folders
//! here and gives them full control of whatever they create. The SYSTEM service writes temp files
//! and renames them into place, so a file planted under a temp file's name would become the real
//! file, still writable by whoever planted it.
//!
//! `secure()` runs elevated or as SYSTEM, before anything in the folder is read or logged to. It
//! also cleans up after older versions: anything a non-administrator could have planted or
//! replaced is removed, because its contents can't be trusted.

use crate::config::data_dir;
use anyhow::{bail, Context, Result};
use std::{
    fs::{self, File, OpenOptions},
    io,
    mem::{size_of, zeroed},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
    sync::Mutex,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HANDLE},
    Security::{
        AdjustTokenPrivileges,
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        GetKernelObjectSecurity, GetSecurityDescriptorOwner, IsWellKnownSid, LookupPrivilegeValueW,
        SetKernelObjectSecurity, WinBuiltinAdministratorsSid, WinLocalSystemSid, DACL_SECURITY_INFORMATION,
        LUID_AND_ATTRIBUTES, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    },
    Storage::FileSystem::{
        CreateDirectoryW, FileDispositionInfo, GetFileInformationByHandle, SetFileInformationByHandle,
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// The folder itself: inherits nothing from ProgramData. 0x1200a9 is read and execute.
const ROOT_DACL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
/// Existing children: exactly what they would inherit from the folder.
const DIR_DACL: &str = "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)";
const FILE_DACL: &str = "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)";

/// Kept for the user to review, rather than deleted, since it may hold their own settings.
const CONFIG_NAME: &str = "config.toml";
const QUARANTINED_CONFIG: &str = "config.toml.untrusted";

/// Decides whether an existing file or folder may be kept.
type Trust<'a> = &'a dyn Fn(&Path, &File) -> bool;

/// What the cleanup did. It runs before logging can start, because the log file lives in the folder
/// being secured, so the messages wait here until `log_notes`.
static NOTES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn note(path: &Path, what: &str) {
    if let Ok(mut notes) = NOTES.lock() {
        notes.push(format!("{}: {what}", path.display()));
    }
}

/// Writes out what `secure` did. Call once logging has started.
pub fn log_notes() {
    if let Ok(mut notes) = NOTES.lock() {
        for n in notes.drain(..) {
            tracing::warn!("{n}");
        }
    }
}

/// Creates or repairs the data folder. Call this before reading or writing anything in it.
pub fn secure() -> Result<()> {
    enable_privileges();
    secure_root(&data_dir(), &|_, f| owned_by_admins(f))
}

fn secure_root(root: &Path, trust: Trust) -> Result<()> {
    // A junction here would point everything below at a folder of an attacker's choosing.
    let mut root_trusted = true;
    match open_no_follow(root) {
        Ok(f) => {
            if is_plain_dir(&file_info(&f)?) {
                root_trusted = trust(root, &f);
            } else {
                note(root, "the data folder path isn't a plain folder; removing it");
                delete(&f).context("removing what was at the data folder path")?;
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("opening {}", root.display())),
    }

    // A folder created here is locked from its first moment, by an elevated caller who owns it.
    let created = with_descriptor(ROOT_DACL, |sd| {
        let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
        sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.lpSecurityDescriptor = sd;
        let path: Vec<u16> = root.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { CreateDirectoryW(path.as_ptr(), &sa) } != 0 {
            return Ok(true);
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            return Ok(false);
        }
        Err(io::Error::last_os_error())
    })
    .with_context(|| format!("creating {}", root.display()))?;
    if created {
        return Ok(());
    }

    // Lock the folder first, so nothing new can appear while we go through what's in it. Using a
    // handle we've checked means this can't be redirected, and unlike SetNamedSecurityInfo it
    // doesn't propagate to children, which could otherwise reach through a junction.
    let f = open_no_follow(root).with_context(|| format!("opening {}", root.display()))?;
    if !is_plain_dir(&file_info(&f)?) {
        bail!("{} isn't a plain folder", root.display());
    }
    set_descriptor(&f, ROOT_DACL).with_context(|| format!("securing {}", root.display()))?;
    drop(f);

    secure_children(root, root_trusted, trust)
}

fn secure_children(dir: &Path, parent_trusted: bool, trust: Trust) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let path = entry?.path();
        secure_entry(&path, parent_trusted, trust).with_context(|| format!("securing {}", path.display()))?;
    }
    Ok(())
}

fn secure_entry(path: &Path, parent_trusted: bool, trust: Trust) -> Result<()> {
    let f = match open_no_follow(path) {
        Ok(f) => f,
        // The running service renames its temp files, so an entry can legitimately vanish.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let info = file_info(&f)?;

    // Never change the ACL of a link: that would change the ACL of whatever it points to.
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.nNumberOfLinks > 1 {
        note(path, "removing a link planted in the data folder");
        return delete(&f).map_err(Into::into);
    }

    // Everything inside an untrusted folder is untrusted too: its owner could rewrite it.
    let trusted = parent_trusted && trust(path, &f);
    let is_dir = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    set_descriptor(&f, if is_dir { DIR_DACL } else { FILE_DACL })?;

    if is_dir {
        secure_children(path, trusted, trust)?;
    }
    if !trusted {
        note(path, "not created by Foxhole or an administrator; not using it");
        if !is_dir && path.file_name().is_some_and(|n| n == CONFIG_NAME) {
            drop(f);
            fs::rename(path, path.with_file_name(QUARANTINED_CONFIG))?;
        } else {
            delete(&f)?;
        }
    }
    Ok(())
}

/// Marks a file, folder or link for deletion when `f` closes. Works through the handle, so it can't
/// be redirected and never touches what a link points to. A folder must be empty by then.
fn delete(f: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    let size = size_of::<FILE_DISPOSITION_INFO>() as u32;
    let handle = f.as_raw_handle() as HANDLE;
    if unsafe { SetFileInformationByHandle(handle, FileDispositionInfo, ptr::from_ref(&info).cast(), size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn is_plain_dir(info: &BY_HANDLE_FILE_INFORMATION) -> bool {
    info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

/// Opens the file, folder or link itself. Backup semantics let an elevated caller get past a DACL
/// that denies administrators, which the owner of a planted file can set.
fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

fn file_info(f: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(f.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// True if owned by SYSTEM or Administrators. Other users can't assign either as an owner. Anything
/// unreadable counts as not trusted.
fn owned_by_admins(f: &File) -> bool {
    let handle = f.as_raw_handle() as HANDLE;
    let mut needed = 0;
    unsafe { GetKernelObjectSecurity(handle, OWNER_SECURITY_INFORMATION, ptr::null_mut(), 0, &mut needed) };
    // u64 storage keeps the buffer aligned, as a security descriptor requires.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let sd: PSECURITY_DESCRIPTOR = buf.as_mut_ptr().cast();
    if unsafe { GetKernelObjectSecurity(handle, OWNER_SECURITY_INFORMATION, sd, needed, &mut needed) } == 0 {
        return false;
    }
    let mut owner: PSID = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) } == 0 || owner.is_null() {
        return false;
    }
    unsafe { IsWellKnownSid(owner, WinLocalSystemSid) != 0 || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0 }
}

fn with_descriptor<T>(sddl: &str, f: impl FnOnce(PSECURITY_DESCRIPTOR) -> io::Result<T>) -> io::Result<T> {
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, ptr::null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let r = f(sd);
    unsafe { LocalFree(sd) };
    r
}

/// Applies `dacl` and makes Administrators the owner. Handle-based, so it affects only this object.
fn set_descriptor(f: &File, dacl: &str) -> io::Result<()> {
    with_descriptor(&format!("O:BA{dacl}"), |sd| {
        // Unelevated test runs can't assign an owner; they still exercise everything else.
        let owner = if cfg!(test) && !crate::winctl::is_admin() { 0 } else { OWNER_SECURITY_INFORMATION };
        if unsafe { SetKernelObjectSecurity(f.as_raw_handle() as HANDLE, owner | DACL_SECURITY_INFORMATION, sd) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
}

/// Best effort: without these, a planted file whose DACL shuts out administrators stays out of reach
/// and `secure()` reports an error instead.
fn enable_privileges() {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == 0 {
            return;
        }
        for name in ["SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"] {
            let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: zeroed(), Attributes: SE_PRIVILEGE_ENABLED }],
            };
            if LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut tp.Privileges[0].Luid) != 0 {
                AdjustTokenPrivileges(token, 0, &tp, 0, ptr::null_mut(), ptr::null_mut());
            }
        }
        CloseHandle(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::PathBuf, process::Command};

    /// A scratch tree, unlocked again on drop so it can be deleted.
    struct Tree(PathBuf);

    impl Tree {
        fn new(name: &str) -> Self {
            let base = std::env::temp_dir().join(format!("foxhole-datadir-{name}-{}", std::process::id()));
            let t = Tree(base);
            t.unlock();
            let _ = fs::remove_dir_all(&t.0);
            fs::create_dir_all(t.root().join("lists")).unwrap();
            t
        }
        fn root(&self) -> PathBuf {
            self.0.join("Foxhole")
        }
        fn unlock(&self) {
            // S-1-1-0 is Everyone. We own these files, so this works without elevation.
            let _ = Command::new("icacls").arg(&self.0).args(["/grant", "*S-1-1-0:(OI)(CI)F", "/T", "/Q", "/C"]).output();
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            self.unlock();
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sddl(path: &Path) -> String {
        let script = format!("(Get-Acl -LiteralPath '{}').Sddl", path.display());
        let out = Command::new("powershell").args(["-NoProfile", "-Command", &script]).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Reads the ACL rather than trying a write, so it means the same thing in an elevated test
    /// run, where this process is an administrator and is meant to have write access.
    fn assert_only_admins_can_write(path: &Path) {
        let s = sddl(path);
        let dacl = s.split_once("D:").unwrap_or_else(|| panic!("no DACL: {s}")).1;
        for ace in dacl.split('(').skip(1) {
            let ace = ace.trim_end_matches(')');
            let admin = ace.ends_with(";;;SY") || ace.ends_with(";;;BA");
            let read_only_users = ace.ends_with(";0x1200a9;;;BU");
            assert!(admin || read_only_users, "{} has an unexpected entry: {ace}", path.display());
        }
    }

    /// Stands in for the owner check, which needs real Administrators-owned files.
    fn trust_all_but(names: &'static [&'static str]) -> impl Fn(&Path, &File) -> bool {
        move |p, _| !names.iter().any(|n| p.file_name().is_some_and(|f| f == *n))
    }

    #[test]
    fn locks_the_folder_and_keeps_trusted_files() {
        let t = Tree::new("lock");
        let root = t.root();
        fs::write(root.join("config.toml"), "keep").unwrap();
        fs::write(root.join("lists").join("a.txt"), "keep").unwrap();

        secure_root(&root, &trust_all_but(&[])).unwrap();

        let d = sddl(&root);
        assert!(d.contains("D:P"), "not protected from inheritance: {d}");
        for dir in [root.clone(), root.join("lists")] {
            assert_only_admins_can_write(&dir);
            if !crate::winctl::is_admin() {
                let e = fs::write(dir.join("planted.tmp"), "x").unwrap_err();
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{}", dir.display());
                assert!(fs::create_dir(dir.join("planted-dir")).is_err());
            }
        }
        for f in [root.join("config.toml"), root.join("lists").join("a.txt")] {
            assert_only_admins_can_write(&f);
            assert_eq!(fs::read_to_string(&f).unwrap(), "keep");
            if !crate::winctl::is_admin() {
                assert!(OpenOptions::new().append(true).open(&f).is_err(), "{}", f.display());
            }
        }
    }

    #[test]
    fn creates_a_locked_folder_on_a_fresh_install() {
        let t = Tree::new("fresh");
        let root = t.0.join("New");
        secure_root(&root, &trust_all_but(&[])).unwrap();
        assert!(root.is_dir());
        assert!(sddl(&root).contains("D:P"));
        assert_only_admins_can_write(&root);
        if !crate::winctl::is_admin() {
            assert!(fs::write(root.join("x"), "x").is_err());
        }
    }

    #[test]
    fn removes_planted_files_and_folders() {
        let t = Tree::new("planted");
        let root = t.root();
        fs::write(root.join("config.toml"), "keep").unwrap();
        fs::write(root.join("dns-state.json"), "forged").unwrap();
        fs::write(root.join("lists").join("a.tmp"), "forged").unwrap();
        // A folder under a temp file's name would make every later write fail.
        fs::create_dir(root.join("dns-state.tmp")).unwrap();
        fs::write(root.join("dns-state.tmp").join("inner"), "x").unwrap();

        secure_root(&root, &trust_all_but(&["dns-state.json", "a.tmp", "dns-state.tmp"])).unwrap();

        assert!(root.join("config.toml").exists());
        assert!(root.join("lists").exists());
        assert!(!root.join("dns-state.json").exists());
        assert!(!root.join("lists").join("a.tmp").exists());
        assert!(!root.join("dns-state.tmp").exists());

        let notes = NOTES.lock().unwrap();
        assert!(notes.iter().any(|n| n.contains("dns-state.json")), "{notes:?}");
    }

    /// Renaming inside the locked folder needs real administrator rights.
    #[test]
    #[ignore = "run from an elevated prompt"]
    fn quarantines_an_untrusted_config() {
        let t = Tree::new("config");
        let root = t.root();
        fs::write(root.join("config.toml"), "planted").unwrap();
        secure_root(&root, &trust_all_but(&["config.toml"])).unwrap();
        assert!(!root.join("config.toml").exists());
        assert_eq!(fs::read_to_string(root.join(QUARANTINED_CONFIG)).unwrap(), "planted");
    }

    #[test]
    fn everything_inside_an_untrusted_folder_is_untrusted() {
        let t = Tree::new("nested");
        let root = t.root();
        fs::write(root.join("lists").join("a.txt"), "x").unwrap();
        secure_root(&root, &trust_all_but(&["lists"])).unwrap();
        assert!(!root.join("lists").exists());
    }

    #[test]
    #[ignore = "run from an elevated prompt"]
    fn a_squatted_root_taints_its_contents() {
        let t = Tree::new("squat");
        let root = t.root();
        fs::write(root.join("config.toml"), "planted").unwrap();
        fs::write(root.join("dns-state.json"), "forged").unwrap();
        secure_root(&root, &trust_all_but(&["Foxhole"])).unwrap();
        assert!(sddl(&root).contains("D:P"));
        assert!(!root.join("config.toml").exists());
        assert!(root.join(QUARANTINED_CONFIG).exists());
        assert!(!root.join("dns-state.json").exists());
    }

    #[test]
    fn removes_links_without_touching_their_targets() {
        let t = Tree::new("links");
        let root = t.root();
        let outside = t.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("victim"), "safe").unwrap();
        fs::write(t.0.join("hard-victim"), "safe").unwrap();
        let (before_dir, before_hard) = (sddl(&outside), sddl(&t.0.join("hard-victim")));

        let junction = root.join("dns-state.tmp");
        let status = Command::new("cmd").arg("/c").arg("mklink").arg("/J").arg(&junction).arg(&outside).output().unwrap();
        assert!(status.status.success(), "{status:?}");
        fs::hard_link(t.0.join("hard-victim"), root.join("stats.tmp")).unwrap();

        secure_root(&root, &trust_all_but(&[])).unwrap();

        assert!(fs::symlink_metadata(&junction).is_err(), "junction still there");
        assert!(!root.join("stats.tmp").exists(), "hard link still there");
        assert_eq!(fs::read_to_string(outside.join("victim")).unwrap(), "safe");
        assert_eq!(fs::read_to_string(t.0.join("hard-victim")).unwrap(), "safe");
        assert_eq!(sddl(&outside), before_dir, "the junction's target ACL changed");
        assert_eq!(sddl(&t.0.join("hard-victim")), before_hard, "the hard link's target ACL changed");
    }

    #[test]
    fn replaces_a_junction_at_the_root_without_touching_its_target() {
        let t = Tree::new("rootlink");
        let outside = t.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("victim"), "safe").unwrap();
        let before = sddl(&outside);
        let root = t.0.join("Linked");
        let status = Command::new("cmd").arg("/c").arg("mklink").arg("/J").arg(&root).arg(&outside).output().unwrap();
        assert!(status.status.success(), "{status:?}");

        secure_root(&root, &trust_all_but(&[])).unwrap();

        assert!(root.is_dir());
        assert!(!root.join("victim").exists(), "still follows the junction");
        assert!(sddl(&root).contains("D:P"));
        assert_eq!(fs::read_to_string(outside.join("victim")).unwrap(), "safe");
        assert_eq!(sddl(&outside), before, "the junction's target ACL changed");
    }

    /// Unelevated, a new file is owned by the user; elevated, by Administrators.
    #[test]
    fn real_owner_check_matches_the_current_token() {
        let t = Tree::new("owner");
        let p = t.root().join("mine");
        fs::write(&p, "x").unwrap();
        let f = OpenOptions::new().access_mode(READ_CONTROL).open(&p).unwrap();
        assert_eq!(owned_by_admins(&f), crate::winctl::is_admin());
    }
}
