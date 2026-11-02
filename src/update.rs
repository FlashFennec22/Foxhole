//! Update checks against the project's GitHub releases, used by the tray icon.
//!
//! Everything here runs as the signed-in user (the tray is unelevated): ask GitHub for the latest
//! release, and only once the user agrees, download its installer, check it against the SHA-256
//! digest GitHub publishes for every release asset, and start it. The installer asks for
//! administrator rights itself (UAC), so Windows has the final word, not this code.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::ERROR_CANCELLED,
    System::Threading::{WaitForSingleObject, INFINITE},
    UI::{
        Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

const LATEST_URL: &str = "https://api.github.com/repos/FlashFennec22/Foxhole/releases/latest";
/// Installers are only downloaded from, and pages only opened under, this repository's releases.
const DOWNLOAD_PREFIX: &str = "https://github.com/FlashFennec22/Foxhole/releases/download/";
const PAGE_PREFIX: &str = "https://github.com/FlashFennec22/Foxhole/releases/";
const MAX_INSTALLER_BYTES: u64 = 100 * 1024 * 1024;
/// Release notes longer than this are cut short in the prompt (the release page has the rest).
const MAX_NOTES_CHARS: usize = 600;
/// From fileapi.h; windows-sys only has it behind a feature we don't otherwise need.
const FILE_SHARE_READ: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u64, u64, u64);

impl Version {
    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).expect("crate version is x.y.z")
    }

    /// Finds the first `x.y` or `x.y.z` in `s`, so tags like `v0.2.0` and `Foxhole0.1.1` both work.
    pub fn parse(s: &str) -> Option<Self> {
        let rest = &s[s.find(|c: char| c.is_ascii_digit())?..];
        let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
        let mut parts = rest[..end].trim_end_matches('.').split('.').map(|p| p.parse::<u64>().ok());
        let major = parts.next()??;
        let minor = parts.next()??;
        let patch = parts.next().unwrap_or(Some(0))?;
        if parts.next().is_some() {
            return None;
        }
        Some(Version(major, minor, patch))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[derive(Clone, Debug)]
pub struct Release {
    pub version: Version,
    /// Start of the release notes, for the prompt.
    pub notes: String,
    /// The release's page on GitHub.
    pub page: String,
    /// None if the release has no installer exe with a published digest; the user then gets the page instead.
    pub installer: Option<Asset>,
}

#[derive(Clone, Debug)]
pub struct Asset {
    url: String,
    size: u64,
    /// Lowercase hex.
    sha256: String,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    /// "sha256:<hex>"; GitHub computes it for every uploaded asset.
    digest: Option<String>,
}

fn client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("foxhole-tray/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// The latest published release (GitHub's `latest` never returns drafts or pre-releases).
pub fn latest() -> Result<Release> {
    let body = client(Duration::from_secs(20))?
        .get(LATEST_URL)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .and_then(|r| r.error_for_status())
        .context("asking GitHub for the latest release")?
        .bytes()?;
    parse_release(&body)
}

fn parse_release(json: &[u8]) -> Result<Release> {
    let r: ApiRelease = serde_json::from_slice(json).context("unexpected reply from GitHub")?;
    if r.draft || r.prerelease {
        bail!("the latest release is a draft or pre-release");
    }
    let version = Version::parse(&r.tag_name)
        .or_else(|| r.name.as_deref().and_then(Version::parse))
        .with_context(|| format!("release {:?} has no version number", r.tag_name))?;
    if !r.html_url.starts_with(PAGE_PREFIX) {
        bail!("unexpected release page {}", r.html_url);
    }
    let installer = r.assets.into_iter().find_map(|a| {
        let name = a.name.to_ascii_lowercase();
        if !(name.starts_with("foxhole-setup") && name.ends_with(".exe") && a.browser_download_url.starts_with(DOWNLOAD_PREFIX)) {
            return None;
        }
        let sha256 = a.digest?.strip_prefix("sha256:")?.to_ascii_lowercase();
        (sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()))
            .then_some(Asset { url: a.browser_download_url, size: a.size, sha256 })
    });
    let notes = r.body.unwrap_or_default().replace('\r', "");
    let notes = notes.trim();
    let notes = match notes.char_indices().nth(MAX_NOTES_CHARS) {
        Some((cut, _)) => format!("{}…", notes[..cut].trim_end()),
        None => notes.to_string(),
    };
    Ok(Release { version, notes, page: r.html_url, installer })
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// A downloaded, verified installer. The file stays open without write or delete sharing, so
/// nothing can swap it between the checksum check and Setup reading it.
pub struct Installer {
    path: PathBuf,
    _lock: File,
}

/// Downloads the release's installer into `dir` (replacing older downloads) and verifies it.
pub fn download(release: &Release, dir: &Path) -> Result<Installer> {
    let asset = release.installer.as_ref().context("this release has no installer to download")?;
    if asset.size > MAX_INSTALLER_BYTES {
        bail!("the installer is unexpectedly large ({} bytes)", asset.size);
    }
    let mut resp = client(Duration::from_secs(600))?
        .get(&asset.url)
        .send()
        .and_then(|r| r.error_for_status())
        .context("downloading the installer")?;
    let mut data = Vec::with_capacity(asset.size as usize);
    (&mut resp).take(MAX_INSTALLER_BYTES + 1).read_to_end(&mut data).context("downloading the installer")?;
    if data.len() as u64 != asset.size {
        bail!("the download was incomplete ({} of {} bytes)", data.len(), asset.size);
    }
    if sha256_hex(&data) != asset.sha256 {
        bail!("the download doesn't match the checksum GitHub published for it");
    }

    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    // Older downloads are no longer needed (best effort: one may still be open).
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
    // Our own name, not the asset's: the file name never comes from the network.
    let path = dir.join(format!("Foxhole-Setup-{}.exe", release.version));
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .share_mode(0)
        .open(&path)
        .and_then(|mut f| f.write_all(&data))
        .with_context(|| format!("saving {}", path.display()))?;
    // Reopen read-only, refusing write/delete sharing, and check what actually landed on disk.
    let mut lock = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(&path)?;
    let mut on_disk = Vec::with_capacity(data.len());
    lock.read_to_end(&mut on_disk)?;
    if sha256_hex(&on_disk) != asset.sha256 {
        bail!("the saved installer doesn't match the download");
    }
    Ok(Installer { path, _lock: lock })
}

impl Installer {
    /// Starts the installer (Windows shows the UAC prompt) and waits for it to finish, keeping the
    /// file locked until then. Returns false if the user declined the UAC prompt. On success the
    /// installer closes every tray icon, this one included, before replacing the files.
    pub fn run(self) -> Result<bool> {
        let process = match shell_execute(self.path.as_os_str(), "/SILENT") {
            Ok(p) => p,
            Err(e) if e.raw_os_error() == Some(ERROR_CANCELLED as i32) => return Ok(false),
            Err(e) => return Err(e).context("starting the installer"),
        };
        if let Some(p) = process {
            unsafe { WaitForSingleObject(p.as_raw_handle(), INFINITE) };
        }
        Ok(true)
    }
}

/// Opens a release page in the default browser.
pub fn open_page(url: &str) -> Result<()> {
    if !url.starts_with(PAGE_PREFIX) {
        bail!("refusing to open unexpected address {url}");
    }
    shell_execute(OsStr::new(url), "").context("opening the release page")?;
    Ok(())
}

/// ShellExecuteEx "open", like winctl's (which lives in foxhole.exe, not the tray).
fn shell_execute(file: &OsStr, params: &str) -> io::Result<Option<OwnedHandle>> {
    let file: Vec<u16> = file.encode_wide().chain(Some(0)).collect();
    let params = crate::trayctl::wide(params);
    let verb = crate::trayctl::wide("open");
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((!info.hProcess.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(info.hProcess) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions_from_tags_and_names() {
        assert_eq!(Version::parse("v0.2.0"), Some(Version(0, 2, 0)));
        assert_eq!(Version::parse("Foxhole0.1.1"), Some(Version(0, 1, 1)));
        assert_eq!(Version::parse("Release 0.1.0"), Some(Version(0, 1, 0)));
        assert_eq!(Version::parse("1.4"), Some(Version(1, 4, 0)));
        assert_eq!(Version::parse("v1.2.3-beta.1"), Some(Version(1, 2, 3)));
        assert_eq!(Version::parse("Releases"), None);
        assert_eq!(Version::parse("2026"), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
        assert!(Version(0, 10, 0) > Version(0, 9, 9));
        assert!(Version(1, 0, 0) > Version(0, 99, 99));
    }

    fn release_json(tag: &str, assets: &str) -> String {
        format!(
            r#"{{"tag_name":"{tag}","name":"Release","body":"Notes\r\nline two","draft":false,"prerelease":false,
               "html_url":"https://github.com/FlashFennec22/Foxhole/releases/tag/{tag}","assets":[{assets}]}}"#
        )
    }

    const DIGEST: &str = "sha256:A4265201979B3A8BFB16A2B7B31D9577BBE48338462419FB52DBE73EB041113A";

    #[test]
    fn picks_the_installer_exe_with_a_digest() {
        let assets = format!(
            r#"{{"name":"Foxhole-Setup-0.2.0.zip","size":5,"digest":"{DIGEST}",
                 "browser_download_url":"https://github.com/FlashFennec22/Foxhole/releases/download/v0.2.0/Foxhole-Setup-0.2.0.zip"}},
               {{"name":"Foxhole-Setup-0.2.0.exe","size":7,"digest":"{DIGEST}",
                 "browser_download_url":"https://github.com/FlashFennec22/Foxhole/releases/download/v0.2.0/Foxhole-Setup-0.2.0.exe"}}"#
        );
        let r = parse_release(release_json("v0.2.0", &assets).as_bytes()).unwrap();
        assert_eq!(r.version, Version(0, 2, 0));
        assert_eq!(r.notes, "Notes\nline two");
        let a = r.installer.unwrap();
        assert!(a.url.ends_with(".exe"));
        assert_eq!(a.size, 7);
        assert_eq!(a.sha256, DIGEST[7..].to_ascii_lowercase());
    }

    #[test]
    fn no_installer_without_exe_digest_or_trusted_url() {
        let cases = [
            // zip only, like the 0.1.x releases
            format!(r#"{{"name":"Foxhole-Setup-0.1.1.zip","size":5,"digest":"{DIGEST}","browser_download_url":"https://github.com/FlashFennec22/Foxhole/releases/download/x/a.zip"}}"#),
            // no digest
            r#"{"name":"Foxhole-Setup-0.2.0.exe","size":5,"browser_download_url":"https://github.com/FlashFennec22/Foxhole/releases/download/x/a.exe"}"#.to_string(),
            // somewhere else
            format!(r#"{{"name":"Foxhole-Setup-0.2.0.exe","size":5,"digest":"{DIGEST}","browser_download_url":"https://example.com/Foxhole-Setup-0.2.0.exe"}}"#),
        ];
        for assets in cases {
            let r = parse_release(release_json("v0.2.0", &assets).as_bytes()).unwrap();
            assert!(r.installer.is_none(), "{assets}");
        }
    }

    #[test]
    fn rejects_untrusted_pages_and_versionless_releases() {
        let json = release_json("v0.2.0", "").replace("github.com/FlashFennec22", "github.com/someone-else");
        assert!(parse_release(json.as_bytes()).is_err());
        let json = release_json("Releases", "").replace(r#""name":"Release""#, r#""name":"Latest""#);
        assert!(parse_release(json.as_bytes()).is_err());
    }

    #[test]
    fn long_notes_are_cut_short() {
        let json = release_json("v0.2.0", "").replace("Notes\\r\\nline two", &"x".repeat(MAX_NOTES_CHARS + 50));
        let r = parse_release(json.as_bytes()).unwrap();
        assert_eq!(r.notes.chars().count(), MAX_NOTES_CHARS + 1);
        assert!(r.notes.ends_with('…'));
    }

    /// Talks to GitHub: `cargo test --bin foxhole-tray -- --ignored`
    #[test]
    #[ignore]
    fn live_latest_release() {
        let r = latest().unwrap();
        assert!(r.version >= Version(0, 1, 1), "{r:?}");
        assert!(r.page.starts_with(PAGE_PREFIX));
    }

    /// Downloads the 0.1.1 zip as a stand-in installer to exercise download, verification and the lock.
    #[test]
    #[ignore]
    fn live_download_verifies_and_locks() {
        let asset = Asset {
            url: format!("{DOWNLOAD_PREFIX}Foxhole0.1.1/Foxhole-Setup-0.1.1.zip"),
            size: 2841590,
            sha256: DIGEST[7..].to_ascii_lowercase(),
        };
        let release = Release { version: Version(0, 1, 1), notes: String::new(), page: String::new(), installer: Some(asset.clone()) };
        let dir = std::env::temp_dir().join("foxhole-update-test");
        let installer = download(&release, &dir).unwrap();
        assert_eq!(installer.path, dir.join("Foxhole-Setup-0.1.1.exe"));
        // Locked: no one can open it for writing or delete it while we hold it...
        assert!(OpenOptions::new().write(true).open(&installer.path).is_err());
        assert!(std::fs::remove_file(&installer.path).is_err());
        // ...but it can still be read (as Setup will).
        assert!(File::open(&installer.path).is_ok());
        drop(installer);

        let bad = Release { installer: Some(Asset { sha256: "0".repeat(64), ..asset }), ..release };
        let err = download(&bad, &dir).err().unwrap();
        assert!(err.to_string().contains("checksum"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
