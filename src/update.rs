//! Update checks against the project's GitHub releases, used by the tray icon.
//!
//! Everything here runs as the signed-in user (the tray is unelevated): ask GitHub for the latest
//! release, verify its signed manifest, and only once the user agrees, download the installer,
//! check it against the manifest's SHA-256 digest, and start it. The installer asks for
//! administrator rights itself (UAC), so Windows has the final word, not this code.
//!
//! GitHub is only a delivery channel here: nothing it says is trusted, so a compromised repository
//! or account can't push an update. Everything shown to the user or acted on (version, notes,
//! installer digest) comes from `foxhole-update.json`, signed with a minisign key kept offline
//! whose public half is compiled in. A release without a valid signature is ignored outright,
//! rather than offered through its release page, where the attacker would control the download.

use anyhow::{bail, Context, Result};
use minisign_verify::{PublicKey, Signature};
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
/// Files are only downloaded from this repository's releases.
const DOWNLOAD_PREFIX: &str = "https://github.com/FlashFennec22/Foxhole/releases/download/";
/// The only key updates are accepted from. Generating it is a one-time step: see src/README.md.
const PUBLIC_KEY: &str = include_str!("../resources/update-signing.pub");
const MANIFEST_NAME: &str = "foxhole-update.json";
const SIGNATURE_NAME: &str = "foxhole-update.json.minisig";
/// Stops a signature made with the same key for something else from passing as a Foxhole update.
const PRODUCT: &str = "foxhole";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 4 * 1024;
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

/// A release whose manifest passed signature verification.
#[derive(Clone, Debug)]
pub struct Release {
    pub version: Version,
    /// Start of the signed release notes, for the prompt.
    pub notes: String,
    installer: Asset,
}

#[derive(Clone, Debug)]
struct Asset {
    url: String,
    size: u64,
    /// Lowercase hex.
    sha256: String,
}

/// The contents of `foxhole-update.json`. Only ever parsed after its signature has been verified.
#[derive(Deserialize)]
struct Manifest {
    product: String,
    version: String,
    /// The installer's file name among the release's assets.
    installer: String,
    size: u64,
    /// Lowercase or uppercase hex.
    sha256: String,
    #[serde(default)]
    notes: String,
}

/// GitHub's view of the release: unauthenticated, so only used to find the files to download.
#[derive(Deserialize)]
struct ApiRelease {
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
}

fn client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("foxhole-tray/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// The latest published release (GitHub's `latest` never returns drafts or pre-releases), or an
/// error if it isn't validly signed.
pub fn latest() -> Result<Release> {
    let client = client(Duration::from_secs(20))?;
    let body = client
        .get(LATEST_URL)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .and_then(|r| r.error_for_status())
        .context("asking GitHub for the latest release")?
        .bytes()?;
    verified_release(&body, PUBLIC_KEY, |url, max| fetch(&client, url, max))
}

fn fetch(client: &reqwest::blocking::Client, url: &str, max: u64) -> Result<Vec<u8>> {
    let resp = client.get(url).send().and_then(|r| r.error_for_status()).context("downloading the update manifest")?;
    let mut data = Vec::new();
    resp.take(max + 1).read_to_end(&mut data).context("downloading the update manifest")?;
    if data.len() as u64 > max {
        bail!("the update manifest is unexpectedly large");
    }
    Ok(data)
}

/// Turns GitHub's reply into a release, fetching the manifest and signature with `fetch(url, max_bytes)`.
fn verified_release(api_json: &[u8], key: &str, fetch: impl Fn(&str, u64) -> Result<Vec<u8>>) -> Result<Release> {
    let api: ApiRelease = serde_json::from_slice(api_json).context("unexpected reply from GitHub")?;
    if api.draft || api.prerelease {
        bail!("the latest release is a draft or pre-release");
    }
    let (Some(manifest_url), Some(signature_url)) = (asset_url(&api, MANIFEST_NAME), asset_url(&api, SIGNATURE_NAME)) else {
        bail!("the latest release isn't signed, so Foxhole won't install it");
    };
    let manifest = fetch(manifest_url, MAX_MANIFEST_BYTES)?;
    let signature = fetch(signature_url, MAX_SIGNATURE_BYTES)?;
    verify_signature(&manifest, &signature, key)?;
    release_from_manifest(&manifest, &api)
}

fn asset_url<'a>(api: &'a ApiRelease, name: &str) -> Option<&'a str> {
    api.assets
        .iter()
        .find(|a| a.name == name && a.browser_download_url.starts_with(DOWNLOAD_PREFIX))
        .map(|a| a.browser_download_url.as_str())
}

fn verify_signature(manifest: &[u8], signature: &[u8], key: &str) -> Result<()> {
    let key = PublicKey::decode(key).context("Foxhole's built-in update key is invalid")?;
    let bad = "the latest release has an invalid signature, so Foxhole won't install it";
    let signature = std::str::from_utf8(signature).ok().and_then(|s| Signature::decode(s).ok()).context(bad)?;
    // false: only accept the current signature format, as minisign itself produces by default.
    key.verify(manifest, &signature, false).ok().context(bad)
}

/// `manifest` must already be verified.
fn release_from_manifest(manifest: &[u8], api: &ApiRelease) -> Result<Release> {
    let m: Manifest = serde_json::from_slice(manifest).context("the update manifest is malformed")?;
    if m.product != PRODUCT {
        bail!("the update manifest is for {:?}, not {PRODUCT}", m.product);
    }
    let version = Version::parse(&m.version).with_context(|| format!("bad version {:?} in the update manifest", m.version))?;
    if m.size > MAX_INSTALLER_BYTES {
        bail!("the installer is unexpectedly large ({} bytes)", m.size);
    }
    if !(m.sha256.len() == 64 && m.sha256.bytes().all(|b| b.is_ascii_hexdigit())) {
        bail!("bad SHA-256 digest in the update manifest");
    }
    let url = asset_url(api, &m.installer).with_context(|| format!("the release doesn't include {}", m.installer))?;
    let installer = Asset { url: url.to_string(), size: m.size, sha256: m.sha256.to_ascii_lowercase() };
    Ok(Release { version, notes: short_notes(&m.notes), installer })
}

fn short_notes(notes: &str) -> String {
    let notes = notes.replace('\r', "");
    let notes = notes.trim();
    match notes.char_indices().nth(MAX_NOTES_CHARS) {
        Some((cut, _)) => format!("{}…", notes[..cut].trim_end()),
        None => notes.to_string(),
    }
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
    let asset = &release.installer;
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
        bail!("the download doesn't match the checksum in the signed update manifest");
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

    // Real signatures, made with throwaway keys that have nothing to do with resources/update-signing.pub.
    const TEST_KEY: &str = "untrusted comment: minisign public key: 0DF0884701B1FEFE
RWT+/rEBR4jwDWSMWXkJh6LsbKSXm2ImN0ouPqc6IGRGea4nF047ZJA6
";
    /// sha256 is that of INSTALLER_BYTES.
    const MANIFEST: &str = r#"{"product":"foxhole","version":"9.8.7","installer":"Foxhole-Setup-9.8.7.exe","size":11,"sha256":"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9","notes":"Signed notes"}"#;
    const INSTALLER_BYTES: &[u8] = b"hello world";
    const SIGNATURE: &str = "untrusted comment: signature from rsign secret key
RUT+/rEBR4jwDcWDNzs1E0WwBtpsVaFYJevPw3sbZPsVh7ywZbMw6fhYXUy5nlujwu/MObEhIUv0NQ0LgPOZ/LjZ+zif6UxR+AM=
trusted comment: fixture
59zCg+EgP6XMslMY46el/cGdqRgSGrNsDuvKKifJQAid2Zd1z/4mKlUZhVEHpH2eiwuxR2ofyMpyFZE5qgYVBQ==
";
    /// The same manifest, signed with a different key.
    const ATTACKER_SIGNATURE: &str = "untrusted comment: signature from rsign secret key
RURmSWPiqPgShUvR+iEydZF1nxdxU4Fx7qnJwNDeJks4DaN1UXKJeA1QlYu3eAKe1QM8EL3esrz/zbuPpesyFmSNbR6Zq9xpqAE=
trusted comment: fixture
XSMlMnnw2LlbwFxyQ+CSMbpUAE8NAgkgkY5jMuvcab8o1hgBzOMug2OdVm4MPspbgsnVQQucEgwDpA7W4LzLAA==
";

    const RELEASES: &str = "https://github.com/FlashFennec22/Foxhole/releases/download/v9.8.7";

    /// What a fully controlled GitHub might say; `assets` are names under the expected download URL.
    fn api_json(tag: &str, assets: &[&str]) -> String {
        let assets: Vec<_> = assets
            .iter()
            .map(|n| format!(r#"{{"name":"{n}","size":11,"digest":"sha256:{}","browser_download_url":"{RELEASES}/{n}"}}"#, "0".repeat(64)))
            .collect();
        format!(r#"{{"tag_name":"{tag}","name":"{tag}","body":"Unsigned notes","draft":false,"prerelease":false,"assets":[{}]}}"#, assets.join(","))
    }

    const ALL_ASSETS: [&str; 3] = ["Foxhole-Setup-9.8.7.exe", MANIFEST_NAME, SIGNATURE_NAME];

    /// Runs the whole check against `api`, serving the given manifest and signature.
    fn check(api: &str, manifest: &str, signature: &str) -> Result<Release> {
        verified_release(api.as_bytes(), TEST_KEY, |url, _| {
            Ok(if url.ends_with(SIGNATURE_NAME) { signature } else { manifest }.as_bytes().to_vec())
        })
    }

    #[test]
    fn accepts_a_validly_signed_release() {
        let r = check(&api_json("v9.8.7", &ALL_ASSETS), MANIFEST, SIGNATURE).unwrap();
        assert_eq!(r.version, Version(9, 8, 7));
        assert_eq!(r.notes, "Signed notes");
        assert_eq!(r.installer.url, format!("{RELEASES}/Foxhole-Setup-9.8.7.exe"));
        assert_eq!(r.installer.size, 11);
        assert_eq!(r.installer.sha256, sha256_hex(INSTALLER_BYTES));
    }

    #[test]
    fn rejects_unsigned_releases() {
        for assets in [&["Foxhole-Setup-9.8.7.exe"][..], &["Foxhole-Setup-9.8.7.exe", MANIFEST_NAME], &["Foxhole-Setup-9.8.7.exe", SIGNATURE_NAME]] {
            let err = check(&api_json("v9.8.7", assets), MANIFEST, SIGNATURE).unwrap_err();
            assert!(err.to_string().contains("isn't signed"), "{err:#}");
        }
    }

    #[test]
    fn rejects_forged_manifests_and_signatures() {
        let api = api_json("v9.8.7", &ALL_ASSETS);
        // A swapped installer digest, a bumped version, and a one-character edit of the notes.
        let forged_digest = MANIFEST.replace("b94d27b9", "00000000");
        let forged_version = MANIFEST.replace("9.8.7", "9.8.8");
        let forged_notes = MANIFEST.replace("Signed", "signed");
        let cases = [
            (forged_digest.as_str(), SIGNATURE),
            (forged_version.as_str(), SIGNATURE),
            (forged_notes.as_str(), SIGNATURE),
            // The attacker's own valid signature, and things that aren't signatures at all.
            (MANIFEST, ATTACKER_SIGNATURE),
            (MANIFEST, ""),
            (MANIFEST, "not a signature"),
        ];
        for (manifest, signature) in cases {
            let err = check(&api, manifest, signature).unwrap_err();
            assert!(err.to_string().contains("invalid signature"), "{manifest} / {signature}: {err:#}");
        }
    }

    #[test]
    fn rejects_a_tampered_trusted_comment() {
        let tampered = SIGNATURE.replace("trusted comment: fixture", "trusted comment: fixturf");
        let err = check(&api_json("v9.8.7", &ALL_ASSETS), MANIFEST, &tampered).unwrap_err();
        assert!(err.to_string().contains("invalid signature"), "{err:#}");
    }

    #[test]
    fn ignores_what_github_says_about_the_release() {
        // Passing an old signed release off as a new one: the signed version wins, and the tray
        // then treats it as "up to date" for anyone already on that version or newer.
        let r = check(&api_json("v99.0.0", &ALL_ASSETS), MANIFEST, SIGNATURE).unwrap();
        assert_eq!(r.version, Version(9, 8, 7));
        assert_eq!(r.notes, "Signed notes");
        assert_eq!(r.installer.sha256, sha256_hex(INSTALLER_BYTES));
    }

    #[test]
    fn only_fetches_from_this_repository() {
        let api = api_json("v9.8.7", &ALL_ASSETS).replace(RELEASES, "https://example.com");
        let err = check(&api, MANIFEST, SIGNATURE).unwrap_err();
        assert!(err.to_string().contains("isn't signed"), "{err:#}");
        // A correctly signed manifest whose installer is hosted elsewhere isn't downloaded either.
        let api = api_json("v9.8.7", &ALL_ASSETS).replace(&format!("{RELEASES}/Foxhole-Setup"), "https://example.com/Foxhole-Setup");
        let err = check(&api, MANIFEST, SIGNATURE).unwrap_err();
        assert!(err.to_string().contains("doesn't include"), "{err:#}");
    }

    #[test]
    fn rejects_bad_manifest_contents() {
        let api: ApiRelease = serde_json::from_str(&api_json("v9.8.7", &ALL_ASSETS)).unwrap();
        let parse = |m: String| release_from_manifest(m.as_bytes(), &api).map(|_| ());
        parse(MANIFEST.to_string()).unwrap();
        assert!(parse(MANIFEST.replace(r#""product":"foxhole""#, r#""product":"other""#)).is_err());
        assert!(parse(MANIFEST.replace(r#""version":"9.8.7""#, r#""version":"latest""#)).is_err());
        assert!(parse(MANIFEST.replace(r#""size":11"#, &format!(r#""size":{}"#, MAX_INSTALLER_BYTES + 1))).is_err());
        assert!(parse(MANIFEST.replace("b94d27b9", "b94d")).is_err());
        assert!(parse(MANIFEST.replace("b94d27b9", "zzzzzzzz")).is_err());
        assert!(parse(MANIFEST.replace("Setup-9.8.7.exe", "Setup-1.0.0.exe")).is_err());
        assert!(parse("[]".to_string()).is_err());
    }

    #[test]
    fn long_notes_are_cut_short() {
        let notes = short_notes(&"x".repeat(MAX_NOTES_CHARS + 50));
        assert_eq!(notes.chars().count(), MAX_NOTES_CHARS + 1);
        assert!(notes.ends_with('…'));
        assert_eq!(short_notes(" Notes\r\nline two\r\n"), "Notes\nline two");
    }

    #[test]
    fn the_built_in_key_is_usable() {
        PublicKey::decode(PUBLIC_KEY).expect("resources/update-signing.pub is not a minisign public key");
    }

    /// Serves `body` once over plain HTTP on a loopback port and returns its URL.
    fn serve_once(body: &'static [u8]) -> String {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/installer", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = conn.read(&mut request);
            let _ = write!(conn, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = conn.write_all(body);
        });
        url
    }

    fn release_at(url: String, sha256: String) -> Release {
        let installer = Asset { url, size: INSTALLER_BYTES.len() as u64, sha256 };
        Release { version: Version(9, 8, 7), notes: String::new(), installer }
    }

    #[test]
    fn download_verifies_and_locks() {
        let dir = std::env::temp_dir().join(format!("foxhole-update-test-{}", std::process::id()));
        let release = release_at(serve_once(INSTALLER_BYTES), sha256_hex(INSTALLER_BYTES));
        let installer = download(&release, &dir).unwrap();
        assert_eq!(installer.path, dir.join("Foxhole-Setup-9.8.7.exe"));
        assert_eq!(std::fs::read(&installer.path).unwrap(), INSTALLER_BYTES);
        // Locked: no one can open it for writing or delete it while we hold it...
        assert!(OpenOptions::new().write(true).open(&installer.path).is_err());
        assert!(std::fs::remove_file(&installer.path).is_err());
        // ...but it can still be read (as Setup will).
        assert!(File::open(&installer.path).is_ok());
        drop(installer);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_swapped_installer_is_never_saved() {
        let dir = std::env::temp_dir().join(format!("foxhole-forged-test-{}", std::process::id()));
        // The right size, but not the bytes the signed manifest promised.
        let release = release_at(serve_once(b"evil  world"), sha256_hex(INSTALLER_BYTES));
        let err = download(&release, &dir).err().unwrap();
        assert!(err.to_string().contains("signed update manifest"), "{err:#}");
        assert!(!dir.exists());
    }

    /// Talks to GitHub: `cargo test --bin foxhole-tray -- --ignored`. Releases before signing was
    /// introduced must be refused, not offered.
    #[test]
    #[ignore]
    fn live_latest_release() {
        match latest() {
            Ok(r) => assert!(r.version >= Version(0, 1, 1), "{r:?}"),
            Err(e) => assert!(e.to_string().contains("isn't signed"), "{e:#}"),
        }
    }
}
