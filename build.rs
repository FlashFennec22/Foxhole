//! Embeds Windows resources into both executables: version information (shown in Explorer's
//! Properties > Details and in Task Manager), the icon, and an application manifest that declares
//! the supported Windows versions and that the program runs as the invoking user (asInvoker).
//! The .rc and .manifest files are generated from Cargo metadata so the version never drifts.

use std::{env, fs, path::Path};

const BINS: &[(&str, &str)] = &[
    ("foxhole", "Foxhole DNS ad blocker"),
    ("foxhole-tray", "Foxhole tray icon"),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=resources/foxhole.ico");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // The resource compiler wants forward slashes (or escaped backslashes) inside string literals.
    let rc_path = |p: &Path| p.display().to_string().replace('\\', "/");
    let icon = rc_path(&Path::new(&manifest_dir).join("resources").join("foxhole.ico"));

    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let num = |k: &str| env::var(k).unwrap().parse::<u16>().unwrap_or(0);
    let (major, minor, patch) = (num("CARGO_PKG_VERSION_MAJOR"), num("CARGO_PKG_VERSION_MINOR"), num("CARGO_PKG_VERSION_PATCH"));

    for (bin, description) in BINS {
        let manifest_path = Path::new(&out).join(format!("{bin}.manifest"));
        fs::write(&manifest_path, format!(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Foxhole.{bin}" version="{major}.{minor}.{patch}.0" processorArchitecture="*"/>
  <description>{description}</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 and 11 -->
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
    </application>
  </compatibility>
</assembly>
"#)).unwrap();

        let rc_file = Path::new(&out).join(format!("{bin}.rc"));
        fs::write(&rc_file, format!(r#"#pragma code_page(65001)
1 ICON "{icon}"
1 24 "{manifest}"

1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEFLAGSMASK 0x3f
FILEFLAGS 0x0
FILEOS 0x40004
FILETYPE 0x1
FILESUBTYPE 0x0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Foxhole"
      VALUE "FileDescription", "{description}"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "{bin}"
      VALUE "LegalCopyright", "Copyright (c) 2026 FlashFennec22. MIT License."
      VALUE "OriginalFilename", "{bin}.exe"
      VALUE "ProductName", "Foxhole"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#, manifest = rc_path(&manifest_path))).unwrap();

        embed_resource::compile_for(&rc_file, [bin], embed_resource::NONE)
            .manifest_required()
            .unwrap();
    }
}
