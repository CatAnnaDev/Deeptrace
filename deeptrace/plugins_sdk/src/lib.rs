//! DeepTrace plugin SDK.
//!
//! A plugin is a `cdylib` that decodes raw packet/payload bytes into a JSON
//! value. Plugins talk to the host over a tiny, versioned C ABI so they can
//! be built independently and loaded at runtime.
//!
//! # Writing a plugin
//!
//! ```ignore
//! use plugins_sdk::declare_plugin;
//! use serde_json::{json, Value};
//!
//! fn decode(data: &[u8]) -> anyhow::Result<Value> {
//!     if !data.starts_with(b"DTP1") {
//!         anyhow::bail!("not a DTP1 frame");
//!     }
//!     Ok(json!({ "magic": "DTP1", "len": data.len() }))
//! }
//!
//! declare_plugin!("dtp1-decoder", decode);
//! ```
//!
//! The macro generates the whole C ABI surface for you. Return `Err` to mean
//! "this payload isn't mine" — the host treats that as a clean no-match.
//!
//! # Loading plugins (host side)
//!
//! ```ignore
//! let reg = plugins_sdk::host::PluginRegistry::from_default_dirs();
//! for (name, value) in reg.decode_all(payload) {
//!     println!("{name}: {value}");
//! }
//! ```

use libc::c_char;
use serde::Serialize;
use std::ffi::CString;

/// ABI version. Bump on any breaking change to the exported C functions.
/// The host refuses to load a plugin whose version doesn't match.
pub const ABI_VERSION: u32 = 1;

/// Serialize a value to a heap C string (JSON). Returns null on failure.
pub fn json_to_c_ptr<T: Serialize>(v: &T) -> *mut c_char {
    match serde_json::to_string(v).ok().and_then(|s| CString::new(s).ok()) {
        Some(c) => c.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Free a C string previously produced by [`json_to_c_ptr`].
///
/// # Safety
/// `s` must be null or a pointer returned by this plugin's `decode_packet`.
pub unsafe fn free_c_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe { drop(CString::from_raw(s)) };
}

/// Generate the full plugin C ABI from a `fn(&[u8]) -> anyhow::Result<Value>`.
///
/// Exports: `deeptrace_plugin_abi_version`, `deeptrace_plugin_name`,
/// `decode_packet`, and `deeptrace_free_string`.
#[macro_export]
macro_rules! declare_plugin {
    // Short form: no description.
    ($name:expr, $decode_fn:path) => {
        $crate::declare_plugin!($name, "", $decode_fn);
    };
    ($name:expr, $desc:expr, $decode_fn:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn deeptrace_plugin_abi_version() -> u32 {
            $crate::ABI_VERSION
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn deeptrace_plugin_name() -> *const ::std::os::raw::c_char {
            concat!($name, "\0").as_ptr() as *const ::std::os::raw::c_char
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn deeptrace_plugin_description() -> *const ::std::os::raw::c_char {
            concat!($desc, "\0").as_ptr() as *const ::std::os::raw::c_char
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn decode_packet(
            data: *const u8,
            len: usize,
        ) -> *mut ::std::os::raw::c_char {
            if data.is_null() || len == 0 {
                return ::std::ptr::null_mut();
            }
            let slice = unsafe { ::std::slice::from_raw_parts(data, len) };
            let f: fn(&[u8]) -> ::anyhow::Result<::serde_json::Value> = $decode_fn;
            match f(slice) {
                Ok(value) => $crate::json_to_c_ptr(&value),
                Err(_) => ::std::ptr::null_mut(),
            }
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn deeptrace_free_string(s: *mut ::std::os::raw::c_char) {
            unsafe { $crate::free_c_string(s) }
        }
    };
}

/// Host-side: discover, load and run plugins.
pub mod host {
    use super::ABI_VERSION;
    use anyhow::{anyhow, Context, Result};
    use libc::c_char;
    use libloading::{Library, Symbol};
    use serde_json::Value;
    use std::ffi::CStr;
    use std::path::{Path, PathBuf};

    type AbiFn = unsafe extern "C" fn() -> u32;
    type NameFn = unsafe extern "C" fn() -> *const c_char;
    type DecodeFn = unsafe extern "C" fn(*const u8, usize) -> *mut c_char;
    type FreeFn = unsafe extern "C" fn(*mut c_char);

    type DescFn = unsafe extern "C" fn() -> *const c_char;

    /// A single loaded plugin. The `Library` is kept alive for the plugin's
    /// whole lifetime; symbols are resolved per call (cheap, and avoids
    /// self-referential lifetimes).
    pub struct Plugin {
        lib: Library,
        name: String,
        description: String,
        abi: u32,
        path: PathBuf,
    }

    impl Plugin {
        /// Probe a shared library.
        ///
        /// - `None`         → not a DeepTrace plugin (skip silently)
        /// - `Some(Err(_))` → it *is* a plugin but is broken (worth reporting)
        /// - `Some(Ok(_))`  → a valid, loaded plugin
        pub fn probe(path: &Path) -> Option<Result<Self>> {
            let lib = match unsafe { Library::new(path) } {
                Ok(lib) => lib,
                // Couldn't even dlopen it: treat as "not a plugin", not an
                // error, so unrelated libs in target/ don't spam the manager.
                Err(_) => return None,
            };

            // The abi symbol is what makes something a plugin at all.
            let abi = unsafe {
                match lib.get::<AbiFn>(b"deeptrace_plugin_abi_version\0") {
                    Ok(f) => f(),
                    Err(_) => return None,
                }
            };

            Some(Self::finish_load(lib, abi, path))
        }

        fn finish_load(lib: Library, abi: u32, path: &Path) -> Result<Self> {
            if abi != ABI_VERSION {
                return Err(anyhow!(
                    "ABI mismatch: plugin={abi}, host={ABI_VERSION}"
                ));
            }

            let name = unsafe {
                let f: Symbol<NameFn> = lib
                    .get(b"deeptrace_plugin_name\0")
                    .context("missing deeptrace_plugin_name")?;
                let ptr = f();
                if ptr.is_null() {
                    return Err(anyhow!("plugin name is null"));
                }
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            };

            let description = unsafe {
                match lib.get::<DescFn>(b"deeptrace_plugin_description\0") {
                    Ok(f) => {
                        let ptr = f();
                        if ptr.is_null() {
                            String::new()
                        } else {
                            CStr::from_ptr(ptr).to_string_lossy().into_owned()
                        }
                    }
                    Err(_) => String::new(),
                }
            };

            // Required for decoding; verify it resolves up-front.
            unsafe {
                lib.get::<DecodeFn>(b"decode_packet\0")
                    .context("missing decode_packet")?;
            }

            Ok(Self {
                lib,
                name,
                description,
                abi,
                path: path.to_path_buf(),
            })
        }

        /// Load and validate a plugin. Errors if the file isn't a plugin.
        pub fn load(path: &Path) -> Result<Self> {
            match Self::probe(path) {
                Some(res) => res,
                None => Err(anyhow!("{} is not a DeepTrace plugin", path.display())),
            }
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn description(&self) -> &str {
            &self.description
        }

        pub fn abi_version(&self) -> u32 {
            self.abi
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Run the plugin on `data`. `Ok(None)` means a clean no-match.
        pub fn decode(&self, data: &[u8]) -> Result<Option<Value>> {
            unsafe {
                let decode: Symbol<DecodeFn> = self.lib.get(b"decode_packet\0")?;
                let ptr = decode(data.as_ptr(), data.len());
                if ptr.is_null() {
                    return Ok(None);
                }
                let json = CStr::from_ptr(ptr).to_string_lossy().into_owned();
                // Free with the plugin's own exported free fn / allocator.
                if let Ok(free) = self.lib.get::<FreeFn>(b"deeptrace_free_string\0") {
                    free(ptr);
                }
                let value: Value = serde_json::from_str(&json)
                    .with_context(|| format!("plugin {} returned invalid JSON", self.name))?;
                Ok(Some(value))
            }
        }
    }

    /// A library that *looked* like a plugin but failed to load.
    #[derive(Clone, Debug)]
    pub struct PluginError {
        pub path: PathBuf,
        pub error: String,
    }

    /// A set of loaded plugins plus diagnostics for the plugin manager.
    #[derive(Default)]
    pub struct PluginRegistry {
        plugins: Vec<Plugin>,
        errors: Vec<PluginError>,
        scanned_dirs: Vec<PathBuf>,
    }

    impl PluginRegistry {
        pub fn new() -> Self {
            Self::default()
        }

        /// Load every shared library directly inside `dir` that exposes a
        /// valid plugin ABI. Non-plugin libraries are skipped silently;
        /// broken plugins are recorded in [`PluginRegistry::errors`].
        pub fn load_dir(&mut self, dir: &Path) {
            if !self.scanned_dirs.iter().any(|d| d == dir) {
                self.scanned_dirs.push(dir.to_path_buf());
            }
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let is_lib = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| matches!(e, "so" | "dylib" | "dll"));
                if !is_lib {
                    continue;
                }
                match Plugin::probe(&path) {
                    None => {} // not a plugin
                    Some(Ok(plugin)) => {
                        // De-dup by name: the same plugin often shows up in
                        // several scanned dirs (target/debug + exe dir, …).
                        if self.plugins.iter().all(|p| p.name() != plugin.name()) {
                            self.plugins.push(plugin);
                        }
                    }
                    Some(Err(e)) => {
                        if !self.errors.iter().any(|pe| pe.path == path) {
                            self.errors.push(PluginError {
                                path,
                                error: format!("{e:#}"),
                            });
                        }
                    }
                }
            }
        }

        /// The directories scanned by [`PluginRegistry::from_default_dirs`].
        pub fn default_dirs() -> Vec<PathBuf> {
            let mut dirs: Vec<PathBuf> = Vec::new();
            if let Ok(env_dir) = std::env::var("DEEPTRACE_PLUGINS") {
                dirs.push(PathBuf::from(env_dir));
            }
            dirs.push(PathBuf::from("plugins"));
            if let Ok(exe) = std::env::current_exe() {
                if let Some(parent) = exe.parent() {
                    dirs.push(parent.to_path_buf());
                }
            }
            dirs.push(PathBuf::from("target/debug"));
            dirs.push(PathBuf::from("target/release"));
            dirs
        }

        /// Scan the conventional locations: `$DEEPTRACE_PLUGINS`, `./plugins`,
        /// the executable's directory, and `target/{debug,release}`.
        pub fn from_default_dirs() -> Self {
            let mut reg = Self::new();
            for dir in Self::default_dirs() {
                reg.load_dir(&dir);
            }
            reg
        }

        /// Drop everything and rescan the default locations.
        pub fn reload(&mut self) {
            *self = Self::from_default_dirs();
        }

        pub fn is_empty(&self) -> bool {
            self.plugins.is_empty()
        }

        pub fn len(&self) -> usize {
            self.plugins.len()
        }

        pub fn names(&self) -> Vec<&str> {
            self.plugins.iter().map(|p| p.name()).collect()
        }

        /// Loaded plugins (for the manager UI).
        pub fn plugins(&self) -> &[Plugin] {
            &self.plugins
        }

        /// Libraries that looked like plugins but failed to load.
        pub fn errors(&self) -> &[PluginError] {
            &self.errors
        }

        /// Directories that were scanned.
        pub fn scanned_dirs(&self) -> &[PathBuf] {
            &self.scanned_dirs
        }

        /// Run every plugin against `data`, returning each match.
        pub fn decode_all(&self, data: &[u8]) -> Vec<(String, Value)> {
            let mut out = Vec::new();
            for p in &self.plugins {
                if let Ok(Some(v)) = p.decode(data) {
                    out.push((p.name().to_string(), v));
                }
            }
            out
        }
    }
}
