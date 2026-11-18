use concord_tun::{IdRange, Prefix, TunOptions};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunRequest {
    #[serde(default)]
    pub device: Option<String>,
    pub mtu: u32,
    pub inet4_address: Vec<String>,
    #[serde(default)]
    pub inet6_address: Vec<String>,
    #[serde(default)]
    pub route_address: Vec<String>,
    #[serde(default)]
    pub route_exclude_address: Vec<String>,
    #[serde(default)]
    pub strict_route: bool,
    #[serde(default)]
    pub include_package: Vec<String>,
    #[serde(default)]
    pub exclude_package: Vec<String>,
    #[serde(default)]
    pub include_uid: Vec<u32>,
    #[serde(default)]
    pub exclude_uid: Vec<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("bad request: {0}")]
    Request(#[from] serde_json::Error),
    #[error("not a prefix: {0}")]
    Prefix(String),
    #[error("read installed packages: {0}")]
    Packages(std::io::Error),
    #[error("none of the included packages is installed")]
    NoIncludedPackage,
    #[error("no runtime")]
    NoRuntime,
    #[error(transparent)]
    Start(#[from] concord_tun::StartError),
    #[error("no descriptor")]
    NoDescriptor,
    #[error("panicked")]
    Panicked,
    #[error("no request")]
    NoRequest,
}

/// The longest prefix of `reason` that ends on a character boundary and leaves room for a NUL
/// in `capacity` bytes.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn fit_c_string(reason: &str, capacity: usize) -> &str {
    &reason[..reason.floor_char_boundary(capacity.saturating_sub(1))]
}

fn prefixes(texts: &[String]) -> Result<Vec<Prefix>, ProvisionError> {
    texts
        .iter()
        .map(|text| Prefix::parse(text).ok_or_else(|| ProvisionError::Prefix(text.clone())))
        .collect()
}

impl TunRequest {
    pub fn options(&self) -> Result<TunOptions, ProvisionError> {
        Ok(TunOptions {
            device: self.device.clone(),
            mtu: self.mtu,
            inet4_address: prefixes(&self.inet4_address)?,
            inet6_address: prefixes(&self.inet6_address)?,
            auto_route: true,
            strict_route: self.strict_route,
            route_address: prefixes(&self.route_address)?,
            route_exclude_address: prefixes(&self.route_exclude_address)?,
            include_uid: self
                .include_uid
                .iter()
                .copied()
                .map(IdRange::single)
                .collect(),
            exclude_uid: self
                .exclude_uid
                .iter()
                .copied()
                .map(IdRange::single)
                .collect(),
            ..TunOptions::default()
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use exported::*;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod exported {
    use std::collections::HashMap;
    use std::ffi::{CStr, c_char};
    use std::os::fd::IntoRawFd;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{LazyLock, Mutex};

    use concord_common::Network;
    use concord_common::sync::lock;
    use concord_tun::provision::{Provisioned, clean_stale, provision};
    use concord_tun::route::packages::read_package_uids;

    use concord_tun::TunOptions;

    use super::{ProvisionError, TunRequest, fit_c_string};

    static RUNTIME: LazyLock<Option<tokio::runtime::Runtime>> = LazyLock::new(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()
    });
    static OPEN: LazyLock<Mutex<HashMap<u64, Provisioned>>> = LazyLock::new(Mutex::default);
    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn open(request: &[u8]) -> Result<(u64, i32), ProvisionError> {
        let request: TunRequest = serde_json::from_slice(request)?;
        let mut options = request.options()?;
        let packages = read_package_uids(&request.include_package, &request.exclude_package)
            .map_err(ProvisionError::Packages)?;
        for name in &packages.missing {
            tracing::warn!("[TUN] package not installed: {name}");
        }
        if !request.include_package.is_empty() && packages.include.is_empty() {
            return Err(ProvisionError::NoIncludedPackage);
        }
        options.include_uid.extend(packages.include);
        options.exclude_uid.extend(packages.exclude);
        let runtime = RUNTIME.as_ref().ok_or(ProvisionError::NoRuntime)?;
        let mut provisioned = runtime.block_on(provision(&options))?;
        for note in provisioned.notes() {
            tracing::info!("[TUN] {note}");
        }
        let fd = provisioned
            .take_fd()
            .ok_or(ProvisionError::NoDescriptor)?
            .into_raw_fd();
        let handle = NEXT.fetch_add(1, Ordering::Relaxed);
        lock(&OPEN).insert(handle, provisioned);
        Ok((handle, fd))
    }

    /// See `.agents/embedding.md`, Privileged TUN.
    ///
    /// # Safety
    /// `request` is null or holds `len` bytes, `fd` is one writable `i32`, `error` is `capacity`
    /// writable bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn concord_tun_provision(
        request: *const u8,
        len: usize,
        fd: *mut i32,
        error: *mut u8,
        capacity: usize,
    ) -> u64 {
        let opened = if request.is_null() {
            Err(ProvisionError::NoRequest)
        } else {
            // SAFETY: forwarded from this function's contract.
            let request = unsafe { std::slice::from_raw_parts(request, len) };
            catch_unwind(AssertUnwindSafe(|| open(request)))
                .unwrap_or(Err(ProvisionError::Panicked))
        };
        match opened {
            Ok((handle, descriptor)) => {
                // SAFETY: forwarded from this function's contract.
                unsafe { fd.write(descriptor) };
                handle
            }
            Err(reason) => {
                if capacity > 0 {
                    let reason = reason.to_string();
                    let text = fit_c_string(&reason, capacity);
                    // SAFETY: `text` and its NUL take at most `capacity` bytes.
                    unsafe {
                        std::ptr::copy_nonoverlapping(text.as_ptr(), error, text.len());
                        error.add(text.len()).write(0);
                    }
                }
                0
            }
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn concord_tun_release(handle: u64) -> i32 {
        catch_unwind(|| {
            let Some(provisioned) = lock(&OPEN).remove(&handle) else {
                return -1;
            };
            let Some(runtime) = RUNTIME.as_ref() else {
                return -1;
            };
            let failures = runtime.block_on(provisioned.release());
            for failure in &failures {
                tracing::warn!("[TUN] {failure}");
            }
            i32::try_from(failures.len()).unwrap_or(i32::MAX)
        })
        .unwrap_or(-1)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn concord_tun_clean_stale() -> i32 {
        catch_unwind(|| {
            let runtime = RUNTIME.as_ref()?;
            let removed = runtime.block_on(clean_stale(&TunOptions::default())).ok()?;
            i32::try_from(removed).ok()
        })
        .ok()
        .flatten()
        .unwrap_or(-1)
    }

    /// # Safety
    /// `source` is a NUL-terminated string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn concord_socket_uid(protocol: i32, source: *const c_char) -> i32 {
        // SAFETY: forwarded from this function's contract.
        let source = unsafe { CStr::from_ptr(source) };
        let network = match protocol {
            6 => Network::Tcp,
            17 => Network::Udp,
            _ => return -1,
        };
        let Some(source) = source.to_str().ok().and_then(|text| text.parse().ok()) else {
            return -1;
        };
        catch_unwind(|| concord_platform::owner::find_uid(network, source))
            .ok()
            .flatten()
            .and_then(|uid| i32::try_from(uid).ok())
            .unwrap_or(-1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_becomes_auto_routed_options() {
        let request: TunRequest = serde_json::from_str(
            r#"{"mtu":9000,"inet4Address":["198.18.0.1/30"],"inet6Address":["fdfe:dcba:9876::1/126"],
                "routeExcludeAddress":["192.168.0.0/16"],"excludeUid":[10123],"excludePackage":["a.b"]}"#,
        )
        .unwrap();
        let options = request.options().unwrap();
        assert!(options.auto_route);
        assert_eq!(options.inet4_address[0].to_string(), "198.18.0.1/30");
        assert_eq!(options.route_exclude_address.len(), 1);
        assert_eq!(options.exclude_uid, [IdRange::single(10123)]);
        assert_eq!(request.exclude_package, ["a.b"]);
    }

    #[test]
    fn an_error_is_cut_on_a_character_boundary_before_its_nul() {
        assert_eq!(fit_c_string("no route", 0), "");
        assert_eq!(fit_c_string("no route", 1), "");
        assert_eq!(fit_c_string("no route", 4), "no ");
        assert_eq!(fit_c_string("no route", 64), "no route");
        assert_eq!(fit_c_string("包名", 4), "包");
        assert_eq!(fit_c_string("包名", 3), "");
    }

    #[test]
    fn a_bad_prefix_or_unknown_key_is_refused() {
        let bad: TunRequest =
            serde_json::from_str(r#"{"mtu":1500,"inet4Address":["nope"]}"#).unwrap();
        assert!(bad.options().is_err());
        assert!(
            serde_json::from_str::<TunRequest>(r#"{"mtu":1500,"inet4Address":[],"x":1}"#).is_err()
        );
    }
}
