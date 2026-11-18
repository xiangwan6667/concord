//! A device and its routes set up by a privileged process for an unprivileged core that adopts
//! the descriptor. The device goes away with the last descriptor.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

use crate::options::TunOptions;
use crate::route::{
    IfaceInfo, NetlinkBackend, Plan, RouteBackend, RouteError, RouteSession, Step, android_tables,
};
use crate::runner::{StartError, StartStep};

pub struct Provisioned {
    fd: Option<OwnedFd>,
    iface: IfaceInfo,
    session: RouteSession<NetlinkBackend>,
    notes: Vec<String>,
}

impl Provisioned {
    pub fn iface(&self) -> &IfaceInfo {
        &self.iface
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    pub fn take_fd(&mut self) -> Option<OwnedFd> {
        self.fd.take()
    }

    pub async fn release(mut self) -> Vec<RouteError> {
        // The device, and the routes with it, went away when the adopter closed the last descriptor.
        if self.fd.is_none() && if_index(&self.iface.name).ok() != Some(self.iface.index) {
            self.session.forget(|step| matches!(step, Step::Route(_)));
        }
        let failures = self.session.teardown().await;
        drop(self.fd.take());
        let (backend, _) = self.session.into_parts();
        let _ = backend.delete_link(self.iface.index).await;
        failures
    }
}

fn failed(step: StartStep, err: &io::Error) -> StartError {
    StartError {
        step,
        kind: err.kind(),
        detail: err.to_string(),
        undo_failures: 0,
    }
}

/// Removes what a run killed before its release left: the rules in the priority range `options`
/// uses and the routes in its tables.
pub async fn clean_stale(options: &TunOptions) -> io::Result<usize> {
    let start = options.iproute2_rule_index;
    let mut backend = NetlinkBackend::connect()?;
    let rules = backend.clean_stale((start, start + 10)).await?;
    let routes = backend.flush_tables(&android_tables(options)).await?;
    Ok(rules + routes)
}

pub async fn provision(options: &TunOptions) -> Result<Provisioned, StartError> {
    let (fd, name) =
        open_device(options.device.as_deref()).map_err(|err| failed(StartStep::Device, &err))?;
    let index = if_index(&name).map_err(|err| failed(StartStep::Device, &err))?;
    let backend = NetlinkBackend::connect().map_err(|err| failed(StartStep::Device, &err))?;
    let mtu = options.effective_mtu() as u32;
    let addresses: Vec<(IpAddr, u8)> = options
        .inet4_address
        .iter()
        .chain(&options.inet6_address)
        .map(|prefix| (prefix.addr(), prefix.len()))
        .collect();
    backend
        .bring_up(index, mtu, &addresses)
        .await
        .map_err(|err| failed(StartStep::Device, &err))?;
    let iface = IfaceInfo { name, index };
    let (session, notes) = RouteSession::install(backend, &plan(options, &iface))
        .await
        .map_err(|err| StartError {
            step: StartStep::Routes,
            kind: err.source.kind(),
            detail: err.to_string(),
            undo_failures: err.undo_failures,
        })?;
    Ok(Provisioned {
        fd: Some(fd),
        iface,
        session,
        notes,
    })
}

fn plan(options: &TunOptions, iface: &IfaceInfo) -> Plan {
    if cfg!(target_os = "android") {
        crate::route::plan_android(options, iface)
    } else {
        crate::route::plan_linux(options, iface)
    }
}

/// sing-tun's `openTun`: Android keeps the clone device at `/dev/tun`.
fn open_device(name: Option<&str>) -> io::Result<(OwnedFd, String)> {
    let path = if std::path::Path::new("/dev/tun").exists() {
        "/dev/tun"
    } else {
        "/dev/net/tun"
    };
    let fd = OwnedFd::from(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?,
    );
    #[allow(unsafe_code, reason = "ifreq is a plain C struct")]
    // SAFETY: all-zero bytes are a valid `ifreq`.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    let wanted = name.unwrap_or_default().as_bytes();
    if wanted.len() >= request.ifr_name.len() || wanted.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device name too long",
        ));
    }
    for (slot, byte) in request.ifr_name.iter_mut().zip(wanted) {
        *slot = *byte as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    #[allow(unsafe_code, reason = "TUNSETIFF has no safe wrapper")]
    // SAFETY: `request` is a valid `ifreq` the ioctl reads and writes for the duration of the call.
    let set = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF as _, &mut request) };
    if set < 0 {
        return Err(io::Error::last_os_error());
    }
    let name: Vec<u8> = request
        .ifr_name
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| byte.to_ne_bytes()[0])
        .collect();
    Ok((fd, String::from_utf8_lossy(&name).into_owned()))
}

fn if_index(name: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(name)?;
    #[allow(unsafe_code, reason = "if_nametoindex(3) on a C string")]
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}
