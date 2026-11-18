/// Seconds east of UTC in the zone the device is set to, at the Unix time `unix`.
#[cfg(unix)]
#[cfg_attr(
    target_pointer_width = "32",
    allow(
        clippy::useless_conversion,
        reason = "tm_gmtoff is a 32-bit long here and 64 bits on 64-bit targets"
    )
)]
pub fn local_utc_offset(unix: i64) -> i32 {
    #[allow(
        irrefutable_let_patterns,
        reason = "time_t is 32 bits on armv7 Android and 64 bits elsewhere"
    )]
    let Ok(time) = libc::time_t::try_from(unix) else {
        return 0;
    };
    // SAFETY: `tm` is plain data that localtime_r fills in, and both pointers outlive the call.
    let offset = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&raw const time, &raw mut tm).is_null() {
            0
        } else {
            tm.tm_gmtoff
        }
    };
    i32::try_from(offset).unwrap_or(0)
}

/// The offset in force now: Windows has no call that answers for an arbitrary instant
/// without walking the zone's rules, and the cron schedule only asks about the next
/// minutes.
#[cfg(windows)]
pub fn local_utc_offset(_unix: i64) -> i32 {
    use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
    // SAFETY: the struct is plain data the call fills in.
    let (kind, info) = unsafe {
        let mut info: TIME_ZONE_INFORMATION = std::mem::zeroed();
        (GetTimeZoneInformation(&raw mut info), info)
    };
    let daylight = if kind == TIME_ZONE_ID_DAYLIGHT {
        info.DaylightBias
    } else {
        0
    };
    -(info.Bias + daylight) * 60
}

/// Android's app seccomp policy kills the process on `settimeofday` rather than failing it.
#[cfg(all(unix, not(target_os = "android")))]
pub fn set_system_time(time: std::time::SystemTime) -> std::io::Result<()> {
    let since = time
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let value = libc::timeval {
        tv_sec: libc::time_t::try_from(since.as_secs())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?,
        tv_usec: since.subsec_micros() as libc::suseconds_t,
    };
    // SAFETY: the timeval outlives the call, and a null zone is the documented way to leave it alone.
    if unsafe { libc::settimeofday(&raw const value, std::ptr::null()) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
pub fn set_system_time(time: std::time::SystemTime) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::SystemInformation::SetSystemTime;
    use windows_sys::Win32::System::Time::FileTimeToSystemTime;

    const UNIX_TO_FILETIME_SECS: u64 = 11_644_473_600;
    let since = time
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let ticks = (since.as_secs() + UNIX_TO_FILETIME_SECS) * 10_000_000
        + u64::from(since.subsec_nanos()) / 100;
    let file_time = FILETIME {
        dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    // SAFETY: both structs are plain data that outlive the calls.
    unsafe {
        let mut system_time: SYSTEMTIME = std::mem::zeroed();
        if FileTimeToSystemTime(&raw const file_time, &raw mut system_time) == 0
            || SetSystemTime(&raw const system_time) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(any(all(unix, not(target_os = "android")), windows)))]
pub fn set_system_time(_time: std::time::SystemTime) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_offset_is_a_plausible_zone() {
        let offset = local_utc_offset(1_700_000_000);
        assert!((-12 * 3600..=14 * 3600).contains(&offset), "{offset}");
        assert_eq!(offset % 60, 0);
    }
}
