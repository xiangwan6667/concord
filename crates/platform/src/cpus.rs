use std::io;
use std::num::NonZeroUsize;

#[cfg(any(target_os = "linux", target_os = "android", test))]
mod quota;

/// The CPUs this process may run on. `std::thread::available_parallelism` honours the affinity
/// mask on Linux but not on Windows, where a core limited by `start /affinity`, a job object or a
/// launcher that pins it would otherwise start a worker for every CPU of the machine.
pub fn available_cpus() -> io::Result<NonZeroUsize> {
    #[cfg(windows)]
    if let Some(count) = affinity_count() {
        return Ok(count);
    }
    std::thread::available_parallelism()
}

/// The CPUs a process may be given over its life when the system, not its launcher, moves it
/// between CPU sets: the online CPUs within the cgroup CPU quota. An Android app process is moved
/// between the `top-app`, `foreground` and `background` cpusets as its state changes, so the mask
/// it starts with need not be the one it runs with later, and a Tokio pool cannot grow.
pub fn assignable_cpus() -> io::Result<NonZeroUsize> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(online) = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|list| quota::count_cpu_list(&list))
    {
        let count = online.min(quota::cgroup_quota(&quota::SystemFs).max(1));
        return Ok(NonZeroUsize::new(count).unwrap_or(NonZeroUsize::MIN));
    }
    available_cpus()
}

#[cfg(windows)]
fn affinity_count() -> Option<NonZeroUsize> {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessAffinityMask};

    let mut process = 0usize;
    let mut system = 0usize;
    // SAFETY: the current-process pseudo handle needs no closing, and both pointers are valid.
    let ok = unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut process, &mut system) };
    // A process whose threads span processor groups gets zero masks: one mask cannot describe it.
    if ok == 0 {
        return None;
    }
    NonZeroUsize::new(process.count_ones() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_at_least_one_cpu_and_no_more_than_the_machine() {
        let usable = available_cpus().unwrap().get();
        let machine = std::thread::available_parallelism().unwrap().get();
        assert!((1..=machine.max(64)).contains(&usable));
    }

    #[test]
    fn assignable_cpus_cover_the_cpus_the_process_may_use_now() {
        let assignable = assignable_cpus().unwrap().get();
        let usable = available_cpus().unwrap().get();
        assert!(assignable >= usable, "{assignable} < {usable}");
    }
}
