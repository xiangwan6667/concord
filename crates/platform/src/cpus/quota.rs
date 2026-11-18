//! The cgroup CPU quota in whole CPUs, found the way Rust 1.99.0's `available_parallelism` finds
//! it (`library/std/src/sys/thread/unix.rs`, `mod cgroups`): the process's group from
//! `/proc/self/cgroup`, a v1 `cpu` controller ahead of v2, and the tightest limit of that group and
//! every parent, rounded down. `std` does not expose the quota apart from the affinity mask.

use std::path::{Path, PathBuf};

const V2_MOUNT: &str = "/sys/fs/cgroup";
const V1_MOUNTS: [&str; 2] = ["/sys/fs/cgroup/cpu", "/sys/fs/cgroup/cpu,cpuacct"];

pub(super) trait CgroupFs {
    fn read(&self, path: &Path) -> Option<String>;
    fn exists(&self, path: &Path) -> bool;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) struct SystemFs;

#[cfg(any(target_os = "linux", target_os = "android"))]
impl CgroupFs for SystemFs {
    fn read(&self, path: &Path) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

/// The number of CPUs in a kernel CPU list such as `0-3,5,7-8`.
pub(super) fn count_cpu_list(list: &str) -> Option<usize> {
    let mut count = 0;
    for range in list.trim().split(',') {
        count += match range.split_once('-') {
            Some((first, last)) => {
                let (first, last) = (first.parse::<usize>().ok()?, last.parse::<usize>().ok()?);
                last.checked_sub(first)? + 1
            }
            None => range.parse::<usize>().map(|_| 1).ok()?,
        };
    }
    (count > 0).then_some(count)
}

/// `usize::MAX` when no quota is set or none can be read.
pub(super) fn cgroup_quota(fs: &impl CgroupFs) -> usize {
    let Some(table) = fs.read(Path::new("/proc/self/cgroup")) else {
        return usize::MAX;
    };
    match own_group(&table) {
        Some((group, true)) => quota_v1(fs, &group),
        Some((group, false)) => quota_v2(fs, &group),
        None => usize::MAX,
    }
}

/// The group path without its leading slash, and whether it is a v1 `cpu` hierarchy.
fn own_group(table: &str) -> Option<(PathBuf, bool)> {
    table.lines().fold(None, |found, line| {
        let mut fields = line.splitn(3, ':');
        let v1 = match fields.nth(1) {
            Some("") => false,
            Some(controllers) if controllers.split(',').any(|c| c == "cpu") => true,
            _ => return found,
        };
        if !v1 && found.is_some() {
            return found;
        }
        match fields.next().and_then(|path| path.get(1..)) {
            Some(path) => Some((PathBuf::from(path), v1)),
            None => found,
        }
    })
}

fn quota_v2(fs: &impl CgroupFs, group: &Path) -> usize {
    let mut path = Path::new(V2_MOUNT).join(group);
    if !fs.exists(&path.join("cgroup.controllers")) {
        return usize::MAX;
    }
    let mut quota = usize::MAX;
    while path.starts_with(V2_MOUNT) {
        if let Some(limit) = fs.read(&path.join("cpu.max")).and_then(|max| {
            let mut fields = max.lines().next()?.split(' ');
            ratio(fields.next()?, fields.next()?)
        }) {
            quota = quota.min(limit);
        }
        if !path.pop() {
            break;
        }
    }
    quota
}

fn quota_v1(fs: &impl CgroupFs, group: &Path) -> usize {
    let fixed = V1_MOUNTS
        .iter()
        .map(|mount| (PathBuf::from(mount), group.to_path_buf()));
    let found = || v1_mount_from_mountinfo(fs, group);
    for (mount, group) in fixed.chain(std::iter::from_fn(found).take(1)) {
        let mut path = mount.join(&group);
        if !fs.exists(&path) {
            continue;
        }
        let mut quota = usize::MAX;
        while path.starts_with(&mount) {
            let file = |name| fs.read(&path.join(name));
            if let (Some(limit), Some(period)) =
                (file("cpu.cfs_quota_us"), file("cpu.cfs_period_us"))
                && let Some(limit) = ratio(limit.trim(), period.trim())
            {
                quota = quota.min(limit);
            }
            if !path.pop() {
                break;
            }
        }
        return quota;
    }
    usize::MAX
}

/// A v1 `cpu` mount whose root holds `group`, and the rest of `group` below that root.
fn v1_mount_from_mountinfo(fs: &impl CgroupFs, group: &Path) -> Option<(PathBuf, PathBuf)> {
    fs.read(Path::new("/proc/self/mountinfo"))?
        .lines()
        .find_map(|line| {
            let mut items = line.trim().split(' ');
            let root = items.nth(3)?;
            let mount = items.next()?;
            let options = items.next_back()?;
            let fstype = items.nth_back(1)?;
            if fstype != "cgroup" || !options.split(',').any(|option| option == "cpu") {
                return None;
            }
            let rest = group
                .strip_prefix(Path::new(root).strip_prefix("/").ok()?)
                .ok()?;
            Some((PathBuf::from(mount), rest.to_path_buf()))
        })
}

/// `limit / period` in whole CPUs; a `max` or `-1` limit does not parse and sets nothing.
fn ratio(limit: &str, period: &str) -> Option<usize> {
    let (limit, period) = (limit.parse::<usize>().ok()?, period.parse::<usize>().ok()?);
    (period > 0).then(|| limit / period)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    struct Fixture(BTreeMap<PathBuf, String>);

    impl Fixture {
        fn new(files: &[(&str, &str)]) -> Self {
            Fixture(
                files
                    .iter()
                    .map(|(path, text)| (PathBuf::from(path), text.to_string()))
                    .collect(),
            )
        }
    }

    impl CgroupFs for Fixture {
        fn read(&self, path: &Path) -> Option<String> {
            self.0.get(path).cloned()
        }

        fn exists(&self, path: &Path) -> bool {
            self.0.keys().any(|file| file.starts_with(path))
        }
    }

    #[test]
    fn counts_cpu_lists() {
        assert_eq!(count_cpu_list("0-7\n"), Some(8));
        assert_eq!(count_cpu_list("0"), Some(1));
        assert_eq!(count_cpu_list("0-3,5,7-8"), Some(7));
        assert_eq!(count_cpu_list(""), None);
        assert_eq!(count_cpu_list("0-x"), None);
        assert_eq!(count_cpu_list("3-1"), None);
    }

    #[test]
    fn no_cgroup_table_means_no_quota() {
        assert_eq!(cgroup_quota(&Fixture::new(&[])), usize::MAX);
    }

    #[test]
    fn v2_max_means_no_quota() {
        let fs = Fixture::new(&[
            ("/proc/self/cgroup", "0::/app.slice\n"),
            ("/sys/fs/cgroup/app.slice/cgroup.controllers", "cpu memory"),
            ("/sys/fs/cgroup/app.slice/cpu.max", "max 100000\n"),
        ]);
        assert_eq!(cgroup_quota(&fs), usize::MAX);
    }

    #[test]
    fn v2_quota_rounds_down() {
        let fs = |max: &str| {
            Fixture::new(&[
                ("/proc/self/cgroup", "0::/box\n"),
                ("/sys/fs/cgroup/box/cgroup.controllers", "cpu"),
                ("/sys/fs/cgroup/box/cpu.max", max),
            ])
        };
        assert_eq!(cgroup_quota(&fs("150000 100000\n")), 1);
        assert_eq!(cgroup_quota(&fs("50000 100000\n")), 0);
        assert_eq!(cgroup_quota(&fs("400000 100000\n")), 4);
    }

    #[test]
    fn v2_takes_the_tightest_parent() {
        let fs = Fixture::new(&[
            ("/proc/self/cgroup", "0::/outer/inner\n"),
            ("/sys/fs/cgroup/outer/inner/cgroup.controllers", "cpu"),
            ("/sys/fs/cgroup/outer/inner/cpu.max", "600000 100000\n"),
            ("/sys/fs/cgroup/outer/cpu.max", "200000 100000\n"),
        ]);
        assert_eq!(cgroup_quota(&fs), 2);
    }

    #[test]
    fn v2_without_its_mount_has_no_quota() {
        let fs = Fixture::new(&[("/proc/self/cgroup", "0::/box\n")]);
        assert_eq!(cgroup_quota(&fs), usize::MAX);
    }

    #[test]
    fn v1_reads_cfs_quota_at_a_standard_mount() {
        let fs = |quota: &str| {
            Fixture::new(&[
                (
                    "/proc/self/cgroup",
                    "4:cpu,cpuacct:/docker/abc\n1:name=systemd:/\n",
                ),
                (
                    "/sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_quota_us",
                    quota,
                ),
                (
                    "/sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_period_us",
                    "100000\n",
                ),
            ])
        };
        assert_eq!(cgroup_quota(&fs("200000\n")), 2);
        assert_eq!(cgroup_quota(&fs("-1\n")), usize::MAX);
    }

    #[test]
    fn v1_finds_a_mount_in_mountinfo() {
        let fs = Fixture::new(&[
            (
                "/proc/self/cgroup",
                "5:cpuset:/top-app\n3:cpu:/\n0::/uid_10123/pid_4567\n",
            ),
            (
                "/proc/self/mountinfo",
                "20 1 0:5 / /dev/cpuset rw,relatime - cgroup none rw,cpuset\n\
                 21 1 0:6 / /dev/cpuctl rw,relatime - cgroup none rw,cpu\n",
            ),
            ("/dev/cpuctl/cpu.shares", "1024\n"),
            ("/dev/cpuctl/cpu.cfs_quota_us", "-1\n"),
            ("/dev/cpuctl/cpu.cfs_period_us", "100000\n"),
        ]);
        assert_eq!(cgroup_quota(&fs), usize::MAX);

        let mut limited = fs;
        limited
            .0
            .insert("/dev/cpuctl/cpu.cfs_quota_us".into(), "300000\n".into());
        assert_eq!(cgroup_quota(&limited), 3);
    }

    #[test]
    fn v1_cpu_controller_wins_over_v2() {
        let fs = Fixture::new(&[
            ("/proc/self/cgroup", "0::/unified\n2:cpu,cpuacct:/legacy\n"),
            ("/sys/fs/cgroup/unified/cgroup.controllers", "cpu"),
            ("/sys/fs/cgroup/unified/cpu.max", "100000 100000\n"),
            (
                "/sys/fs/cgroup/cpu,cpuacct/legacy/cpu.cfs_quota_us",
                "500000\n",
            ),
            (
                "/sys/fs/cgroup/cpu,cpuacct/legacy/cpu.cfs_period_us",
                "100000\n",
            ),
        ]);
        assert_eq!(cgroup_quota(&fs), 5);
    }
}
