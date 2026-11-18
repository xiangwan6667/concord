//! Android package names as uids, the way sing-tun's `BuildAndroidRules` turns `include-package`
//! and `exclude-package` into uid rules: each package once per Android user.

use std::collections::HashMap;

use crate::options::IdRange;

/// Android's `AID_USER_OFFSET`: user `n` runs app `a` as uid `n * PER_USER + a`.
const PER_USER: u32 = 100_000;

pub const PACKAGE_LIST: &str = "/data/system/packages.list";
pub const USER_DIR: &str = "/data/user";

/// `packages.list` holds one `name appId …` line per package. Packages that share a uid are
/// each listed with it, which is what sing-tun gets from `shared-user` in `packages.xml`.
pub fn parse_package_list(text: &str) -> HashMap<String, u32> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let name = fields.next()?;
            let app_id = fields.next()?.parse().ok()?;
            Some((name.to_owned(), app_id))
        })
        .collect()
}

pub fn parse_users<I: IntoIterator<Item = String>>(names: I) -> Vec<u32> {
    let mut users: Vec<u32> = names
        .into_iter()
        .filter_map(|name| name.parse().ok())
        .collect();
    users.sort_unstable();
    users.dedup();
    if users.is_empty() {
        users.push(0);
    }
    users
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PackageUids {
    pub include: Vec<IdRange>,
    pub exclude: Vec<IdRange>,
    pub missing: Vec<String>,
}

pub fn package_uids(
    apps: &HashMap<String, u32>,
    users: &[u32],
    include: &[String],
    exclude: &[String],
) -> PackageUids {
    let mut found = PackageUids::default();
    for (names, into) in [(include, &mut found.include), (exclude, &mut found.exclude)] {
        for name in names {
            let Some(app_id) = apps.get(name) else {
                found.missing.push(name.clone());
                continue;
            };
            for user in users {
                let uid = user
                    .checked_mul(PER_USER)
                    .and_then(|base| base.checked_add(app_id % PER_USER));
                into.extend(uid.map(IdRange::single));
            }
        }
    }
    found
}

pub fn read_package_uids(include: &[String], exclude: &[String]) -> std::io::Result<PackageUids> {
    if include.is_empty() && exclude.is_empty() {
        return Ok(PackageUids::default());
    }
    let apps = parse_package_list(&std::fs::read_to_string(PACKAGE_LIST)?);
    let users = parse_users(
        std::fs::read_dir(USER_DIR)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok()),
    );
    Ok(package_uids(&apps, &users, include, exclude))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "com.android.chrome 10123 0 /data/user/0/com.android.chrome default:targetSdkVersion=34 3002,3003\n\
                        com.android.shell 2000 0 /data/user_de/0/com.android.shell platform:privapp 3002\n\
                        com.example.shared.a 10200 0 /data/user/0/a default 3003\n\
                        com.example.shared.b 10200 0 /data/user/0/b default 3003\n\
                        broken-line\n";

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn the_package_list_maps_names_to_app_ids() {
        let apps = parse_package_list(LIST);
        assert_eq!(apps.get("com.android.chrome"), Some(&10123));
        assert_eq!(apps.get("com.android.shell"), Some(&2000));
        assert_eq!(apps.get("com.example.shared.b"), Some(&10200));
        assert_eq!(apps.len(), 4);
    }

    #[test]
    fn users_come_from_numeric_entries_and_default_to_the_owner() {
        assert_eq!(parse_users(names(&["10", "0", "x", "10"])), [0, 10]);
        assert_eq!(parse_users(Vec::new()), [0]);
    }

    #[test]
    fn a_package_maps_to_its_uid_in_every_user() {
        let apps = parse_package_list(LIST);
        let uids = package_uids(
            &apps,
            &[0, 10],
            &names(&["com.android.chrome", "gone.app"]),
            &names(&["com.example.shared.a"]),
        );
        assert_eq!(
            uids.include,
            [IdRange::single(10123), IdRange::single(1_010_123)]
        );
        assert_eq!(
            uids.exclude,
            [IdRange::single(10200), IdRange::single(1_010_200)]
        );
        assert_eq!(uids.missing, ["gone.app"]);
    }
}
