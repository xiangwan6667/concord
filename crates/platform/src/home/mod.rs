#[cfg(unix)]
mod reclaim;
#[cfg(unix)]
mod secure;

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Every file the core writes goes through here, so a core running with elevated
/// privileges cannot be steered by a symlink or hard link planted in the home
/// directory, and what it creates belongs to the real user from the first byte.
#[derive(Debug)]
pub struct HomeDir {
    root: PathBuf,
    #[cfg(unix)]
    owner: Option<secure::Owner>,
    counter: AtomicU64,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_string())
}

#[cfg(unix)]
fn restrict_to_owner(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_to_owner(_file: &File) -> io::Result<()> {
    Ok(())
}

fn normalize(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() || out.as_os_str().is_empty() {
                    return None;
                }
            }
            other => out.push(other),
        }
    }
    Some(out)
}

impl HomeDir {
    /// Whether a file a profile names must pass [`confine`](Self::confine); mihomo's Android
    /// build lets it lie anywhere (`constant/path.go::IsSafePath`).
    pub const CONFINES_PROFILE_FILES: bool = !cfg!(target_os = "android");

    pub fn new(root: impl Into<PathBuf>) -> Self {
        HomeDir {
            root: root.into(),
            #[cfg(unix)]
            owner: secure::Owner::detect(),
            counter: AtomicU64::new(0),
        }
    }

    #[cfg(unix)]
    pub fn with_owner(root: impl Into<PathBuf>, uid: u32, gid: u32) -> Self {
        HomeDir {
            root: root.into(),
            owner: Some(secure::Owner { uid, gid }),
            counter: AtomicU64::new(0),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn is_elevated(&self) -> bool {
        #[cfg(unix)]
        {
            self.owner.is_some()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    pub fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative)
    }

    /// The path made absolute and normalized, if it stays inside the home directory
    /// and no existing component below the root is a symlink.
    pub fn confine(&self, path: impl AsRef<Path>) -> io::Result<PathBuf> {
        let candidate = if path.as_ref().is_absolute() {
            path.as_ref().to_path_buf()
        } else {
            self.root.join(path)
        };
        let normalized =
            normalize(&candidate).ok_or_else(|| invalid("path escapes the home directory"))?;
        let lexical_root =
            normalize(&self.root).ok_or_else(|| invalid("invalid home directory"))?;
        let real_root = std::fs::canonicalize(&self.root).ok();
        let (base, relative) = std::iter::once(&lexical_root)
            .chain(real_root.as_ref())
            .find_map(|base| normalized.strip_prefix(base).ok().map(|rel| (base, rel)))
            .ok_or_else(|| invalid("path is outside the home directory"))?;

        let mut walked = base.clone();
        for component in relative.components() {
            walked.push(component);
            match std::fs::symlink_metadata(&walked) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(invalid("path crosses a symlink"));
                }
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => break,
                Err(err) => return Err(err),
            }
        }
        Ok(base.join(relative))
    }

    #[cfg(unix)]
    fn relative_components(&self, confined: &Path) -> io::Result<(PathBuf, Vec<OsString>)> {
        let lexical = normalize(&self.root).ok_or_else(|| invalid("invalid home directory"))?;
        let real = std::fs::canonicalize(&self.root).ok();
        let (base, rel) = std::iter::once(&lexical)
            .chain(real.as_ref())
            .find_map(|base| {
                confined
                    .strip_prefix(base)
                    .ok()
                    .map(|rel| (base.clone(), rel))
            })
            .ok_or_else(|| invalid("path is outside the home directory"))?;
        let names = rel
            .components()
            .map(|c| c.as_os_str().to_os_string())
            .collect();
        Ok((base, names))
    }

    pub fn create_dir_all(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let confined = self.confine(path)?;
        #[cfg(unix)]
        if let Some(owner) = self.owner {
            let (base, names) = self.relative_components(&confined)?;
            secure::open_dir(&base, &names, Some(owner))?;
            return Ok(());
        }
        std::fs::create_dir_all(confined)
    }

    pub fn read(&self, path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        let confined = self.confine(path)?;
        #[cfg(unix)]
        if self.owner.is_some() {
            let (base, names) = self.relative_components(&confined)?;
            return secure::read_file(&base, &names);
        }
        std::fs::read(confined)
    }

    pub fn remove_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let confined = self.confine(path)?;
        #[cfg(unix)]
        if self.owner.is_some() {
            let (base, names) = self.relative_components(&confined)?;
            return secure::remove_file(&base, &names);
        }
        std::fs::remove_file(confined)
    }

    pub fn write_atomic(&self, path: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
        self.write_atomic_with(path, |file| file.write_all(bytes))
    }

    /// [`write_atomic`](Self::write_atomic) for a file only its owner may read, where the
    /// platform has file modes.
    pub fn write_private(&self, path: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
        self.write_atomic_with(path, |file| {
            restrict_to_owner(file)?;
            file.write_all(bytes)
        })
    }

    /// Streams into a temporary file beside the target, then renames it over the
    /// target, so a reader sees the old file or the whole new one.
    pub fn write_atomic_with(
        &self,
        path: impl AsRef<Path>,
        fill: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<()> {
        let confined = self.confine(path)?;
        let name = confined
            .file_name()
            .ok_or_else(|| invalid("path has no file name"))?
            .to_string_lossy()
            .into_owned();
        let temp = self.temp_name(&name);
        #[cfg(unix)]
        if let Some(owner) = self.owner {
            let (base, names) = self.relative_components(&confined)?;
            return secure::write_file(&base, &names, &temp, owner, fill);
        }
        let parent = confined
            .parent()
            .ok_or_else(|| invalid("path has no parent"))?;
        std::fs::create_dir_all(parent)?;
        let temp_path = parent.join(&temp);
        let written = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            fill(&mut file)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp_path, &confined)
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        written
    }

    fn temp_name(&self, name: &str) -> OsString {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos());
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!(".{name}.{}.{nanos:x}{n:x}.tmp", std::process::id()).into()
    }

    /// Hands foreign-owned entries under the home directory back to the real user,
    /// which only matters for files an earlier elevated core left behind; Unix alone has
    /// such owners.
    pub fn reclaim(&self) -> usize {
        #[cfg(unix)]
        if let Some(owner) = self.owner {
            return reclaim::reclaim_home(&self.root, owner.uid, owner.gid);
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> (tempfile::TempDir, HomeDir) {
        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::new(dir.path());
        (dir, home)
    }

    #[test]
    fn paths_must_stay_inside_the_home_directory() {
        let (dir, home) = home();
        assert_eq!(
            home.confine("a/b.yaml").unwrap(),
            dir.path().join("a/b.yaml")
        );
        assert_eq!(
            home.confine("./a/../b.yaml").unwrap(),
            dir.path().join("b.yaml")
        );
        assert_eq!(
            home.confine(dir.path().join("x")).unwrap(),
            dir.path().join("x")
        );

        for bad in ["../outside", "a/../../outside", "/etc/passwd", ".."] {
            let err = home.confine(bad).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_component_is_refused() {
        let (dir, home) = home();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
        std::fs::write(dir.path().join("real"), "x").unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();

        assert!(home.confine("escape/secret").is_err());
        assert!(home.confine("link").is_err());
        assert!(home.write_atomic("escape/secret", b"x").is_err());
        assert!(!outside.path().join("secret").exists());
    }

    #[test]
    fn atomic_writes_replace_the_file_and_leave_no_temporary() {
        let (dir, home) = home();
        home.write_atomic("profiles/1/config.yaml", b"first")
            .unwrap();
        home.write_atomic("profiles/1/config.yaml", b"second")
            .unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("profiles/1/config.yaml")).unwrap(),
            b"second"
        );
        assert_eq!(home.read("profiles/1/config.yaml").unwrap(), b"second");

        let names: Vec<_> = std::fs::read_dir(dir.path().join("profiles/1"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["config.yaml"]);
    }

    #[test]
    fn a_failed_fill_keeps_the_old_content_and_removes_the_temporary() {
        let (dir, home) = home();
        home.write_atomic("keep.yaml", b"old").unwrap();
        let result = home.write_atomic_with("keep.yaml", |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("download dropped"))
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(dir.path().join("keep.yaml")).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn directories_and_removal_work_inside_the_home() {
        let (dir, home) = home();
        home.create_dir_all("a/b/c").unwrap();
        assert!(dir.path().join("a/b/c").is_dir());
        home.write_atomic("a/b/c/f", b"1").unwrap();
        home.remove_file("a/b/c/f").unwrap();
        assert!(!dir.path().join("a/b/c/f").exists());
        assert!(home.create_dir_all("../x").is_err());
    }
}
