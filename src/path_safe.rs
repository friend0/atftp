//! Resolve a TFTP-requested filename against a server root, refusing
//! anything that escapes (absolute paths, `..` components, NUL bytes).
//!
//! We do not chase symlinks here — the security model assumes the
//! operator either deploys into a directory without outward symlinks
//! or runs the daemon under chroot. The C atftpd has the same caveat.

use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

pub fn resolve(root: &Path, requested: &str) -> Result<PathBuf> {
    if requested.is_empty() || requested.contains('\0') {
        return Err(Error::InvalidPath(requested.to_owned()));
    }
    let candidate = Path::new(requested);
    if candidate.is_absolute() {
        return Err(Error::InvalidPath(requested.to_owned()));
    }
    for comp in candidate.components() {
        match comp {
            Component::Normal(_) => {}
            Component::CurDir => {}
            // ParentDir, Prefix, RootDir all reject.
            _ => return Err(Error::InvalidPath(requested.to_owned())),
        }
    }
    Ok(root.join(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from("/srv/tftp")
    }

    #[test]
    fn allows_simple() {
        assert_eq!(
            resolve(&root(), "boot.img").unwrap(),
            PathBuf::from("/srv/tftp/boot.img")
        );
    }

    #[test]
    fn allows_subdirs() {
        assert_eq!(
            resolve(&root(), "sub/boot.img").unwrap(),
            PathBuf::from("/srv/tftp/sub/boot.img")
        );
    }

    #[test]
    fn rejects_parent_dir() {
        assert!(matches!(
            resolve(&root(), "../etc/passwd"),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            resolve(&root(), "sub/../../etc/passwd"),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn rejects_absolute() {
        assert!(matches!(
            resolve(&root(), "/etc/passwd"),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn rejects_nul_and_empty() {
        assert!(matches!(resolve(&root(), ""), Err(Error::InvalidPath(_))));
        assert!(matches!(
            resolve(&root(), "foo\0bar"),
            Err(Error::InvalidPath(_))
        ));
    }
}
