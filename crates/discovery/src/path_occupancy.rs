use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;

use lsm_core::{PathObjectKind, PathOccupancyEvidence};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PathOccupancyDiscoveryError {
    #[error("path occupancy target must be a nonempty absolute path")]
    InvalidPath,
    #[error("could not inspect path occupancy for {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
}

pub fn discover_path_occupancy(
    path: &str,
) -> Result<PathOccupancyEvidence, PathOccupancyDiscoveryError> {
    if path.is_empty() || !path.starts_with('/') || path.as_bytes().contains(&0) {
        return Err(PathOccupancyDiscoveryError::InvalidPath);
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            let kind = if file_type.is_file() {
                PathObjectKind::RegularFile
            } else if file_type.is_dir() {
                PathObjectKind::Directory
            } else if file_type.is_symlink() {
                PathObjectKind::Symlink
            } else {
                PathObjectKind::Other
            };
            Ok(PathOccupancyEvidence {
                path: path.to_owned(),
                exists: true,
                kind: Some(kind),
                uid: Some(metadata.uid()),
                mode: Some(metadata.mode()),
                size_bytes: Some(metadata.len()),
            })
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(PathOccupancyEvidence {
            path: path.to_owned(),
            exists: false,
            kind: None,
            uid: None,
            mode: None,
            size_bytes: None,
        }),
        Err(source) => Err(PathOccupancyDiscoveryError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "lsm-path-state-{}-{stamp}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn absent_path_is_reported_without_creation() {
        let path = temp_path("absent");
        let evidence = discover_path_occupancy(path.to_str().unwrap()).unwrap();
        assert!(!evidence.exists);
        assert_eq!(evidence.kind, None);
        assert!(!path.exists());
    }

    #[test]
    fn symlink_is_observed_without_following_it() {
        let target = temp_path("target");
        let link = temp_path("link");
        fs::write(&target, b"payload").unwrap();
        symlink(&target, &link).unwrap();

        let evidence = discover_path_occupancy(link.to_str().unwrap()).unwrap();
        assert!(evidence.exists);
        assert_eq!(evidence.kind, Some(PathObjectKind::Symlink));

        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
    }
}
