use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::journal_store::{trusted_journal_directory, JournalStoreError};

fn failure(path: &Path, source: io::Error) -> JournalStoreError {
    JournalStoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn open_child(
    directory: &File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
    path: &Path,
) -> Result<File, JournalStoreError> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| JournalStoreError::UnsafeDirectory(path.to_path_buf()))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(failure(path, io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn same_directory(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino() && a.uid() == b.uid() && a.mode() == b.mode()
}

/// An open descriptor for every path component. The directory is addressed only
/// relative to those descriptors and rechecked against the live namespace.
pub(crate) struct JournalDir {
    nodes: Vec<File>,
    names: Vec<OsString>,
    path: PathBuf,
}

impl JournalDir {
    pub(crate) fn open(path: &Path) -> Result<Self, JournalStoreError> {
        if !path.is_absolute() {
            return Err(JournalStoreError::UnsafeDirectory(path.to_path_buf()));
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|source| failure(Path::new("/"), source))?;
        if !trusted_journal_directory(
            &root
                .metadata()
                .map_err(|source| failure(Path::new("/"), source))?,
            false,
        ) {
            return Err(JournalStoreError::UnsafeDirectory(PathBuf::from("/")));
        }
        let mut nodes = vec![root];
        let mut names = Vec::new();
        let mut current = PathBuf::from("/");
        for component in path.components() {
            match component {
                Component::RootDir => continue,
                Component::Normal(name) => {
                    current.push(name);
                    let file = open_child(
                        nodes.last().expect("root directory"),
                        name,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                        &current,
                    )?;
                    let metadata = file
                        .metadata()
                        .map_err(|source| failure(&current, source))?;
                    if !trusted_journal_directory(&metadata, current == path) {
                        return Err(JournalStoreError::UnsafeDirectory(current));
                    }
                    names.push(name.to_os_string());
                    nodes.push(file);
                }
                _ => return Err(JournalStoreError::UnsafeDirectory(path.to_path_buf())),
            }
        }
        Ok(Self {
            nodes,
            names,
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn file(&self) -> &File {
        self.nodes.last().expect("root directory")
    }

    pub(crate) fn open_file(&self, name: &std::ffi::OsStr) -> Result<File, JournalStoreError> {
        open_child(
            self.file(),
            name,
            libc::O_RDONLY | libc::O_NONBLOCK,
            &self.path.join(name),
        )
    }

    pub(crate) fn create_file(&self, name: &std::ffi::OsStr) -> Result<File, JournalStoreError> {
        let path = self.path.join(name);
        let name = CString::new(name.as_bytes())
            .map_err(|_| JournalStoreError::UnsafeDirectory(path.clone()))?;
        let fd = unsafe {
            libc::openat(
                self.file().as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(failure(&path, io::Error::last_os_error()));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(crate) fn exchange(
        &self,
        first: &std::ffi::OsStr,
        second: &std::ffi::OsStr,
    ) -> Result<(), JournalStoreError> {
        self.rename_with_flags(first, second, 2)
    }

    pub(crate) fn publish_new(
        &self,
        first: &std::ffi::OsStr,
        second: &std::ffi::OsStr,
    ) -> Result<(), JournalStoreError> {
        self.rename_with_flags(first, second, 1)
    }

    fn rename_with_flags(
        &self,
        first: &std::ffi::OsStr,
        second: &std::ffi::OsStr,
        flags: libc::c_uint,
    ) -> Result<(), JournalStoreError> {
        let first = CString::new(first.as_bytes())
            .map_err(|_| JournalStoreError::UnsafeDirectory(self.path.clone()))?;
        let second = CString::new(second.as_bytes())
            .map_err(|_| JournalStoreError::UnsafeDirectory(self.path.clone()))?;
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.file().as_raw_fd(),
                first.as_ptr(),
                self.file().as_raw_fd(),
                second.as_ptr(),
                flags,
            )
        };
        if result != 0 {
            return Err(failure(&self.path, io::Error::last_os_error()));
        }
        Ok(())
    }

    pub(crate) fn sync(&self) -> Result<(), JournalStoreError> {
        self.file()
            .sync_all()
            .map_err(|source| failure(&self.path, source))
    }

    pub(crate) fn verify_namespace(&self) -> Result<(), JournalStoreError> {
        let live_root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|source| failure(Path::new("/"), source))?;
        if !same_directory(
            &self.nodes[0]
                .metadata()
                .map_err(|source| failure(Path::new("/"), source))?,
            &live_root
                .metadata()
                .map_err(|source| failure(Path::new("/"), source))?,
        ) {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        let mut current = PathBuf::from("/");
        for (index, name) in self.names.iter().enumerate() {
            current.push(name);
            let pinned = self.nodes[index + 1]
                .metadata()
                .map_err(|source| failure(&current, source))?;
            let live = open_child(
                &self.nodes[index],
                name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                &current,
            )?;
            let live = live
                .metadata()
                .map_err(|source| failure(&current, source))?;
            if !trusted_journal_directory(&pinned, current == self.path)
                || !trusted_journal_directory(&live, current == self.path)
                || !same_directory(&pinned, &live)
            {
                return Err(JournalStoreError::ChangedDuringInspection);
            }
        }
        Ok(())
    }

    pub(crate) fn names(&self) -> Result<Vec<OsString>, JournalStoreError> {
        let descriptor_path = format!("/proc/self/fd/{}", self.file().as_raw_fd());
        let mut names = fs::read_dir(&descriptor_path)
            .map_err(|source| failure(&self.path, source))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|source| failure(&self.path, source))
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    }

    pub(crate) fn watch(&self) -> Result<DirectoryWatch, JournalStoreError> {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(failure(&self.path, io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let path =
            CString::new(format!("/proc/self/fd/{}", self.file().as_raw_fd())).expect("numeric fd");
        let mask = libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_MODIFY
            | libc::IN_ATTRIB
            | libc::IN_CLOSE_WRITE
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_UNMOUNT;
        if unsafe { libc::inotify_add_watch(file.as_raw_fd(), path.as_ptr(), mask) } < 0 {
            return Err(failure(&self.path, io::Error::last_os_error()));
        }
        Ok(DirectoryWatch {
            file,
            path: self.path.clone(),
        })
    }
}

pub(crate) struct DirectoryWatch {
    file: File,
    path: PathBuf,
}

impl DirectoryWatch {
    pub(crate) fn require_unchanged(&mut self) -> Result<(), JournalStoreError> {
        let mut bytes = [0_u8; 4096];
        loop {
            match self.file.read(&mut bytes) {
                Ok(0) => return Err(JournalStoreError::ChangedDuringInspection),
                Ok(count) => {
                    #[cfg(test)]
                    if count >= 16 {
                        let mask = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
                        eprintln!(
                            "journal directory event: path={:?} mask={mask:#x}",
                            self.path
                        );
                    }
                    #[cfg(not(test))]
                    let _ = count;
                    return Err(JournalStoreError::ChangedDuringInspection);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(failure(&self.path, error)),
            }
        }
    }
}
