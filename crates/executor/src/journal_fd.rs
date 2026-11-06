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

#[repr(C)]
struct WriterReport {
    device: u64,
    inode: u64,
    error: i32,
    reserved: i32,
}

#[derive(Clone, Copy)]
struct WriterControls {
    crash_after_create: bool,
    ready_fd: libc::c_int,
    release_fd: libc::c_int,
}

// Called only in the post-fork child. Do not allocate, lock, panic, or run
// destructors here: other threads may have held library locks during fork.
unsafe fn isolated_writer(
    directory: libc::c_int,
    name: *const libc::c_char,
    bytes: &[u8],
    report_fd: libc::c_int,
    controls: WriterControls,
) -> ! {
    let mut report = WriterReport {
        device: 0,
        inode: 0,
        error: 0,
        reserved: 0,
    };
    let fd = libc::openat(
        directory,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    );
    if fd < 0 {
        report.error = *libc::__errno_location();
    } else {
        if controls.crash_after_create {
            libc::_exit(73);
        }
        if controls.ready_fd >= 0 {
            let mut byte = 1_u8;
            if libc::write(controls.ready_fd, (&byte as *const u8).cast(), 1) != 1
                || libc::read(controls.release_fd, (&mut byte as *mut u8).cast(), 1) != 1
            {
                libc::_exit(74);
            }
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let written = libc::write(fd, bytes.as_ptr().add(offset).cast(), bytes.len() - offset);
            if written < 0 {
                let error = *libc::__errno_location();
                if error == libc::EINTR {
                    continue;
                }
                report.error = error;
                break;
            }
            if written == 0 {
                report.error = libc::EIO;
                break;
            }
            offset += written as usize;
        }
        if report.error == 0 && libc::fsync(fd) != 0 {
            report.error = *libc::__errno_location();
        }
        let mut stat = std::mem::zeroed::<libc::stat>();
        if report.error == 0 {
            if libc::fstat(fd, &mut stat) != 0 {
                report.error = *libc::__errno_location();
            } else {
                report.device = stat.st_dev;
                report.inode = stat.st_ino;
            }
        }
        if libc::close(fd) != 0 && report.error == 0 {
            report.error = *libc::__errno_location();
        }
    }
    let written = libc::write(
        report_fd,
        (&report as *const WriterReport).cast(),
        std::mem::size_of::<WriterReport>(),
    );
    libc::_exit(if written == std::mem::size_of::<WriterReport>() as isize {
        0
    } else {
        1
    });
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

    pub(crate) fn write_staged_file(
        &self,
        name: &std::ffi::OsStr,
        bytes: &[u8],
    ) -> Result<File, JournalStoreError> {
        self.write_staged_file_inner(
            name,
            bytes,
            WriterControls {
                crash_after_create: false,
                ready_fd: -1,
                release_fd: -1,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn write_staged_file_crashing(
        &self,
        name: &std::ffi::OsStr,
        bytes: &[u8],
    ) -> Result<File, JournalStoreError> {
        self.write_staged_file_inner(
            name,
            bytes,
            WriterControls {
                crash_after_create: true,
                ready_fd: -1,
                release_fd: -1,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn write_staged_file_paused(
        &self,
        name: &std::ffi::OsStr,
        bytes: &[u8],
        ready_fd: libc::c_int,
        release_fd: libc::c_int,
    ) -> Result<File, JournalStoreError> {
        self.write_staged_file_inner(
            name,
            bytes,
            WriterControls {
                crash_after_create: false,
                ready_fd,
                release_fd,
            },
        )
    }

    fn write_staged_file_inner(
        &self,
        name: &std::ffi::OsStr,
        bytes: &[u8],
        controls: WriterControls,
    ) -> Result<File, JournalStoreError> {
        let path = self.path.join(name);
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| JournalStoreError::UnsafeDirectory(path.clone()))?;
        // With automatic reaping or an application reaper, waitpid cannot prove
        // that our writer exited. Reject before creating any staging evidence.
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
            return Err(failure(&path, io::Error::last_os_error()));
        }
        if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err(failure(
                &path,
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "journal writer requires the default SIGCHLD disposition",
                ),
            ));
        }
        let mut pipe = [-1; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(failure(&path, io::Error::last_os_error()));
        }
        // Block signal handlers across fork. The child executes only async-signal-safe
        // syscalls and exits without running Rust destructors or user handlers.
        let mut all_signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mut old_signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        unsafe { libc::sigfillset(&mut all_signals) };
        let mask_error =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &all_signals, &mut old_signals) };
        if mask_error != 0 {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            return Err(failure(&path, io::Error::from_raw_os_error(mask_error)));
        }
        let directory_fd = self.file().as_raw_fd();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::close(pipe[0]);
                isolated_writer(directory_fd, c_name.as_ptr(), bytes, pipe[1], controls);
            }
        }
        let fork_error = if pid < 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        let restore_error =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_signals, std::ptr::null_mut()) };
        unsafe {
            libc::close(pipe[1]);
        }
        let mut result_pipe = unsafe { File::from_raw_fd(pipe[0]) };
        if let Some(error) = fork_error {
            return Err(failure(&path, error));
        }
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited == pid {
                break;
            }
            if waited < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(failure(&path, error));
            }
        }
        if restore_error != 0 {
            return Err(failure(&path, io::Error::from_raw_os_error(restore_error)));
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(failure(
                &path,
                io::Error::other("journal writer terminated unexpectedly"),
            ));
        }
        let mut report = [0_u8; 24];
        result_pipe
            .read_exact(&mut report)
            .map_err(|source| failure(&path, source))?;
        let device = u64::from_ne_bytes(report[0..8].try_into().unwrap());
        let inode = u64::from_ne_bytes(report[8..16].try_into().unwrap());
        let error = i32::from_ne_bytes(report[16..20].try_into().unwrap());
        if error != 0 {
            return Err(failure(&path, io::Error::from_raw_os_error(error)));
        }
        let file = self.open_file(name)?;
        let metadata = file.metadata().map_err(|source| failure(&path, source))?;
        if metadata.dev() != device || metadata.ino() != inode {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        Ok(file)
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
                        let name_len =
                            u32::from_ne_bytes(bytes[12..16].try_into().unwrap()) as usize;
                        let end = (16 + name_len).min(count);
                        eprintln!(
                            "journal directory event: time={:?} pid={} thread={:?} path={:?} mask={mask:#x} name={:?}",
                            std::time::SystemTime::now(),
                            std::process::id(),
                            std::thread::current().id(),
                            self.path,
                            String::from_utf8_lossy(&bytes[16..end])
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
