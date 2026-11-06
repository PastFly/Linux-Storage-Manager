use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

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
    injected_error: i32,
    fail_fork: bool,
    fail_send: bool,
    fail_shutdown: bool,
    ready_fd: libc::c_int,
    release_fd: libc::c_int,
}

struct SharedCancellation(*mut AtomicU32);

impl SharedCancellation {
    fn new() -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<AtomicU32>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = ptr.cast::<AtomicU32>();
        unsafe {
            ptr.write(AtomicU32::new(0));
        }
        Ok(Self(ptr))
    }
}

impl Drop for SharedCancellation {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.0.cast(), std::mem::size_of::<AtomicU32>());
        }
    }
}

// Resolve without opening an attacker-supplied device or following a symlink.
// The O_PATH descriptor pins the verified regular inode until it is reopened.
unsafe fn open_verified_writer(
    directory_fd: libc::c_int,
    name: *const libc::c_char,
    device: u64,
    inode: u64,
) -> (libc::c_int, i32) {
    let path_fd = libc::openat(
        directory_fd,
        name,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    );
    if path_fd < 0 {
        return (-1, *libc::__errno_location());
    }
    let mut stat = std::mem::zeroed::<libc::stat>();
    if libc::fstat(path_fd, &mut stat) != 0 {
        let error = *libc::__errno_location();
        libc::close(path_fd);
        return (-1, error);
    }
    if stat.st_dev != device || stat.st_ino != inode || stat.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        libc::close(path_fd);
        return (-1, libc::ESTALE);
    }
    let prefix = b"/proc/self/fd/";
    let mut proc_path = [0_u8; 64];
    std::ptr::copy_nonoverlapping(prefix.as_ptr(), proc_path.as_mut_ptr(), prefix.len());
    let mut digits = [0_u8; 10];
    let mut number = path_fd as u32;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (number % 10) as u8;
        count += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    for index in 0..count {
        proc_path[prefix.len() + index] = digits[count - index - 1];
    }
    let fd = libc::open(
        proc_path.as_ptr().cast(),
        libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
    );
    let error = if fd < 0 { *libc::__errno_location() } else { 0 };
    libc::close(path_fd);
    if error != 0 {
        return (-1, error);
    }
    if libc::fstat(fd, &mut stat) != 0 {
        let error = *libc::__errno_location();
        libc::close(fd);
        return (-1, error);
    }
    if stat.st_dev != device || stat.st_ino != inode {
        libc::close(fd);
        return (-1, libc::ESTALE);
    }
    (fd, 0)
}

// Called only in the post-fork child. Do not allocate, lock, panic, or run
// destructors here: other threads may have held library locks during fork.
unsafe fn isolated_writer(
    directory_fd: libc::c_int,
    name: *const libc::c_char,
    bytes: &[u8],
    report_fd: libc::c_int,
    parent_pid: libc::pid_t,
    cancelled: *const AtomicU32,
    controls: WriterControls,
) -> ! {
    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent_pid {
        libc::_exit(75);
    }
    let mut request = WriterReport {
        device: 0,
        inode: 0,
        error: 0,
        reserved: 0,
    };
    let received = loop {
        if (*cancelled).load(Ordering::Acquire) != 0 {
            libc::_exit(77);
        }
        let mut ready = libc::pollfd {
            fd: report_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = libc::poll(&mut ready, 1, 1000);
        if result == 0 {
            continue;
        }
        if result < 0 {
            if *libc::__errno_location() == libc::EINTR {
                continue;
            }
            libc::_exit(78);
        }
        if ready.revents & libc::POLLIN == 0 {
            libc::_exit(79);
        }
        let received = libc::recv(
            report_fd,
            (&mut request as *mut WriterReport).cast(),
            std::mem::size_of::<WriterReport>(),
            libc::MSG_DONTWAIT,
        );
        if received < 0 && *libc::__errno_location() == libc::EAGAIN {
            continue;
        }
        break received;
    };
    if (*cancelled).load(Ordering::Acquire) != 0
        || received != std::mem::size_of::<WriterReport>() as isize
        || request.error != 0
    {
        libc::_exit(76);
    }
    let mut report = WriterReport {
        device: 0,
        inode: 0,
        error: 0,
        reserved: 0,
    };
    let (fd, open_error) = open_verified_writer(directory_fd, name, request.device, request.inode);
    if fd < 0 {
        report.error = open_error;
    } else {
        let mut writable_stat = std::mem::zeroed::<libc::stat>();
        if libc::fstat(fd, &mut writable_stat) != 0 {
            report.error = *libc::__errno_location();
        } else if request.device != writable_stat.st_dev || request.inode != writable_stat.st_ino {
            report.error = libc::ESTALE;
        }
        if controls.crash_after_create {
            libc::_exit(73);
        }
        if report.error == 0 && controls.injected_error != 0 {
            report.error = controls.injected_error;
        }
        if report.error == 0 && controls.ready_fd >= 0 {
            let mut byte = 1_u8;
            if libc::write(controls.ready_fd, (&byte as *const u8).cast(), 1) != 1
                || libc::read(controls.release_fd, (&mut byte as *mut u8).cast(), 1) != 1
            {
                libc::_exit(74);
            }
        }
        let mut offset = 0;
        while report.error == 0 && offset < bytes.len() {
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
    let written = libc::send(
        report_fd,
        (&report as *const WriterReport).cast(),
        std::mem::size_of::<WriterReport>(),
        libc::MSG_NOSIGNAL,
    );
    libc::_exit(if written != std::mem::size_of::<WriterReport>() as isize {
        1
    } else if report.error != 0 {
        2
    } else {
        0
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
        let path = self.path.join(name);
        let pinned = open_child(self.file(), name, libc::O_PATH, &path)?;
        let initial = pinned.metadata().map_err(|source| failure(&path, source))?;
        if !initial.is_file() {
            return Err(JournalStoreError::NotRegularFile(path));
        }
        // Reopen the exact pinned inode, not the potentially replaced name.
        let descriptor_path = format!("/proc/self/fd/{}", pinned.as_raw_fd());
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(descriptor_path)
            .map_err(|source| failure(&path, source))?;
        let reopened = file.metadata().map_err(|source| failure(&path, source))?;
        if !reopened.is_file() || initial.dev() != reopened.dev() || initial.ino() != reopened.ino()
        {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        Ok(file)
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
                injected_error: 0,
                fail_fork: false,
                fail_send: false,
                fail_shutdown: false,
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
                injected_error: 0,
                fail_fork: false,
                fail_send: false,
                fail_shutdown: false,
                ready_fd: -1,
                release_fd: -1,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn write_staged_file_failing(
        &self,
        name: &std::ffi::OsStr,
        bytes: &[u8],
        injected_error: i32,
    ) -> Result<File, JournalStoreError> {
        self.write_staged_file_inner(
            name,
            bytes,
            WriterControls {
                crash_after_create: false,
                injected_error,
                fail_fork: false,
                fail_send: false,
                fail_shutdown: false,
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
                injected_error: 0,
                fail_fork: false,
                fail_send: false,
                fail_shutdown: false,
                ready_fd,
                release_fd,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn write_staged_file_fork_fails(
        &self,
        name: &std::ffi::OsStr,
        bytes: &[u8],
    ) -> Result<File, JournalStoreError> {
        self.write_staged_file_inner(
            name,
            bytes,
            WriterControls {
                crash_after_create: false,
                injected_error: 0,
                fail_fork: true,
                fail_send: false,
                fail_shutdown: false,
                ready_fd: -1,
                release_fd: -1,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn write_staged_file_send_fails(
        &self,
        name: &std::ffi::OsStr,
        bytes: &[u8],
        fail_shutdown: bool,
    ) -> Result<File, JournalStoreError> {
        self.write_staged_file_inner(
            name,
            bytes,
            WriterControls {
                crash_after_create: false,
                injected_error: 0,
                fail_fork: false,
                fail_send: true,
                fail_shutdown,
                ready_fd: -1,
                release_fd: -1,
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
        let cancellation = SharedCancellation::new().map_err(|source| failure(&path, source))?;
        let mut sockets = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sockets.as_mut_ptr(),
            )
        } != 0
        {
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
                libc::close(sockets[0]);
                libc::close(sockets[1]);
            }
            return Err(failure(&path, io::Error::from_raw_os_error(mask_error)));
        }
        let parent_pid = unsafe { libc::getpid() };
        let pid = if controls.fail_fork {
            -1
        } else {
            unsafe { libc::fork() }
        };
        if pid == 0 {
            unsafe {
                libc::close(sockets[0]);
                isolated_writer(
                    self.file().as_raw_fd(),
                    c_name.as_ptr(),
                    bytes,
                    sockets[1],
                    parent_pid,
                    cancellation.0,
                    controls,
                );
            }
        }
        let fork_error = if pid < 0 {
            Some(if controls.fail_fork {
                io::Error::from_raw_os_error(libc::EAGAIN)
            } else {
                io::Error::last_os_error()
            })
        } else {
            None
        };
        let restore_error =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_signals, std::ptr::null_mut()) };
        unsafe {
            libc::close(sockets[1]);
        }
        let result_socket = unsafe { File::from_raw_fd(sockets[0]) };
        if let Some(error) = fork_error {
            return Err(failure(&path, error));
        }
        // The writer already exists but cannot open anything until it receives
        // the identity of the file created and pinned read-only in the parent.
        let mut request = WriterReport {
            device: 0,
            inode: 0,
            error: 0,
            reserved: 0,
        };
        let mut local_error = if restore_error != 0 {
            Some(io::Error::from_raw_os_error(restore_error))
        } else {
            None
        };
        let mut pinned = None;
        if local_error.is_none() {
            let fd = unsafe {
                libc::openat(
                    self.file().as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                local_error = Some(io::Error::last_os_error());
            } else {
                let file = unsafe { File::from_raw_fd(fd) };
                match file.metadata() {
                    Ok(metadata) => {
                        request.device = metadata.dev();
                        request.inode = metadata.ino();
                    }
                    Err(error) => local_error = Some(error),
                }
                pinned = Some(file);
            }
        }
        if let Some(error) = &local_error {
            request.error = error.raw_os_error().unwrap_or(libc::EIO);
        }
        // The injected failure retains a duplicate to verify that shutdown,
        // rather than merely closing this descriptor, wakes the child.
        #[cfg(test)]
        let retained_socket = if controls.fail_send {
            let fd = unsafe { libc::dup(result_socket.as_raw_fd()) };
            if fd < 0 {
                return Err(failure(&path, io::Error::last_os_error()));
            }
            Some(unsafe { File::from_raw_fd(fd) })
        } else {
            None
        };
        let sent = if controls.fail_send {
            -1
        } else {
            unsafe {
                libc::send(
                    result_socket.as_raw_fd(),
                    (&request as *const WriterReport).cast(),
                    std::mem::size_of::<WriterReport>(),
                    libc::MSG_NOSIGNAL,
                )
            }
        };
        let send_error = if sent != std::mem::size_of::<WriterReport>() as isize {
            let error = if controls.fail_send {
                io::Error::from_raw_os_error(libc::EIO)
            } else if sent < 0 {
                io::Error::last_os_error()
            } else {
                io::Error::other("incomplete journal writer request")
            };
            // Cancellation remains visible even if shutdown is denied and
            // another process inherited a duplicate of this socket endpoint.
            unsafe {
                (*cancellation.0).store(1, Ordering::Release);
            }
            if !controls.fail_shutdown {
                unsafe {
                    libc::shutdown(result_socket.as_raw_fd(), libc::SHUT_WR);
                }
            }
            Some(error)
        } else {
            None
        };
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
        #[cfg(test)]
        drop(retained_socket);
        if let Some(error) = local_error.or(send_error) {
            return Err(failure(&path, error));
        }
        if !libc::WIFEXITED(status) || !matches!(libc::WEXITSTATUS(status), 0 | 2) {
            return Err(failure(
                &path,
                io::Error::other("journal writer terminated unexpectedly"),
            ));
        }
        let mut report = [0_u8; 24];
        let received = unsafe {
            libc::recv(
                result_socket.as_raw_fd(),
                report.as_mut_ptr().cast(),
                report.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            return Err(failure(&path, io::Error::last_os_error()));
        }
        if received != report.len() as isize {
            return Err(failure(
                &path,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete journal writer report",
                ),
            ));
        }
        let device = u64::from_ne_bytes(report[0..8].try_into().unwrap());
        let inode = u64::from_ne_bytes(report[8..16].try_into().unwrap());
        let error = i32::from_ne_bytes(report[16..20].try_into().unwrap());
        if error != 0 {
            return Err(failure(&path, io::Error::from_raw_os_error(error)));
        }
        if libc::WEXITSTATUS(status) != 0 {
            return Err(failure(
                &path,
                io::Error::other("journal writer failed without an error report"),
            ));
        }
        let pinned = pinned
            .ok_or_else(|| failure(&path, io::Error::other("missing pinned staging file")))?;
        let metadata = pinned.metadata().map_err(|source| failure(&path, source))?;
        let live = self
            .open_file(name)
            .map_err(|_| JournalStoreError::ChangedDuringInspection)?;
        let live_metadata = live.metadata().map_err(|source| failure(&path, source))?;
        if metadata.dev() != device
            || metadata.ino() != inode
            || live_metadata.dev() != device
            || live_metadata.ino() != inode
        {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        Ok(pinned)
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
                    let _ = count;
                    #[cfg(test)]
                    if std::env::var_os("LSM_WATCH_TRACE").is_some()
                        && count >= std::mem::size_of::<libc::inotify_event>()
                    {
                        let event = unsafe {
                            std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::inotify_event>())
                        };
                        eprintln!(
                            "LSM_WATCH_TRACE pid={} tid={:?} path={:?} mask={:#x}",
                            std::process::id(),
                            std::thread::current().id(),
                            self.path,
                            event.mask
                        );
                    }
                    return Err(JournalStoreError::ChangedDuringInspection);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(failure(&self.path, error)),
            }
        }
    }
}
