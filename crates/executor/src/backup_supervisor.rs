//! Experimental manager for the backup observer. Not an execution gate.
//! No operation here places a process in the cgroup or performs storage mutations.
#![allow(dead_code)]

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const MAX_BACKUPS: usize = 32;
const TIMEOUT: Duration = Duration::from_secs(10);

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn syscall_file(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_child(parent: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    syscall_file(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })
}

fn stat(fd: RawFd) -> io::Result<libc::stat> {
    let mut result: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut result) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

fn trusted_directory(fd: RawFd) -> io::Result<libc::stat> {
    let entry = stat(fd)?;
    if entry.st_mode & libc::S_IFMT != libc::S_IFDIR
        || entry.st_uid != 0
        || entry.st_mode & 0o022 != 0
    {
        return Err(invalid("untrusted cgroup directory"));
    }
    Ok(entry)
}

fn validate_cgroup_directory(directory: &File) -> io::Result<()> {
    trusted_directory(directory.as_raw_fd())?;
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if filesystem.f_type as libc::c_long != CGROUP2_SUPER_MAGIC {
        return Err(invalid("not cgroup v2"));
    }
    Ok(())
}

fn open_trusted_path(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("cgroup path must be absolute"));
    }
    let root = CString::new("/").unwrap();
    let mut directory = syscall_file(unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    trusted_directory(directory.as_raw_fd())?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name =
                    CString::new(name.as_bytes()).map_err(|_| invalid("invalid path component"))?;
                directory = open_child(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                trusted_directory(directory.as_raw_fd())?;
            }
            _ => return Err(invalid("invalid cgroup path")),
        }
    }
    validate_cgroup_directory(&directory)?;
    Ok(directory)
}

fn populated(events: &File) -> io::Result<bool> {
    if unsafe { libc::lseek(events.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = Vec::new();
    events.take(513).read_to_end(&mut bytes)?;
    if bytes.len() > 512 {
        return Err(invalid("oversized cgroup.events"));
    }
    let mut result = None;
    for line in bytes.split(|byte| *byte == b'\n') {
        let value = match line {
            b"populated 0" => Some(false),
            b"populated 1" => Some(true),
            _ => None,
        };
        if let Some(value) = value {
            if result.replace(value).is_some() {
                return Err(invalid("duplicate populated field"));
            }
        }
    }
    result.ok_or_else(|| invalid("missing populated field"))
}

struct Group {
    parent: File,
    root: PathBuf,
    directory: File,
    events: File,
    // Opening this verifies cgroup.kill is available without writing it.
    _kill: File,
    name: CString,
    device: libc::dev_t,
    inode: libc::ino_t,
}

impl Group {
    fn create(root: &Path) -> io::Result<Self> {
        let parent = open_trusted_path(root)?;
        let mut random = [0u8; 16];
        let count = unsafe { libc::getrandom(random.as_mut_ptr().cast(), random.len(), 0) };
        if count != random.len() as isize {
            return Err(io::Error::last_os_error());
        }
        let mut suffix = String::with_capacity(32);
        for byte in random {
            use std::fmt::Write as _;
            write!(&mut suffix, "{byte:02x}").unwrap();
        }
        let name = CString::new(format!("lsm-backup-{suffix}")).unwrap();
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // On any subsequent ambiguity leave the directory intact as evidence.
        let directory = open_child(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        validate_cgroup_directory(&directory)?;
        let identity = trusted_directory(directory.as_raw_fd())?;
        if identity.st_dev != stat(parent.as_raw_fd())?.st_dev {
            return Err(invalid("cgroup mount changed"));
        }
        let events = open_child(&directory, c"cgroup.events", libc::O_RDONLY)?;
        let kill = open_child(&directory, c"cgroup.kill", libc::O_WRONLY)?;
        if populated(&events)? {
            return Err(invalid("new cgroup is populated"));
        }
        let group = Self {
            parent,
            root: root.to_path_buf(),
            directory,
            events,
            _kill: kill,
            name,
            device: identity.st_dev,
            inode: identity.st_ino,
        };
        group.verify()?;
        Ok(group)
    }

    fn verify(&self) -> io::Result<()> {
        let reopened_parent = open_trusted_path(&self.root)?;
        let held_parent = stat(self.parent.as_raw_fd())?;
        let live_parent = stat(reopened_parent.as_raw_fd())?;
        if held_parent.st_dev != live_parent.st_dev || held_parent.st_ino != live_parent.st_ino {
            return Err(invalid("cgroup parent identity changed"));
        }
        let held = trusted_directory(self.directory.as_raw_fd())?;
        let mut live: libc::stat = unsafe { zeroed() };
        if unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                &mut live,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if held.st_dev != self.device
            || held.st_ino != self.inode
            || live.st_dev != self.device
            || live.st_ino != self.inode
            || live.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(invalid("cgroup identity changed"));
        }
        Ok(())
    }
}

fn validate_backups(files: &[File]) -> io::Result<()> {
    if files.is_empty() || files.len() > MAX_BACKUPS {
        return Err(invalid("invalid backup count"));
    }
    let mut seen = HashSet::new();
    for file in files {
        let metadata = stat(file.as_raw_fd())?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_ACCMODE != libc::O_RDONLY
            || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || metadata.st_uid != 0
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_nlink != 1
            || !seen.insert((metadata.st_dev, metadata.st_ino))
        {
            return Err(invalid("unsafe or duplicate backup descriptor"));
        }
    }
    Ok(())
}

fn pidfd(pid: libc::pid_t) -> io::Result<File> {
    syscall_file(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as libc::c_int })
}

fn socket_pair() -> io::Result<(File, File)> {
    let mut pair = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let manager = unsafe { File::from_raw_fd(pair[0]) };
    let observer = unsafe { File::from_raw_fd(pair[1]) };
    let enabled: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            manager.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((manager, observer))
}

fn send_descriptors(
    socket: &File,
    manager: &File,
    group: &File,
    backups: &[File],
) -> io::Result<()> {
    let mut fds = Vec::with_capacity(backups.len() + 2);
    fds.push(manager.as_raw_fd());
    fds.push(group.as_raw_fd());
    fds.extend(backups.iter().map(AsRawFd::as_raw_fd));
    let count = backups.len() as u32;
    let mut iov = libc::iovec {
        iov_base: (&count as *const u32).cast_mut().cast(),
        iov_len: size_of::<u32>(),
    };
    let mut control = [0usize; 64];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen =
        unsafe { libc::CMSG_SPACE((fds.len() * size_of::<libc::c_int>()) as u32) } as usize;
    let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if header.is_null() || msg.msg_controllen > size_of::<[usize; 64]>() {
        return Err(invalid("control buffer too small"));
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN((fds.len() * size_of::<libc::c_int>()) as u32) as usize;
        ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
    }
    let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if sent != size_of::<u32>() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn receive_byte(socket: &File, expected_pid: libc::pid_t, expected: u8) -> io::Result<()> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    // Space for credentials and malicious SCM_RIGHTS; close any received rights.
    let mut control = [0usize; 64];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = size_of::<[usize; 64]>();
    let count = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut credentials = None;
    let mut unexpected = false;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !header.is_null() {
        let current = unsafe { &*header };
        if current.cmsg_level == libc::SOL_SOCKET
            && current.cmsg_type == libc::SCM_CREDENTIALS
            && current.cmsg_len
                == unsafe { libc::CMSG_LEN(size_of::<libc::ucred>() as u32) } as usize
            && credentials.is_none()
        {
            credentials =
                Some(unsafe { ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>()) });
        } else {
            if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_RIGHTS {
                let base = unsafe { libc::CMSG_LEN(0) } as usize;
                let number = current.cmsg_len.saturating_sub(base) / size_of::<libc::c_int>();
                for index in 0..number {
                    unsafe {
                        libc::close(ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                        ));
                    }
                }
            }
            unexpected = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(&msg, header) };
    }
    let peer = credentials.ok_or_else(|| invalid("missing observer credentials"))?;
    if count != 1
        || byte != expected
        || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || unexpected
        || peer.pid != expected_pid
        || peer.uid != 0
    {
        return Err(invalid("invalid observer acknowledgement"));
    }
    Ok(())
}

fn receive_ready(socket: &File, expected_pid: libc::pid_t) -> io::Result<()> {
    receive_byte(socket, expected_pid, b'R')
}

fn wait_readable(socket: &File, observer_pidfd: &File) -> io::Result<()> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "observer acknowledgement timed out",
            ));
        }
        let mut fds = [
            libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: observer_pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        // An observer may send its final acknowledgement and exit before
        // poll returns, so consume readable data even alongside HUP/pidfd.
        if fds[0].revents & libc::POLLIN != 0 {
            return Ok(());
        }
        if fds[1].revents != 0 {
            return Err(invalid("observer exited"));
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(invalid("observer connection failed"));
        }
    }
}

fn require_observer_alive(observer_pidfd: &File) -> io::Result<()> {
    let mut pollfd = libc::pollfd {
        fd: observer_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result != 0 || pollfd.revents != 0 {
        return Err(invalid("observer exited"));
    }
    Ok(())
}

pub(crate) struct BackupSupervisor {
    socket: Option<File>,
    child: Option<Child>,
    observer_pidfd: File,
    group: Option<Group>,
}

impl BackupSupervisor {
    pub(crate) fn start(backups: Vec<File>) -> io::Result<Self> {
        Self::start_inner(
            backups,
            Path::new("/sys/fs/cgroup"),
            OsStr::new("/proc/self/exe"),
            false,
        )
    }

    // Test-only injection: callers must supply a disposable delegated group.
    #[cfg(test)]
    pub(crate) fn start_at(
        backups: Vec<File>,
        root: &Path,
        executable: &OsStr,
    ) -> io::Result<Self> {
        Self::start_inner(backups, root, executable, false)
    }

    #[cfg(all(test, feature = "diagnostic-backup-watchdog"))]
    fn start_watchdog_at(backups: Vec<File>, root: &Path, executable: &OsStr) -> io::Result<Self> {
        Self::start_inner(backups, root, executable, true)
    }

    fn start_inner(
        backups: Vec<File>,
        root: &Path,
        executable: &OsStr,
        diagnostic: bool,
    ) -> io::Result<Self> {
        if diagnostic && !cfg!(feature = "diagnostic-backup-watchdog") {
            return Err(invalid("diagnostic watchdog unavailable"));
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err(invalid("observer requires root"));
        }
        validate_backups(&backups)?;
        let manager_pidfd = pidfd(unsafe { libc::getpid() })?;
        let group = Group::create(root)?;
        let (socket, observer_socket) = socket_pair()?;
        // Preserve this descriptor through exec without overwriting any of
        // Command's private descriptors. The observer moves it to FD 3 itself.
        let child_fd = syscall_file(unsafe {
            libc::fcntl(observer_socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3)
        })?;
        let raw = child_fd.as_raw_fd();
        let mut command = Command::new(executable);
        command.arg("__lsm_backup_observer").arg(raw.to_string());
        if diagnostic {
            command.arg("--diagnostic-watchdog");
        }
        command
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                // Mark every other inherited FD close-on-exec; the observer closes
                // them again on entry. Fail closed if the kernel lacks close_range.
                if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0
                    || libc::fcntl(raw, libc::F_SETFD, 0) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // Prevent an inherited signal handler from running in the forked
        // child before exec; only this calling thread's mask is changed.
        let mut all_signals: libc::sigset_t = unsafe { zeroed() };
        let mut old_signals: libc::sigset_t = unsafe { zeroed() };
        if unsafe { libc::sigfillset(&mut all_signals) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mask_error =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &all_signals, &mut old_signals) };
        if mask_error != 0 {
            return Err(io::Error::from_raw_os_error(mask_error));
        }
        let spawned = command.spawn();
        let restore_error =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_signals, ptr::null_mut()) };
        if restore_error != 0 {
            drop(socket);
            if let Ok(mut child) = spawned {
                let _ = std::thread::Builder::new().spawn(move || {
                    let _ = child.wait();
                });
            }
            return Err(io::Error::from_raw_os_error(restore_error));
        }
        let mut child = spawned?;
        let observer = match pidfd(child.id() as libc::pid_t) {
            Ok(observer) => observer,
            Err(error) => {
                drop(socket);
                let _ = std::thread::Builder::new().spawn(move || {
                    let _ = child.wait();
                });
                return Err(error);
            }
        };
        drop(child_fd);
        drop(observer_socket);
        let supervisor = Self {
            socket: Some(socket),
            child: Some(child),
            observer_pidfd: observer,
            group: Some(group),
        };
        supervisor.group.as_ref().unwrap().verify()?;
        if populated(&supervisor.group.as_ref().unwrap().events)? {
            return Err(invalid("cgroup became populated"));
        }
        send_descriptors(
            supervisor.socket.as_ref().unwrap(),
            &manager_pidfd,
            &supervisor.group.as_ref().unwrap().directory,
            &backups,
        )?;
        // Never issue F_UNLCK: close manager copies after transferring them.
        drop(backups);
        wait_readable(
            supervisor.socket.as_ref().unwrap(),
            &supervisor.observer_pidfd,
        )?;
        receive_ready(
            supervisor.socket.as_ref().unwrap(),
            supervisor.child.as_ref().unwrap().id() as libc::pid_t,
        )?;
        require_observer_alive(&supervisor.observer_pidfd)?;
        supervisor.group.as_ref().unwrap().verify()?;
        if populated(&supervisor.group.as_ref().unwrap().events)? {
            return Err(invalid("cgroup became populated"));
        }
        Ok(supervisor)
    }

    /// A point-in-time process/socket check, not proof that no SIGIO is
    /// pending or that a lease will remain intact after this call.
    #[cfg(test)]
    pub(crate) fn probe_observer_alive(&self) -> io::Result<()> {
        require_observer_alive(&self.observer_pidfd)?;
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| invalid("observer socket unavailable"))?;
        let mut item = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut item, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result != 0 || item.revents != 0 {
            return Err(invalid("observer connection changed"));
        }
        let group = self
            .group
            .as_ref()
            .ok_or_else(|| invalid("observer cgroup unavailable"))?;
        group.verify()?;
        if populated(&group.events)? {
            return Err(invalid("observer cgroup became populated"));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn observer_pidfd_for_test(&self) -> io::Result<File> {
        self.observer_pidfd.try_clone()
    }

    /// Disarm only after the observer has confirmed the group is empty.
    /// The directory is deliberately retained: Linux has no conditional
    /// unlink-by-inode, so a concurrent rename could otherwise remove a
    /// different empty cgroup after our last identity check.
    pub(crate) fn finish_empty(mut self) -> io::Result<PathBuf> {
        let group = self.group.as_ref().unwrap();
        group.verify()?;
        if populated(&group.events)? {
            return Err(invalid("cgroup is populated"));
        }
        let socket = self.socket.as_ref().unwrap();
        if unsafe {
            libc::send(
                socket.as_raw_fd(),
                b"Q".as_ptr().cast(),
                1,
                libc::MSG_NOSIGNAL,
            )
        } != 1
        {
            return Err(io::Error::last_os_error());
        }
        wait_readable(socket, &self.observer_pidfd)?;
        receive_byte(
            socket,
            self.child.as_ref().unwrap().id() as libc::pid_t,
            b'Q',
        )?;
        let deadline = Instant::now() + TIMEOUT;
        let child = self.child.as_mut().unwrap();
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Err(invalid("observer exited unsuccessfully"));
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "observer did not exit",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.child.take();
        self.socket.take();
        let group = self.group.take().unwrap();
        group.verify()?;
        if populated(&group.events)? {
            return Err(invalid("cgroup became populated"));
        }
        Ok(group.root.join(OsStr::from_bytes(group.name.as_bytes())))
    }
}

impl Drop for BackupSupervisor {
    fn drop(&mut self) {
        // Closing the control channel asks the observer to kill/wait itself.
        // Never kill the observer, unlock a lease, or remove an uncertain group.
        self.socket.take();
        if let Some(mut child) = self.child.take() {
            let _ = std::thread::Builder::new().spawn(move || {
                let _ = child.wait();
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "diagnostic-backup-watchdog")]
    fn watchdog_fixture(suffix: &str) -> (BackupSupervisor, PathBuf) {
        use std::os::unix::fs::OpenOptionsExt;
        let root = PathBuf::from(
            std::env::var_os("LSM_TEST_DISPOSABLE_CGROUP").expect("disposable cgroup required"),
        );
        let executable =
            std::env::var_os("LSM_TEST_OBSERVER_EXE").expect("observer executable required");
        assert!(root.starts_with("/sys/fs/cgroup") && root != Path::new("/sys/fs/cgroup"));
        assert!(root
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let backup =
            std::env::temp_dir().join(format!("lsm-watchdog-{suffix}-{}", std::process::id()));
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backup)
            .unwrap();
        drop(writer);
        let supervisor = BackupSupervisor::start_watchdog_at(
            vec![File::open(&backup).unwrap()],
            &root,
            &executable,
        )
        .unwrap();
        (supervisor, backup)
    }

    #[test]
    #[ignore = "requires an explicitly delegated disposable Linux cgroup and observer executable"]
    #[cfg(feature = "diagnostic-backup-watchdog")]
    fn watchdog_observer_acknowledges_heartbeat_without_releasing_lease() {
        let (supervisor, backup) = watchdog_fixture("heartbeat");
        let socket = supervisor.socket.as_ref().unwrap();
        assert_eq!(
            unsafe {
                libc::send(
                    socket.as_raw_fd(),
                    b"H".as_ptr().cast(),
                    1,
                    libc::MSG_NOSIGNAL,
                )
            },
            1
        );
        wait_readable(socket, &supervisor.observer_pidfd).unwrap();
        receive_byte(
            socket,
            supervisor.child.as_ref().unwrap().id() as libc::pid_t,
            b'H',
        )
        .unwrap();
        supervisor.probe_observer_alive().unwrap();
        supervisor.finish_empty().unwrap();
        std::fs::remove_file(backup).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly delegated disposable Linux cgroup and observer executable"]
    #[cfg(feature = "diagnostic-backup-watchdog")]
    fn watchdog_observer_stops_when_manager_heartbeats_cease() {
        let (supervisor, backup) = watchdog_fixture("deadline");
        let mut item = libc::pollfd {
            fd: supervisor.observer_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut item, 1, 5_000) };
        assert_eq!(result, 1, "observer did not stop after heartbeat deadline");
        assert_ne!(item.revents & libc::POLLIN, 0);
        assert!(supervisor.probe_observer_alive().is_err());
        drop(supervisor);
        std::fs::remove_file(backup).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly delegated disposable Linux cgroup and observer executable"]
    #[cfg(feature = "diagnostic-backup-watchdog")]
    fn watchdog_rejects_heartbeat_from_inherited_socket_in_another_process() {
        let (supervisor, backup) = watchdog_fixture("foreign-heartbeat");
        let socket = supervisor.socket.as_ref().unwrap().as_raw_fd();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let result = unsafe { libc::send(socket, b"H".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
            unsafe { libc::_exit(if result == 1 { 0 } else { 1 }) }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        let mut item = libc::pollfd {
            fd: supervisor.observer_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut item, 1, 1_000) }, 1);
        assert_ne!(item.revents & libc::POLLIN, 0);
        assert!(supervisor.probe_observer_alive().is_err());
        drop(supervisor);
        std::fs::remove_file(backup).unwrap();
    }

    #[test]
    fn supervisor_rejects_non_cgroup_filesystem_before_mutating_it() {
        let directory = File::open(std::env::temp_dir()).unwrap();
        assert!(validate_cgroup_directory(&directory).is_err());
    }

    #[test]
    fn supervisor_rejects_ready_from_wrong_process() {
        let (receiver, sender) = socket_pair().unwrap();
        assert_eq!(
            unsafe { libc::send(sender.as_raw_fd(), b"R".as_ptr().cast(), 1, 0) },
            1
        );
        assert!(receive_ready(&receiver, unsafe { libc::getpid() } + 1).is_err());
    }

    #[test]
    fn supervisor_accepts_authenticated_ready_from_expected_process() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let (receiver, sender) = socket_pair().unwrap();
        assert_eq!(
            unsafe { libc::send(sender.as_raw_fd(), b"R".as_ptr().cast(), 1, 0) },
            1
        );
        receive_ready(&receiver, unsafe { libc::getpid() }).unwrap();
    }

    #[test]
    fn supervisor_rejects_writable_backup_descriptors() {
        use std::os::unix::fs::OpenOptionsExt;
        let path =
            std::env::temp_dir().join(format!("lsm-supervisor-backup-{}", std::process::id()));
        let writable = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        assert!(validate_backups(&[writable]).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "requires explicit disposable Linux cgroup and observer executable"]
    fn supervisor_disarms_empty_disposable_cgroup() {
        use std::os::unix::fs::OpenOptionsExt;
        let root = PathBuf::from(std::env::var_os("LSM_TEST_DISPOSABLE_CGROUP").unwrap());
        let executable = std::env::var_os("LSM_TEST_OBSERVER_EXE").unwrap();
        assert!(root.starts_with("/sys/fs/cgroup"));
        assert_ne!(root, Path::new("/sys/fs/cgroup"));
        let backup = std::env::temp_dir().join(format!(
            "lsm-supervisor-disposable-backup-{}",
            std::process::id()
        ));
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backup)
            .unwrap();
        drop(writer);
        let source = File::open(&backup).unwrap();
        let supervisor = BackupSupervisor::start_at(vec![source], &root, &executable).unwrap();
        let group_path = root.join(OsStr::from_bytes(
            supervisor.group.as_ref().unwrap().name.as_bytes(),
        ));
        assert!(group_path.exists());
        assert_eq!(supervisor.finish_empty().unwrap(), group_path);
        assert!(group_path.exists());
        std::fs::remove_file(backup).unwrap();
    }
}
