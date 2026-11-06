//! Isolated Linux lifecycle experiment; not wired to production or authorization.
//! It does not prevent privileged cgroup migration, prove backup integrity, stop
//! already-submitted I/O, or guarantee progress when multiple supervisors stop.
//! Internal guard/launcher modes are not a security boundary against a root
//! attacker controlling the runner, its environment, or its cgroup namespace.
//! Execute only in an explicitly disposable Linux CI environment.
use crate::{channel, gated};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

const CGROUP2_MAGIC: libc::c_long = 0x6367_7270;
fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn file(fd: i32) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn pidfd(pid: libc::pid_t) -> io::Result<File> {
    file(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 })
}
fn openat(dir: &File, name: &CStr, flags: i32) -> io::Result<File> {
    file(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })
}
fn metadata(fd: RawFd) -> io::Result<libc::stat> {
    let mut result: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut result) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if result.st_mode & libc::S_IFMT != libc::S_IFDIR
        || result.st_uid != 0
        || result.st_mode & 0o022 != 0
    {
        return Err(invalid("untrusted directory"));
    }
    Ok(result)
}
fn cgroup_dir(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("cgroup root must be absolute"));
    }
    let mut dir = file(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    metadata(dir.as_raw_fd())?;
    for part in path.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name =
                    CString::new(name.as_bytes()).map_err(|_| invalid("bad cgroup component"))?;
                dir = openat(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                metadata(dir.as_raw_fd())?;
            }
            _ => return Err(invalid("bad cgroup path")),
        }
    }
    let mut fs: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut fs) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if fs.f_type as libc::c_long != CGROUP2_MAGIC {
        return Err(invalid("not cgroup v2"));
    }
    Ok(dir)
}
fn valid_name(name: &OsStr, prefix: &str) -> bool {
    let Some(name) = name.to_str().and_then(|name| name.strip_prefix(prefix)) else {
        return false;
    };
    name.len() == 32
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn require_disposable_root(root: &Path) -> io::Result<()> {
    let base = std::env::var_os("LSM_TEST_DISPOSABLE_CGROUP")
        .map(PathBuf::from)
        .ok_or_else(|| invalid("missing disposable cgroup scope"))?;
    if !base.is_absolute()
        || base == Path::new("/sys/fs/cgroup")
        || !base.starts_with("/sys/fs/cgroup")
        || root.parent() != Some(base.as_path())
        || !root
            .file_name()
            .is_some_and(|name| valid_name(name, "lsm-lifecycle-case-"))
    {
        return Err(invalid("outside disposable cgroup scope"));
    }
    cgroup_dir(&base)?;
    Ok(())
}

fn populated(events: &File) -> io::Result<bool> {
    if unsafe { libc::lseek(events.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut text = String::new();
    events.take(513).read_to_string(&mut text)?;
    if text.len() > 512 {
        return Err(invalid("oversized cgroup events"));
    }
    let mut state = None;
    for line in text.lines() {
        let value = match line {
            "populated 0" => Some(false),
            "populated 1" => Some(true),
            _ => None,
        };
        if let Some(value) = value {
            if state.replace(value).is_some() {
                return Err(invalid("duplicate populated"));
            }
        }
    }
    state.ok_or_else(|| invalid("missing populated"))
}
struct GroupIdentity {
    root: PathBuf,
    parent: File,
    name: CString,
    device: libc::dev_t,
    inode: libc::ino_t,
    worker_device: libc::dev_t,
    worker_inode: libc::ino_t,
}
struct Group {
    identity: Option<GroupIdentity>,
    directory: File,
    worker: File,
    events: File,
    kill: File,
    path: PathBuf,
}
impl Group {
    fn create(root: &Path) -> io::Result<Self> {
        let parent = cgroup_dir(root)?;
        require_disposable_root(root)?;
        let mut random = [0u8; 16];
        if unsafe { libc::getrandom(random.as_mut_ptr().cast(), random.len(), 0) }
            != random.len() as isize
        {
            return Err(io::Error::last_os_error());
        }
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let name = CString::new(format!("lsm-lifecycle-{suffix}")).unwrap();
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let directory = openat(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let stat = metadata(directory.as_raw_fd())?;
        let mut live: libc::stat = unsafe { zeroed() };
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                &mut live,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || live.st_dev != stat.st_dev
            || live.st_ino != stat.st_ino
        {
            return Err(invalid("cgroup identity changed"));
        }
        if unsafe { libc::mkdirat(directory.as_raw_fd(), c"worker".as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let worker = openat(&directory, c"worker", libc::O_RDONLY | libc::O_DIRECTORY)?;
        let worker_stat = metadata(worker.as_raw_fd())?;
        let events = openat(&directory, c"cgroup.events", libc::O_RDONLY)?;
        let kill = openat(&directory, c"cgroup.kill", libc::O_WRONLY)?;
        if populated(&events)? {
            return Err(invalid("new cgroup populated"));
        }
        let path = root.join(OsStr::from_bytes(name.as_bytes())).join("worker");
        let group = Self {
            identity: Some(GroupIdentity {
                root: root.to_path_buf(),
                parent,
                name,
                device: stat.st_dev,
                inode: stat.st_ino,
                worker_device: worker_stat.st_dev,
                worker_inode: worker_stat.st_ino,
            }),
            directory,
            worker,
            events,
            kill,
            path,
        };
        group.verify()?;
        Ok(group)
    }
    fn verify(&self) -> io::Result<()> {
        let Some(identity) = &self.identity else {
            return Ok(());
        };
        let reopened = cgroup_dir(&identity.root)?;
        let original_parent = metadata(identity.parent.as_raw_fd())?;
        let live_parent = metadata(reopened.as_raw_fd())?;
        let held = metadata(self.directory.as_raw_fd())?;
        let held_worker = metadata(self.worker.as_raw_fd())?;
        let mut linked_worker: libc::stat = unsafe { zeroed() };
        if unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                c"worker".as_ptr(),
                &mut linked_worker,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || (held_worker.st_dev, held_worker.st_ino)
                != (identity.worker_device, identity.worker_inode)
            || (linked_worker.st_dev, linked_worker.st_ino)
                != (identity.worker_device, identity.worker_inode)
            || linked_worker.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(invalid("worker cgroup namespace changed"));
        }
        let mut linked: libc::stat = unsafe { zeroed() };
        if unsafe {
            libc::fstatat(
                identity.parent.as_raw_fd(),
                identity.name.as_ptr(),
                &mut linked,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || (original_parent.st_dev, original_parent.st_ino)
                != (live_parent.st_dev, live_parent.st_ino)
            || (held.st_dev, held.st_ino) != (identity.device, identity.inode)
            || (linked.st_dev, linked.st_ino) != (identity.device, identity.inode)
            || linked.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(invalid("cgroup namespace changed"));
        }
        Ok(())
    }
    fn stop(&self) -> io::Result<()> {
        // Do not let a pathname mismatch prevent killing the pinned group.
        let identity = self.verify();
        let mut retries = 0;
        loop {
            let n = unsafe { libc::write(self.kill.as_raw_fd(), b"1".as_ptr().cast(), 1) };
            if n == 1 {
                break;
            }
            let e = if n < 0 {
                io::Error::last_os_error()
            } else {
                invalid("short cgroup.kill")
            };
            if e.kind() == io::ErrorKind::Interrupted && retries < 64 {
                retries += 1;
                continue;
            }
            return Err(e);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while populated(&self.events)? {
            if Instant::now() >= deadline {
                return Err(invalid("group did not empty"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        identity?;
        self.verify()
    }
}
fn packet_pair() -> io::Result<(File, File)> {
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let (a, b) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    let one: libc::c_int = 1;
    for fd in [a.as_raw_fd(), b.as_raw_fd()] {
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&one as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((a, b))
}
fn send(socket: &File, value: u8) -> io::Result<()> {
    let n = unsafe {
        libc::send(
            socket.as_raw_fd(),
            (&value as *const u8).cast(),
            1,
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    };
    if n == 1 {
        Ok(())
    } else if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(invalid("short control send"))
    }
}
fn send_fds(socket: &File, tag: u8, fds: &[RawFd]) -> io::Result<()> {
    if fds.is_empty() || fds.len() > 3 {
        return Err(invalid("invalid test fd count"));
    }
    let mut byte = tag;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 16];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
        ptr::copy_nonoverlapping(
            fds.as_ptr(),
            libc::CMSG_DATA(header).cast::<RawFd>(),
            fds.len(),
        );
    }
    let n = unsafe {
        libc::sendmsg(
            socket.as_raw_fd(),
            &msg,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if n == 1 {
        Ok(())
    } else if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(invalid("short test fd send"))
    }
}
fn test_socket() -> io::Result<File> {
    let raw = std::env::var_os("LSM_TEST_LIFECYCLE_TEST_FD")
        .ok_or_else(|| invalid("missing test control fd"))?;
    let fd = parse_fd(&raw)?;
    protect_fd(fd)?;
    let socket = unsafe { File::from_raw_fd(fd) };
    for (option, expected) in [
        (libc::SO_TYPE, libc::SOCK_SEQPACKET),
        (libc::SO_DOMAIN, libc::AF_UNIX),
    ] {
        let mut actual: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&mut actual as *mut libc::c_int).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if actual != expected || len as usize != size_of::<libc::c_int>() {
            return Err(invalid("invalid test control socket"));
        }
    }
    Ok(socket)
}

fn receive(socket: &File, pid: libc::pid_t, expected: u8) -> io::Result<()> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 64];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = size_of::<[usize; 64]>();
    let n = unsafe {
        libc::recvmsg(
            socket.as_raw_fd(),
            &mut msg,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut credentials = None;
    let mut valid =
        n == 1 && byte == expected && msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !header.is_null() {
        let len = unsafe { (*header).cmsg_len };
        let base = unsafe { libc::CMSG_LEN(0) } as usize;
        let offset = (header as usize).saturating_sub(msg.msg_control as usize);
        if len < base || offset > msg.msg_controllen || len > msg.msg_controllen - offset {
            valid = false;
            break;
        }
        let level = unsafe { (*header).cmsg_level };
        let kind = unsafe { (*header).cmsg_type };
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            let data = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
            for index in 0..(len - base) / size_of::<RawFd>() {
                unsafe {
                    libc::close(ptr::read_unaligned(data.add(index)));
                }
            }
            valid = false;
        } else if level == libc::SOL_SOCKET
            && kind == libc::SCM_CREDENTIALS
            && len == unsafe { libc::CMSG_LEN(size_of::<libc::ucred>() as u32) } as usize
        {
            let cred =
                unsafe { ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>()) };
            if credentials.replace(cred).is_some() {
                valid = false;
            }
        } else {
            valid = false;
        }
        header = unsafe { libc::CMSG_NXTHDR(&msg, header) };
    }
    if valid && credentials.is_some_and(|c| c.pid == pid && c.uid == 0) {
        Ok(())
    } else {
        Err(invalid("unauthenticated control packet"))
    }
}
fn readable(socket: &File, peer: &File, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(invalid("control timeout"));
        }
        let mut p = [
            libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: peer.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ms = deadline
            .saturating_duration_since(now)
            .as_millis()
            .clamp(1, i32::MAX as u128) as i32;
        let n = unsafe { libc::poll(p.as_mut_ptr(), p.len() as libc::nfds_t, ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            continue;
        }
        if p[1].revents != 0 || p[0].revents != libc::POLLIN {
            return Err(invalid("control peer lost"));
        }
        return Ok(());
    }
}
fn spawn(mode: &str, args: &[OsString], fds: &[RawFd]) -> io::Result<Child> {
    let mut command = Command::new("/proc/self/exe");
    command
        .arg(mode)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let inherited = fds.to_vec();
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0 {
                return Err(io::Error::last_os_error());
            }
            for &fd in &inherited {
                if fd < 3 || libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command.spawn()
}
fn protect_fd(fd: RawFd) -> io::Result<()> {
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn parse_fd(value: &OsStr) -> io::Result<RawFd> {
    value
        .to_str()
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|&fd| fd >= 3)
        .ok_or_else(|| invalid("invalid fd"))
}
fn parse_pid(value: &OsStr) -> io::Result<libc::pid_t> {
    value
        .to_str()
        .and_then(|s| s.parse::<libc::pid_t>().ok())
        .filter(|&pid| pid > 1)
        .ok_or_else(|| invalid("invalid pid"))
}
fn owned_fds(values: &[&OsStr]) -> io::Result<Vec<File>> {
    let mut raw = Vec::new();
    for value in values {
        let fd = parse_fd(value)?;
        if raw.contains(&fd) {
            return Err(invalid("duplicate inherited fd"));
        }
        raw.push(fd);
    }
    let mut result = Vec::new();
    for fd in raw {
        protect_fd(fd)?;
        result.push(unsafe { File::from_raw_fd(fd) });
    }
    Ok(result)
}
fn number<T: ToString>(v: T) -> OsString {
    OsString::from(v.to_string())
}
fn alive(fd: &File) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n == 0 && p.revents == 0)
    }
}
fn heartbeat(socket: &File, peer: &File, peer_pid: libc::pid_t) -> io::Result<()> {
    send(socket, b'H')?;
    readable(socket, peer, Duration::from_millis(500))?;
    receive(socket, peer_pid, b'h')?;
    if !alive(peer)? {
        return Err(invalid("guard exited"));
    }
    Ok(())
}

struct SingleReaper {
    previous: libc::sigset_t,
}
impl SingleReaper {
    fn enter() -> io::Result<Self> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        if status
            .lines()
            .find_map(|line| line.strip_prefix("Threads:")?.trim().parse::<u32>().ok())
            != Some(1)
        {
            return Err(invalid("manager must be single threaded"));
        }
        let mut action: libc::sigaction = unsafe { zeroed() };
        if unsafe { libc::sigaction(libc::SIGCHLD, ptr::null(), &mut action) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err(invalid("unsafe SIGCHLD"));
        }
        let mut all: libc::sigset_t = unsafe { zeroed() };
        let mut previous: libc::sigset_t = unsafe { zeroed() };
        if unsafe { libc::sigfillset(&mut all) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let e = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut previous) };
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e));
        }
        Ok(Self { previous })
    }
}
impl Drop for SingleReaper {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, ptr::null_mut());
        }
    }
}

fn inherited_group(
    root: PathBuf,
    parent: File,
    dir: File,
    name: CString,
    device: libc::dev_t,
    inode: libc::ino_t,
) -> io::Result<Group> {
    require_disposable_root(&root)?;
    if !valid_name(OsStr::from_bytes(name.as_bytes()), "lsm-lifecycle-") {
        return Err(invalid("invalid group name"));
    }
    let mut fs: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut fs) } != 0
        || fs.f_type as libc::c_long != CGROUP2_MAGIC
    {
        return Err(invalid("inherited group is not cgroup v2"));
    }
    let worker = openat(&dir, c"worker", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let worker_stat = metadata(worker.as_raw_fd())?;
    let events = openat(&dir, c"cgroup.events", libc::O_RDONLY)?;
    let kill = openat(&dir, c"cgroup.kill", libc::O_WRONLY)?;
    let path = root.join(OsStr::from_bytes(name.as_bytes())).join("worker");
    let group = Group {
        identity: Some(GroupIdentity {
            root,
            parent,
            name,
            device,
            inode,
            worker_device: worker_stat.st_dev,
            worker_inode: worker_stat.st_ino,
        }),
        directory: dir,
        worker,
        events,
        kill,
        path,
    };
    group.verify()?;
    Ok(group)
}
// Once the guard has authorised this scope, it must not let any possible
// creator survive the guard's own exit. On ambiguity keep the pinned FDs and
// retry; no timeout is reported as successful cleanup.
fn guard_stop_creator_and_scope(manager: &File, group: &Group, socket: &File) {
    let mut alerted = false;
    loop {
        let mut item = libc::pollfd {
            fd: manager.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut item, 1, 0) };
        if n == 1
            && item.revents & libc::POLLIN != 0
            && item.revents & (libc::POLLERR | libc::POLLNVAL) == 0
        {
            break;
        }
        if n == 0 {
            let killed = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    manager.as_raw_fd(),
                    libc::SIGKILL,
                    ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if killed != 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                && !alerted
            {
                let _ = send(socket, b'E');
                alerted = true;
            }
        } else if !alerted {
            let _ = send(socket, b'E');
            alerted = true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // A killed creator cannot later repopulate this scope. Never release the
    // pinned group on an ambiguous kill/empty result.
    if group.stop().is_err() {
        if !alerted {
            let _ = send(socket, b'E');
        }
        while group.stop().is_err() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn guard(args: &[OsString]) -> io::Result<()> {
    if args.len() != 10 {
        return Err(invalid("invalid guard arguments"));
    }
    let manager = parse_pid(&args[1])?;
    let mut fds = owned_fds(&[&args[2], &args[3], &args[4], &args[5]])?.into_iter();
    let manager_fd = fds.next().unwrap();
    let parent = fds.next().unwrap();
    let dir = fds.next().unwrap();
    let socket = fds.next().unwrap();
    let root = PathBuf::from(&args[6]);
    let name = CString::new(args[7].as_bytes()).map_err(|_| invalid("invalid group name"))?;
    let device = args[8]
        .to_str()
        .and_then(|v| v.parse::<libc::dev_t>().ok())
        .ok_or_else(|| invalid("invalid group device"))?;
    let inode = args[9]
        .to_str()
        .and_then(|v| v.parse::<libc::ino_t>().ok())
        .ok_or_else(|| invalid("invalid group inode"))?;
    let group = inherited_group(root, parent, dir, name, device, inode)?;
    channel::require_live_sender(manager_fd.as_raw_fd(), manager)?;
    readable(&socket, &manager_fd, Duration::from_secs(2))?;
    receive(&socket, manager, b'I')?;
    let own_exe = std::fs::metadata("/proc/self/exe")?;
    let manager_exe = std::fs::metadata(format!("/proc/{manager}/exe"))?;
    if (own_exe.dev(), own_exe.ino()) != (manager_exe.dev(), manager_exe.ino()) {
        return Err(invalid("manager executable mismatch"));
    }
    channel::require_live_sender(manager_fd.as_raw_fd(), manager)?;
    group.verify()?;
    send(&socket, b'R')?;
    // Once R is sent the manager may atomically create the launcher inside
    // this scope. Every subsequent error must kill/wait the whole scope.
    let registration = (|| -> io::Result<File> {
        readable(&socket, &manager_fd, Duration::from_secs(2))?;
        let launcher =
            channel::receive_worker_pidfd(socket.as_raw_fd(), manager_fd.as_raw_fd(), manager)?;
        let pid = worker_pid(&launcher)?;
        channel::require_live_sender(launcher.as_raw_fd(), pid)?;
        let mut members = String::new();
        openat(&group.directory, c"cgroup.procs", libc::O_RDONLY)?
            .take(65537)
            .read_to_string(&mut members)?;
        if members.len() > 65536
            || members.lines().collect::<Vec<_>>() != [pid.to_string().as_str()]
        {
            return Err(invalid("launcher not sole scope member"));
        }
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        let mut parents = status.lines().filter_map(|line| line.strip_prefix("PPid:"));
        if parents
            .next()
            .and_then(|v| v.trim().parse::<libc::pid_t>().ok())
            != Some(manager)
            || parents.next().is_some()
        {
            return Err(invalid("launcher parent mismatch"));
        }
        channel::require_live_sender(launcher.as_raw_fd(), pid)?;
        group.verify()?;
        send(&socket, b'L')?;
        Ok(launcher)
    })();
    let launcher = match registration {
        Ok(launcher) => launcher,
        Err(error) => {
            guard_stop_creator_and_scope(&manager_fd, &group, &socket);
            return Err(error);
        }
    };
    let mut deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let mut p = [
            libc::pollfd {
                fd: manager_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: launcher.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ms = deadline
            .saturating_duration_since(now)
            .as_millis()
            .clamp(1, i32::MAX as u128) as i32;
        let n = unsafe { libc::poll(p.as_mut_ptr(), p.len() as libc::nfds_t, ms) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if n == 0 {
            continue;
        }
        if p[0].revents != 0
            || p[2].revents != 0
            || p[1].revents != libc::POLLIN
            || receive(&socket, manager, b'H').is_err()
            || channel::require_live_sender(manager_fd.as_raw_fd(), manager).is_err()
            || send(&socket, b'h').is_err()
        {
            break;
        }
        deadline = Instant::now() + Duration::from_secs(2);
    }
    guard_stop_creator_and_scope(&manager_fd, &group, &socket);
    Ok(())
}

struct LauncherGuard {
    manager: libc::pid_t,
    manager_fd: File,
    socket: File,
    group_dev: libc::dev_t,
    group_ino: libc::ino_t,
}
impl gated::ExternalGuard for LauncherGuard {
    fn validate(&mut self, group: &File) -> io::Result<()> {
        channel::require_live_sender(self.manager_fd.as_raw_fd(), self.manager)?;
        let stat = metadata(group.as_raw_fd())?;
        if stat.st_dev != self.group_dev || stat.st_ino != self.group_ino {
            return Err(invalid("launcher group changed"));
        }
        Ok(())
    }
    fn register_worker(&mut self, worker: &File) -> io::Result<()> {
        channel::require_live_sender(self.manager_fd.as_raw_fd(), self.manager)?;
        channel::send_worker_pidfd(self.socket.as_raw_fd(), worker.as_raw_fd())?;
        readable(&self.socket, &self.manager_fd, Duration::from_secs(2))?;
        receive(&self.socket, self.manager, b'A')?;
        channel::require_live_sender(self.manager_fd.as_raw_fd(), self.manager)
    }
}
fn snapshot() -> io::Result<File> {
    let source = File::open("/proc/self/exe")?;
    let mut fd = unsafe {
        libc::memfd_create(
            c"lsm-lifecycle-test".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | 0x10,
        )
    };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        fd = unsafe {
            libc::memfd_create(
                c"lsm-lifecycle-test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
    }
    let mut result = file(fd)?;
    let copied = io::copy(&mut source.take(64 * 1024 * 1024), &mut result)?;
    if copied == 0 || copied == 64 * 1024 * 1024 {
        return Err(invalid("invalid executable snapshot"));
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(result.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}
fn stop_worker(worker: &mut gated::Worker) -> io::Result<()> {
    let stop = worker.stop();
    let wait = worker.wait_stopped();
    match (stop, wait) {
        (Ok(()), Ok(status)) if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) => Ok(()),
        (Err(stop), Ok(status))
            if stop.cgroup_kill.is_none()
                && stop
                    .worker_signal
                    .as_ref()
                    .and_then(io::Error::raw_os_error)
                    == Some(libc::ESRCH)
                && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) =>
        {
            Ok(())
        }
        (stop, wait) => Err(io::Error::other(format!(
            "worker stop: {stop:?}; wait: {wait:?}"
        ))),
    }
}
fn launcher(args: &[OsString]) -> io::Result<()> {
    if args.len() != 6 {
        return Err(invalid("invalid launcher arguments"));
    }
    let manager = parse_pid(&args[1])?;
    let mut fds = owned_fds(&[&args[2], &args[3], &args[4]])?.into_iter();
    let manager_fd = fds.next().unwrap();
    let group = fds.next().unwrap();
    let socket = fds.next().unwrap();
    channel::require_live_sender(manager_fd.as_raw_fd(), manager)?;
    readable(&socket, &manager_fd, Duration::from_secs(2))?;
    receive(&socket, manager, b'S')?;
    channel::require_live_sender(manager_fd.as_raw_fd(), manager)?;
    let st = metadata(group.as_raw_fd())?;
    let mut guard = LauncherGuard {
        manager,
        manager_fd,
        socket,
        group_dev: st.st_dev,
        group_ino: st.st_ino,
    };
    let marker = CString::new(args[5].as_bytes()).map_err(|_| invalid("invalid marker path"))?;
    let command = gated::PinnedCommand {
        executable: snapshot()?,
        argv: vec![
            CString::new("lifecycle-test").unwrap(),
            CString::new("--payload").unwrap(),
            marker,
        ],
        environment: Vec::new(),
    };
    let mut worker = match gated::prepare(&mut guard, group, command) {
        Ok(worker) => worker,
        Err(gated::StartFailure::BeforeSpawn(e)) => return Err(e),
        Err(gated::StartFailure::AfterSpawn { cause, mut worker }) => {
            let cleanup = stop_worker(&mut worker);
            return Err(io::Error::other(format!(
                "prepare: {cause}; cleanup: {cleanup:?}"
            )));
        }
    };
    let run = (|| -> io::Result<()> {
        send(&guard.socket, b'R')?;
        readable(&guard.socket, &guard.manager_fd, Duration::from_secs(10))?;
        receive(&guard.socket, guard.manager, b'G')?;
        channel::require_live_sender(guard.manager_fd.as_raw_fd(), guard.manager)?;
        worker.go(&mut guard)?;
        loop {
            if !alive(&guard.manager_fd)? {
                return Err(invalid("manager exited"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })();
    let cleanup = stop_worker(&mut worker);
    match (run, cleanup) {
        (Err(run), Err(cleanup)) => Err(io::Error::other(format!(
            "launcher: {run}; cleanup: {cleanup}"
        ))),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Ok(()), Ok(())) => Ok(()),
    }
}
fn payload(marker: &Path) -> io::Result<()> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            if libc::setsid() < 0 {
                libc::_exit(1);
            }
            let b = b'S';
            if libc::write(fds[1], (&b as *const u8).cast(), 1) != 1 {
                libc::_exit(1);
            }
            loop {
                libc::pause();
            }
        }
    }
    unsafe {
        libc::close(fds[1]);
    }
    let mut b = 0u8;
    let n = unsafe { libc::read(fds[0], (&mut b as *mut u8).cast(), 1) };
    unsafe {
        libc::close(fds[0]);
    }
    if n != 1 || b != b'S' {
        return Err(invalid("setsid child failed"));
    }
    let partial = marker.with_extension("partial");
    std::fs::write(&partial, format!("{} {pid}", unsafe { libc::getpid() }))?;
    std::fs::rename(partial, marker)?;
    loop {
        unsafe {
            libc::pause();
        }
    }
}

struct ManagedChild {
    child: Child,
    pidfd: Option<File>,
}
struct AtomicLauncher {
    pid: libc::pid_t,
    pidfd: File,
    reaped: bool,
}
struct LauncherSpec<'a> {
    keep: &'a [RawFd],
    inherited: &'a [RawFd],
    executable: RawFd,
    stop_before_exec: bool,
    argv: &'a [*const libc::c_char],
    env: &'a [*const libc::c_char],
}
// The post-clone path performs only stack operations and async-signal-safe
// kernel calls. The caller is single-threaded and has blocked signals.
unsafe fn launcher_child(spec: &LauncherSpec<'_>) -> ! {
    // Disposable-only trace: one raw write before the first test syscall,
    // allowing CI to distinguish pre-userspace death from tgkill failure.
    if spec.stop_before_exec {
        let entered = b"lifecycle child: entered\n";
        libc::write(libc::STDERR_FILENO, entered.as_ptr().cast(), entered.len());
        if libc::syscall(
            libc::SYS_tgkill,
            libc::getpid(),
            libc::syscall(libc::SYS_gettid),
            libc::SIGSTOP,
        ) != 0
        {
            libc::_exit(128 + (*libc::__errno_location() & 127));
        }
        let resumed = b"lifecycle child: stop returned\n";
        libc::write(libc::STDERR_FILENO, resumed.as_ptr().cast(), resumed.len());
    }
    let mut first = 3u32;
    for &raw in spec.keep {
        let end = raw as u32;
        if first < end && libc::syscall(libc::SYS_close_range, first, end - 1, 0u32) != 0 {
            libc::_exit(120);
        }
        first = end + 1;
    }
    if libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32) != 0 {
        libc::_exit(120);
    }
    libc::close(0);
    libc::close(1);
    libc::close(2);
    for &fd in spec.inherited {
        if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
            libc::_exit(121);
        }
    }
    libc::syscall(
        libc::SYS_execveat,
        spec.executable,
        c"".as_ptr(),
        spec.argv.as_ptr(),
        spec.env.as_ptr(),
        libc::AT_EMPTY_PATH,
    );
    libc::_exit(122)
}
fn spawn_atomic_launcher(
    scope: &File,
    args: &[OsString],
    inherited: &[RawFd],
) -> io::Result<AtomicLauncher> {
    let executable = snapshot()?;
    let mut values = vec![
        CString::new("lsm-lifecycle-test").unwrap(),
        CString::new("--launcher").unwrap(),
    ];
    for arg in args {
        values.push(
            CString::new(arg.as_bytes()).map_err(|_| invalid("launcher argument contains NUL"))?,
        );
    }
    let mut argv: Vec<_> = values.iter().map(|value| value.as_ptr()).collect();
    argv.push(ptr::null());
    let mut env_values = Vec::new();
    if std::env::var_os("LSM_TEST_LIFECYCLE_STOP_BEFORE_CLONE").as_deref() == Some(OsStr::new("1"))
    {
        env_values.push(CString::new("LSM_TEST_LIFECYCLE_STOP_BEFORE_CLONE=1").unwrap());
    }
    let mut env: Vec<_> = env_values.iter().map(|value| value.as_ptr()).collect();
    env.push(ptr::null());
    let mut keep = inherited.to_vec();
    keep.push(executable.as_raw_fd());
    keep.sort_unstable();
    if keep.iter().any(|&fd| fd < 3) || keep.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("invalid launcher inherited FDs"));
    }
    let spec = LauncherSpec {
        keep: &keep,
        inherited,
        executable: executable.as_raw_fd(),
        stop_before_exec: std::env::var_os("LSM_TEST_LIFECYCLE_STOP_MANAGER_AFTER_GUARD")
            .as_deref()
            == Some(OsStr::new("1")),
        argv: &argv,
        env: &env,
    };
    let mut raw: libc::c_int = -1;
    let mut clone: libc::clone_args = unsafe { zeroed() };
    clone.flags = libc::CLONE_PIDFD as u64 | 0x2_0000_0000;
    clone.pidfd = (&mut raw as *mut libc::c_int) as u64;
    clone.exit_signal = libc::SIGCHLD as u64;
    clone.cgroup = scope.as_raw_fd() as u64;
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &clone as *const libc::clone_args,
            size_of::<libc::clone_args>(),
        )
    };
    if result == 0 {
        unsafe { launcher_child(&spec) }
    }
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // No fallback: a contract violation leaves the scope for guard cleanup.
    if raw < 0 {
        return Err(invalid("atomic launcher pidfd unavailable"));
    }
    Ok(AtomicLauncher {
        pid: result as libc::pid_t,
        pidfd: unsafe { File::from_raw_fd(raw) },
        reaped: false,
    })
}
fn signal_launcher(slot: &mut Option<AtomicLauncher>) -> io::Result<()> {
    let Some(item) = slot.as_mut() else {
        return Ok(());
    };
    let n = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            item.pidfd.as_raw_fd(),
            libc::SIGKILL,
            ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if n == 0 {
        Ok(())
    } else {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(e)
        }
    }
}
fn reap_launcher(slot: &mut Option<AtomicLauncher>) -> io::Result<()> {
    let Some(item) = slot.as_mut() else {
        return Ok(());
    };
    if item.reaped {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut status = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(invalid("launcher reap timed out"));
        }
        let n = unsafe { libc::waitpid(item.pid, &mut status, libc::WNOHANG) };
        if n == item.pid {
            item.reaped = true;
            return Ok(());
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn spawn_tracked(
    slot: &mut Option<ManagedChild>,
    mode: &str,
    args: &[OsString],
    fds: &[RawFd],
) -> io::Result<()> {
    *slot = Some(ManagedChild {
        child: spawn(mode, args, fds)?,
        pidfd: None,
    });
    let item = slot.as_mut().unwrap();
    item.pidfd = Some(pidfd(item.child.id() as libc::pid_t)?);
    Ok(())
}
fn signal_child(slot: &mut Option<ManagedChild>) -> io::Result<()> {
    let Some(item) = slot.as_mut() else {
        return Ok(());
    };
    if item.child.try_wait()?.is_some() {
        return Ok(());
    }
    let fd = item
        .pidfd
        .as_ref()
        .ok_or_else(|| invalid("child pidfd unavailable; no numeric signal"))?;
    let n = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if n == 0 {
        Ok(())
    } else {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(e)
        }
    }
}
fn reap_child(slot: &mut Option<ManagedChild>) -> io::Result<()> {
    let Some(item) = slot.as_mut() else {
        return Ok(());
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if item.child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(invalid("child reap timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn group_members(group: &Group) -> io::Result<Vec<libc::pid_t>> {
    let mut text = String::new();
    openat(&group.worker, c"cgroup.procs", libc::O_RDONLY)?
        .take(65537)
        .read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(invalid("oversized cgroup.procs"));
    }
    text.lines()
        .map(|line| {
            line.parse::<libc::pid_t>()
                .map_err(|_| invalid("invalid cgroup member"))
        })
        .collect()
}
fn worker_pid(fd: &File) -> io::Result<libc::pid_t> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?;
    let mut values = text.lines().filter_map(|line| line.strip_prefix("Pid:"));
    let pid = values
        .next()
        .and_then(|s| s.trim().parse::<libc::pid_t>().ok())
        .filter(|&pid| pid > 0)
        .ok_or_else(|| invalid("invalid worker pidfd"))?;
    if values.next().is_some() {
        return Err(invalid("duplicate worker pid"));
    }
    Ok(pid)
}
fn require_worker(
    group: &Group,
    worker: &File,
    launcher: &File,
    launcher_pid: libc::pid_t,
) -> io::Result<libc::pid_t> {
    let pid = worker_pid(worker)?;
    channel::require_live_sender(worker.as_raw_fd(), pid)?;
    channel::require_live_sender(launcher.as_raw_fd(), launcher_pid)?;
    if group_members(group)? != [pid] {
        return Err(invalid("worker not sole cgroup member"));
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let mut parents = status.lines().filter_map(|line| line.strip_prefix("PPid:"));
    if parents
        .next()
        .and_then(|s| s.trim().parse::<libc::pid_t>().ok())
        != Some(launcher_pid)
        || parents.next().is_some()
    {
        return Err(invalid("worker parent mismatch"));
    }
    if group_members(group)? != [pid] {
        return Err(invalid("worker group changed"));
    }
    channel::require_live_sender(worker.as_raw_fd(), pid)?;
    channel::require_live_sender(launcher.as_raw_fd(), launcher_pid)?;
    Ok(pid)
}
fn wait_guarded(
    target: RawFd,
    guard: &File,
    guard_socket: &File,
    guard_pid: libc::pid_t,
    launcher: &File,
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(invalid("guarded wait timed out"));
        }
        if !alive(launcher)? {
            return Err(invalid("launcher exited"));
        }
        heartbeat(guard_socket, guard, guard_pid)?;
        let mut p = [
            libc::pollfd {
                fd: target,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: guard.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: launcher.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = unsafe { libc::poll(p.as_mut_ptr(), p.len() as libc::nfds_t, 100) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if p[1].revents != 0 || p[2].revents != 0 {
            return Err(invalid("supervisor exited"));
        }
        if p[0].revents == libc::POLLIN {
            return Ok(());
        }
        if p[0].revents != 0 {
            return Err(invalid("target channel failed"));
        }
    }
}
fn manager_inner(
    group: &Group,
    marker: &Path,
    test_socket: &File,
    guard_slot: &mut Option<ManagedChild>,
    launcher_slot: &mut Option<AtomicLauncher>,
) -> io::Result<()> {
    group.verify()?;
    let own = unsafe { libc::getpid() };
    let own_fd = pidfd(own)?;
    let (guard_socket, guard_child_socket) = packet_pair()?;
    let identity = group
        .identity
        .as_ref()
        .ok_or_else(|| invalid("missing group identity"))?;
    let guard_args = [
        number(own),
        number(own_fd.as_raw_fd()),
        number(identity.parent.as_raw_fd()),
        number(group.directory.as_raw_fd()),
        number(guard_child_socket.as_raw_fd()),
        identity.root.as_os_str().to_os_string(),
        OsString::from(OsStr::from_bytes(identity.name.as_bytes())),
        number(identity.device),
        number(identity.inode),
    ];
    spawn_tracked(
        guard_slot,
        "--guard",
        &guard_args,
        &[
            own_fd.as_raw_fd(),
            identity.parent.as_raw_fd(),
            group.directory.as_raw_fd(),
            guard_child_socket.as_raw_fd(),
        ],
    )?;
    drop(guard_child_socket);
    let guard = guard_slot.as_ref().unwrap();
    let guard_fd = guard
        .pidfd
        .as_ref()
        .ok_or_else(|| invalid("guard pidfd unavailable"))?;
    let guard_pid = guard.child.id() as libc::pid_t;
    send(&guard_socket, b'I')?;
    readable(&guard_socket, guard_fd, Duration::from_secs(2))?;
    receive(&guard_socket, guard_pid, b'R')?;
    if std::env::var_os("LSM_TEST_LIFECYCLE_STOP_MANAGER_AFTER_GUARD").as_deref()
        == Some(OsStr::new("1"))
    {
        send_fds(
            test_socket,
            b'B',
            &[own_fd.as_raw_fd(), guard_fd.as_raw_fd()],
        )?;
        println!("MANAGER-GATE {guard_pid} {}", group.path.display());
        io::stdout().flush()?;
        let mut item = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut item, 1, 10000) } != 1 || item.revents != libc::POLLIN {
            return Err(invalid("manager test barrier ended"));
        }
        let mut command = [0u8];
        io::stdin().read_exact(&mut command)?;
        if command != [b'C'] {
            return Err(invalid("invalid manager test barrier"));
        }
    }
    let (manager_socket, launcher_socket) = packet_pair()?;
    let args = [
        number(own),
        number(own_fd.as_raw_fd()),
        number(group.worker.as_raw_fd()),
        number(launcher_socket.as_raw_fd()),
        marker.as_os_str().to_os_string(),
    ];
    // The launcher itself is atomically born inside the monitored parent;
    // a crash before registration therefore cannot leave it outside kill scope.
    *launcher_slot = Some(spawn_atomic_launcher(
        &group.directory,
        &args,
        &[
            own_fd.as_raw_fd(),
            group.worker.as_raw_fd(),
            launcher_socket.as_raw_fd(),
        ],
    )?);
    drop(launcher_socket);
    let launcher = launcher_slot.as_ref().unwrap();
    let launcher_fd = &launcher.pidfd;
    let launcher_pid = launcher.pid;
    if std::env::var_os("LSM_TEST_LIFECYCLE_STOP_MANAGER_AFTER_GUARD").as_deref()
        == Some(OsStr::new("1"))
    {
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                launcher_fd.as_raw_fd(),
                libc::SIGSTOP,
                ptr::null::<libc::siginfo_t>(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let mut info: libc::siginfo_t = unsafe { zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    launcher_pid as libc::id_t,
                    &mut info,
                    libc::WSTOPPED | libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { info.si_pid() } != 0 {
                if info.si_code != libc::CLD_STOPPED {
                    return Err(io::Error::other(format!(
                        "post-timeout launcher event code={} status={}",
                        info.si_code,
                        unsafe { info.si_status() }
                    )));
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(invalid("post-timeout launcher stop timed out"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        send_fds(test_socket, b'C', &[launcher_fd.as_raw_fd()])?;
        println!("CLONED {launcher_pid} {}", group.path.display());
        io::stdout().flush()?;
        let mut item = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = unsafe { libc::poll(&mut item, 1, 5000) };
        return Err(invalid("post-timeout clone observed"));
    }
    if std::env::var_os("LSM_TEST_LIFECYCLE_STOP_BEFORE_REGISTRATION").as_deref()
        == Some(OsStr::new("1"))
    {
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                launcher_fd.as_raw_fd(),
                libc::SIGSTOP,
                ptr::null::<libc::siginfo_t>(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let mut info: libc::siginfo_t = unsafe { zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    launcher_pid as libc::id_t,
                    &mut info,
                    libc::WSTOPPED | libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { info.si_pid() } != 0 {
                if info.si_code != libc::CLD_STOPPED {
                    return Err(invalid("launcher exited before registration barrier"));
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(invalid("registration barrier timed out"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        send_fds(
            test_socket,
            b'U',
            &[
                own_fd.as_raw_fd(),
                guard_fd.as_raw_fd(),
                launcher_fd.as_raw_fd(),
            ],
        )?;
        println!(
            "REGISTER-GATE {guard_pid} {launcher_pid} {}",
            group.path.display()
        );
        io::stdout().flush()?;
        // No GO: the disposable test terminates the manager at this barrier.
        let mut item = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut item, 1, 1000) } != 1 {
            return Err(invalid("registration test barrier ended"));
        }
        return Err(invalid("unexpected registration barrier input"));
    }
    channel::send_worker_pidfd(guard_socket.as_raw_fd(), launcher_fd.as_raw_fd())?;
    readable(&guard_socket, guard_fd, Duration::from_secs(2))?;
    receive(&guard_socket, guard_pid, b'L')?;
    channel::require_live_sender(guard_fd.as_raw_fd(), guard_pid)?;
    send(&manager_socket, b'S')?;
    if std::env::var_os("LSM_TEST_LIFECYCLE_STOP_BEFORE_CLONE").as_deref() == Some(OsStr::new("1"))
    {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let mut info: libc::siginfo_t = unsafe { zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    launcher_pid as libc::id_t,
                    &mut info,
                    libc::WSTOPPED | libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { info.si_pid() } != 0 {
                if info.si_code != libc::CLD_STOPPED {
                    return Err(invalid("launcher exited before clone barrier"));
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(invalid("pre-clone barrier timed out"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        send_fds(
            test_socket,
            b'T',
            &[
                own_fd.as_raw_fd(),
                guard_fd.as_raw_fd(),
                launcher_fd.as_raw_fd(),
            ],
        )?;
        println!(
            "CLONE-GATE {guard_pid} {launcher_pid} {}",
            group.path.display()
        );
        io::stdout().flush()?;
    }
    let worker = channel::receive_worker_pidfd(
        manager_socket.as_raw_fd(),
        launcher_fd.as_raw_fd(),
        launcher_pid,
    )?;
    let worker_pid = require_worker(group, &worker, launcher_fd, launcher_pid)?;
    heartbeat(&guard_socket, guard_fd, guard_pid)?;
    send(&manager_socket, b'A')?;
    wait_guarded(
        manager_socket.as_raw_fd(),
        guard_fd,
        &guard_socket,
        guard_pid,
        launcher_fd,
        Duration::from_secs(5),
    )?;
    receive(&manager_socket, launcher_pid, b'R')?;
    group.verify()?;
    send_fds(
        test_socket,
        b'P',
        &[own_fd.as_raw_fd(), guard_fd.as_raw_fd(), worker.as_raw_fd()],
    )?;
    println!("PREPARED {guard_pid} {worker_pid} {}", group.path.display());
    io::stdout().flush()?;
    wait_guarded(
        libc::STDIN_FILENO,
        guard_fd,
        &guard_socket,
        guard_pid,
        launcher_fd,
        Duration::from_secs(10),
    )?;
    let mut command = [0u8];
    io::stdin().read_exact(&mut command)?;
    if command != [b'G'] {
        return Err(invalid("invalid GO request"));
    }
    heartbeat(&guard_socket, guard_fd, guard_pid)?;
    group.verify()?;
    send(&manager_socket, b'G')?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let descendant = loop {
        if Instant::now() >= deadline {
            return Err(invalid("worker marker timeout"));
        }
        if !alive(&worker)? || !alive(launcher_fd)? {
            return Err(invalid("worker or launcher exited"));
        }
        heartbeat(&guard_socket, guard_fd, guard_pid)?;
        if let Ok(text) = std::fs::read_to_string(marker) {
            let parts: Vec<_> = text
                .split_whitespace()
                .filter_map(|v| v.parse::<libc::pid_t>().ok())
                .collect();
            let members = group_members(group)?;
            if parts.len() != 2
                || parts[0] != worker_pid
                || !members.contains(&parts[0])
                || !members.contains(&parts[1])
            {
                return Err(invalid("invalid worker marker"));
            }
            break parts[1];
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let descendant_fd = pidfd(descendant)?;
    channel::require_live_sender(descendant_fd.as_raw_fd(), descendant)?;
    let descendant_status = std::fs::read_to_string(format!("/proc/{descendant}/status"))?;
    let mut parents = descendant_status
        .lines()
        .filter_map(|line| line.strip_prefix("PPid:"));
    if parents
        .next()
        .and_then(|s| s.trim().parse::<libc::pid_t>().ok())
        != Some(worker_pid)
        || parents.next().is_some()
        || !group_members(group)?.contains(&descendant)
    {
        return Err(invalid("descendant identity mismatch"));
    }
    channel::require_live_sender(descendant_fd.as_raw_fd(), descendant)?;
    send_fds(test_socket, b'D', &[descendant_fd.as_raw_fd()])?;
    println!("RUNNING {descendant}");
    io::stdout().flush()?;
    loop {
        if !alive(&worker)? || !alive(launcher_fd)? {
            return Err(invalid("worker or launcher exited"));
        }
        heartbeat(&guard_socket, guard_fd, guard_pid)?;
        std::thread::sleep(Duration::from_millis(100));
    }
}
pub(crate) fn run_disposable_manager(root: &Path) -> io::Result<()> {
    let _reaper = SingleReaper::enter()?;
    let group = Group::create(root)?;
    let marker = std::env::var_os("LSM_TEST_LIFECYCLE_MARKER")
        .map(PathBuf::from)
        .ok_or_else(|| invalid("missing disposable marker"))?;
    let test_socket = test_socket()?;
    let mut guard = None;
    let mut launcher = None;
    let run = manager_inner(&group, &marker, &test_socket, &mut guard, &mut launcher);
    let signal_launcher = signal_launcher(&mut launcher);
    let stop_group = group.stop();
    let reap_launcher = reap_launcher(&mut launcher);
    let signal_guard = if stop_group.is_ok() {
        signal_child(&mut guard)
    } else {
        Err(invalid(
            "guard retained because cgroup empty was not confirmed",
        ))
    };
    let reap_guard = reap_child(&mut guard);
    let mut errors = Vec::new();
    for (label, result) in [
        ("manager", run),
        ("launcher signal", signal_launcher),
        ("group", stop_group),
        ("launcher reap", reap_launcher),
        ("guard signal", signal_guard),
        ("guard reap", reap_guard),
    ] {
        if let Err(error) = result {
            errors.push(format!("{label}: {error}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(errors.join("; ")))
    }
}
pub(crate) fn run(args: Vec<OsString>) -> io::Result<()> {
    match args.get(1).map(OsString::as_os_str) {
        Some(mode) if mode == OsStr::new("--manager") && args.len() == 3 => {
            run_disposable_manager(Path::new(&args[2]))
        }
        Some(mode) if mode == OsStr::new("--guard") => guard(&args[1..]),
        Some(mode) if mode == OsStr::new("--launcher") => launcher(&args[1..]),
        Some(mode) if mode == OsStr::new("--payload") && args.len() == 3 => {
            payload(Path::new(&args[2]))
        }
        _ => Err(invalid("invalid lifecycle mode")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn non_cgroup_root_is_rejected_without_changes() {
        let root =
            std::env::temp_dir().join(format!("lsm-lifecycle-not-cgroup-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let result = Group::create(&root);
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir(root).unwrap();
    }
}
