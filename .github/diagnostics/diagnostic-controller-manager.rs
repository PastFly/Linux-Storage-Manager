//! Disposable controller experiment. Not an execution gate or safety proof.
//! Stops the cgroup on observed loss; scheduler stalls, simultaneous stops,
//! forced lease breaks and already-submitted I/O remain outside its guarantees.
use super::{backup_supervisor as supervisor, diagnostic_channel as channel, gated};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn pidfd(pid: libc::pid_t) -> io::Result<File> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn live(fd: &File) -> io::Result<bool> {
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
fn group_has(group: &File, pid: libc::pid_t) -> io::Result<bool> {
    let fd = unsafe {
        libc::openat(
            group.as_raw_fd(),
            c"cgroup.procs".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut text = String::new();
    file.take(65537).read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(invalid("oversized cgroup.procs"));
    }
    Ok(text
        .lines()
        .any(|line| line.parse::<libc::pid_t>() == Ok(pid)))
}
fn pidfd_pid(fd: &File) -> io::Result<libc::pid_t> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?;
    let mut values = text.lines().filter_map(|line| line.strip_prefix("Pid:"));
    let pid = values
        .next()
        .and_then(|line| line.trim().parse::<libc::pid_t>().ok())
        .filter(|&pid| pid > 0)
        .ok_or_else(|| invalid("invalid worker pidfd"))?;
    if values.next().is_some() {
        return Err(invalid("ambiguous worker pidfd"));
    }
    Ok(pid)
}
fn socket_pair() -> io::Result<(File, File)> {
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
                std::mem::size_of_val(&one) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((a, b))
}
fn send_ack(socket: &File) -> io::Result<()> {
    if unsafe {
        libc::send(
            socket.as_raw_fd(),
            b"A".as_ptr().cast(),
            1,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    } != 1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
struct ManagerGuard {
    manager: libc::pid_t,
    pidfd: File,
    socket: File,
    dev: u64,
    ino: u64,
}
impl gated::ExternalGuard for ManagerGuard {
    fn validate(&mut self, group: &File) -> io::Result<()> {
        channel::require_live_sender(self.pidfd.as_raw_fd(), self.manager)?;
        let m = group.metadata()?;
        if (m.dev(), m.ino()) != (self.dev, self.ino) {
            return Err(invalid("group mismatch"));
        }
        Ok(())
    }
    fn register_worker(&mut self, worker: &File) -> io::Result<()> {
        channel::require_live_sender(self.pidfd.as_raw_fd(), self.manager)?;
        channel::send_worker_pidfd(self.socket.as_raw_fd(), worker.as_raw_fd())?;
        supervisor::diagnostic_wait_peer(&self.socket, &self.pidfd)?;
        supervisor::diagnostic_receive_byte(&self.socket, self.manager, b'A')?;
        channel::require_live_sender(self.pidfd.as_raw_fd(), self.manager)
    }
}
pub fn launcher(group_path: &Path, manager: &OsStr, raw: &OsStr, marker: &Path) -> io::Result<()> {
    let manager = manager
        .to_str()
        .and_then(|s| s.parse::<libc::pid_t>().ok())
        .ok_or_else(|| invalid("invalid manager pid"))?;
    let raw = raw
        .to_str()
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|&s| s >= 3)
        .ok_or_else(|| invalid("invalid channel"))?;
    let socket = unsafe { File::from_raw_fd(raw) };
    let manager_fd = pidfd(manager)?;
    let group = File::open(group_path)?;
    let m = group.metadata()?;
    let mut guard = ManagerGuard {
        manager,
        pidfd: manager_fd,
        socket,
        dev: m.dev(),
        ino: m.ino(),
    };
    let command = gated::PinnedCommand {
        executable: super::snapshot()?,
        argv: vec![
            CString::new("gated-test").unwrap(),
            CString::new("--payload-session").unwrap(),
            CString::new(marker.as_os_str().as_encoded_bytes())
                .map_err(|_| invalid("marker path"))?,
        ],
        environment: Vec::new(),
    };
    let mut worker = match gated::prepare(&mut guard, group, command) {
        Ok(worker) => worker,
        Err(gated::StartFailure::BeforeSpawn(e)) => return Err(e),
        Err(gated::StartFailure::AfterSpawn { cause, mut worker }) => {
            let cleanup = super::stop_and_wait(&mut worker);
            return Err(io::Error::other(format!(
                "prepare: {cause}; cleanup: {cleanup:?}"
            )));
        }
    };
    if let Err(error) = worker.go(&mut guard) {
        let cleanup = super::stop_and_wait(&mut worker);
        return Err(io::Error::other(format!(
            "GO: {error}; cleanup: {cleanup:?}"
        )));
    }
    // Every post-GO outcome reaches cleanup, including poll errors.
    let run = (|| -> io::Result<()> {
        let mut item = libc::pollfd {
            fd: guard.socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let n = unsafe { libc::poll(&mut item, 1, 100) };
            if std::env::var_os("LSM_TEST_POST_GO_POLL_FAULT").as_deref() == Some(OsStr::new("1"))
                && marker.with_extension("fault").exists()
            {
                return Err(invalid("injected post-GO poll failure"));
            }
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n > 0 || !live(&guard.pidfd)? {
                return Err(invalid("manager channel or pidfd lost"));
            }
        }
    })();
    let cleanup = super::stop_and_wait(&mut worker);
    match (run, cleanup) {
        (Err(run), Err(cleanup)) => Err(io::Error::other(format!(
            "launcher: {run}; cleanup: {cleanup}"
        ))),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

pub fn payload(marker: &Path) -> io::Result<()> {
    let mut pipe = [-1; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::close(pipe[0]);
            if libc::setsid() < 0 {
                libc::_exit(1);
            }
            let byte = b'S';
            if libc::write(pipe[1], (&byte as *const u8).cast(), 1) != 1 {
                libc::_exit(1);
            }
            loop {
                libc::pause();
            }
        }
    }
    unsafe {
        libc::close(pipe[1]);
    }
    let mut byte = 0u8;
    let n = unsafe { libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1) };
    unsafe {
        libc::close(pipe[0]);
    }
    if n != 1 || byte != b'S' {
        return Err(invalid("setsid child failed"));
    }
    std::fs::write(marker, format!("{} {pid}", unsafe { libc::getpid() }))?;
    loop {
        unsafe {
            libc::pause();
        }
    }
}
pub fn manager(root: &Path, observer: &OsStr, backup: &Path) -> io::Result<()> {
    let guard =
        supervisor::BackupSupervisor::start_watchdog_at(vec![File::open(backup)?], root, observer)?;
    let result = run_manager(&guard, backup);
    let cleanup = guard.diagnostic_kill_and_wait();
    match (result, cleanup) {
        (Err(run), Err(cleanup)) => Err(io::Error::other(format!(
            "manager: {run}; cleanup: {cleanup}"
        ))),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}
fn run_manager(guard: &supervisor::BackupSupervisor, backup: &Path) -> io::Result<()> {
    let (group, path) = guard.diagnostic_group()?;
    let (observer_fd, observer_pid) = guard.diagnostic_observer()?;
    let (manager, launcher) = socket_pair()?;
    let marker = backup.with_extension("worker");
    let raw = launcher.as_raw_fd();
    let mut command = Command::new("/proc/self/exe");
    command
        .arg("--diagnostic-launcher")
        .arg(&path)
        .arg(unsafe { libc::getpid() }.to_string())
        .arg(raw.to_string())
        .arg(&marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(raw, libc::F_SETFD, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    guard.diagnostic_heartbeat()?;
    let mut child = command.spawn()?;
    let launcher_fd = pidfd(child.id() as libc::pid_t)?;
    drop(launcher);
    // Diagnostic red case: the launcher is outside the worker cgroup and
    // must still be killed/reaped after a failure before registration.
    if std::env::var_os("LSM_TEST_FAIL_WITH_STOPPED_LAUNCHER").as_deref() == Some(OsStr::new("1")) {
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                launcher_fd.as_raw_fd(),
                libc::SIGSTOP,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.id() as libc::id_t,
                    &mut info,
                    libc::WSTOPPED | libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { info.si_pid() } != 0 {
                if info.si_code != libc::CLD_STOPPED {
                    return Err(invalid("launcher exited before stop"));
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(invalid("launcher stop timed out"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        println!("LAUNCHER {} {}", child.id(), path.display());
        io::stdout().flush()?;
        return Err(invalid("injected failure with stopped launcher"));
    }
    let worker = channel::receive_worker_pidfd(
        manager.as_raw_fd(),
        launcher_fd.as_raw_fd(),
        child.id() as libc::pid_t,
    )?;
    let worker_pid = pidfd_pid(&worker)?;
    channel::require_live_sender(worker.as_raw_fd(), worker_pid)?;
    if !group_has(&group, worker_pid)? {
        return Err(invalid("worker outside group"));
    }
    guard.diagnostic_heartbeat()?;
    if std::env::var_os("LSM_TEST_PAUSE_BEFORE_GO").as_deref() == Some(OsStr::new("1")) {
        println!(
            "GATE {observer_pid} {worker_pid} {} {}",
            child.id(),
            path.display()
        );
        io::stdout().flush()?;
        let mut poll = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 1000) } != 1 || poll.revents != libc::POLLIN {
            return Err(invalid("pre-GO barrier timed out"));
        }
        let mut byte = [0u8];
        io::stdin().read_exact(&mut byte)?;
        if byte != [b'C'] {
            return Err(invalid("invalid barrier command"));
        }
    }
    // This catches the explicit test barrier, but cannot eliminate a break
    // after this point; it must never be interpreted as permission to mutate.
    guard.diagnostic_heartbeat()?;
    send_ack(&manager)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let descendant = loop {
        if Instant::now() >= deadline {
            return Err(invalid("worker did not become active"));
        }
        if !live(&launcher_fd)? || !live(&worker)? || !live(&observer_fd)? {
            return Err(invalid("process died before active"));
        }
        if let Ok(text) = std::fs::read_to_string(&marker) {
            let values: Vec<_> = text
                .split_whitespace()
                .filter_map(|v| v.parse::<libc::pid_t>().ok())
                .collect();
            if values.len() != 2 || values[0] != worker_pid || !group_has(&group, values[1])? {
                return Err(invalid("invalid worker marker"));
            }
            break values[1];
        }
        guard.diagnostic_heartbeat()?;
        std::thread::sleep(Duration::from_millis(100));
    };
    println!(
        "ACTIVE {observer_pid} {worker_pid} {descendant} {} {}",
        child.id(),
        path.display()
    );
    io::stdout().flush()?;
    loop {
        if !live(&launcher_fd)? || !live(&worker)? || !live(&observer_fd)? {
            break;
        }
        guard.diagnostic_heartbeat()?;
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.try_wait();
    Err(invalid("supervised process exited"))
}
