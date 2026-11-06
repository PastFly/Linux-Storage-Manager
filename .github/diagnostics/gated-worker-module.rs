//! Test-only reusable Linux worker-launch experiment. NOT a production gate.
//!
//! The caller supplies an already verified external guard and a fresh dedicated
//! cgroup v2 directory. Guard validation and the following syscall are NOT
//! atomic. The caller must run this in a single-threaded sole-reaper process,
//! keep the guard alive, and monitor it concurrently while the worker runs.
//! This module does not persist a journal, hold backup leases, authenticate a
//! guard, prevent privileged cgroup migration, or stop kernel I/O in flight.
#![allow(dead_code)]

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::marker::PhantomData;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::ptr;
use std::rc::Rc;
use std::time::{Duration, Instant};

const CGROUP2_MAGIC: u64 = 0x6367_7270;
const WAIT_LIMIT: Duration = Duration::from_secs(10);

/// The external controller must authenticate its guard, prove this cgroup is
/// freshly dedicated to this operation, and retain exclusive migration rights.
/// `validate` must fail if the guard is unready, dead, or bound to a different
/// group. It must never create threads, install signal handlers or reap children.
/// It is intentionally a caller contract, not a cryptographic proof.
pub trait ExternalGuard {
    fn validate(&mut self, dedicated_group: &File) -> io::Result<()>;
}

/// Pre-created sealed ELF snapshot and prevalidated argument/environment bytes.
/// This module checks seals and format; it does not authenticate source bytes,
/// the dynamic linker/libraries, arguments, or the operation being executed.
pub struct PinnedCommand {
    pub executable: File,
    pub argv: Vec<CString>,
    pub environment: Vec<CString>,
}

/// BeforeSpawn means no child exists. AfterSpawn retains the child pidfd and
/// control state; the controller MUST call `stop` and then `wait_stopped`.
#[must_use]
pub enum StartFailure {
    BeforeSpawn(io::Error),
    AfterSpawn { cause: io::Error, worker: Worker },
}

/// Owns the exact worker pidfd and the dedicated cgroup handles. Dropping a
/// prepared worker closes GO but is NOT a substitute for explicit stop/wait.
/// Once GO has been sent, dropping this value does not kill running processes.
#[must_use]
pub struct Worker {
    pid: libc::pid_t,
    pidfd: File,
    go: Option<File>,
    group: File,
    kill: File,
    events: File,
    procs: File,
    started: bool,
    reaped: bool,
    old_signal_mask: Option<libc::sigset_t>,
    // The saved pthread signal mask must be restored on this same thread.
    not_send_or_sync: PhantomData<Rc<()>>,
}

#[derive(Debug)]
pub struct StopError {
    pub worker_signal: Option<io::Error>,
    pub cgroup_kill: Option<io::Error>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn owned(fd: i32) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn dup_min(fd: RawFd) -> io::Result<File> {
    owned(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })
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
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}
fn openat(group: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    owned(unsafe {
        libc::openat(
            group.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })
}
fn pipe() -> io::Result<(File, File)> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}
fn pidfd_open_self() -> io::Result<File> {
    owned(unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 })
}
fn ready(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let n = unsafe { libc::poll(&mut p, 1, timeout_ms) };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if p.revents & libc::POLLNVAL != 0 {
            return Err(invalid("invalid poll descriptor"));
        }
        return Ok(n != 0 && p.revents != 0);
    }
}
fn group_populated(events: &mut File) -> io::Result<bool> {
    if unsafe { libc::lseek(events.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut data = Vec::new();
    events.take(513).read_to_end(&mut data)?;
    if data.len() > 512 {
        return Err(invalid("oversized cgroup.events"));
    }
    let mut state = None;
    for line in data.split(|&c| c == b'\n') {
        let next = match line {
            b"populated 0" => Some(false),
            b"populated 1" => Some(true),
            _ => None,
        };
        if let Some(next) = next {
            if state.replace(next).is_some() {
                return Err(invalid("duplicate populated"));
            }
        }
    }
    state.ok_or_else(|| invalid("missing populated"))
}
fn require_sole_reaper() -> io::Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let threads = status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:")?.trim().parse::<u32>().ok());
    if threads != Some(1) {
        return Err(invalid("launcher is not single threaded"));
    }
    let mut action: libc::sigaction = unsafe { zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, ptr::null(), &mut action) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(invalid("SIGCHLD must be default without SA_NOCLDWAIT"));
    }
    Ok(())
}
fn require_sealed_elf(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() < 4 {
        return Err(invalid("executable must be a regular ELF"));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 || seals & required != required {
        return Err(invalid("executable snapshot must be sealed"));
    }
    let mut magic = [0u8; 4];
    let n = unsafe { libc::pread(file.as_raw_fd(), magic.as_mut_ptr().cast(), magic.len(), 0) };
    if n != 4 || magic != *b"\x7fELF" {
        return Err(invalid("executable must be ELF"));
    }
    Ok(())
}
fn require_cgroup(group: &File) -> io::Result<()> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut fs: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstat(group.as_raw_fd(), &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || unsafe { libc::fstatfs(group.as_raw_fd(), &mut fs) } != 0
        || fs.f_type as u64 != CGROUP2_MAGIC
    {
        return Err(invalid("not a cgroup v2 directory"));
    }
    Ok(())
}

struct ChildSpec<'a> {
    keep: [RawFd; 4],
    exe: RawFd,
    go: RawFd,
    ready: RawFd,
    parent_fd: RawFd,
    parent_pid: libc::pid_t,
    argv: &'a [*const libc::c_char],
    env: &'a [*const libc::c_char],
}

/// After clone, only raw Linux calls with stack data; no allocation, locking,
/// logging, unwinding, destructors, or access to mutable Rust runtime state.
unsafe fn child(spec: &ChildSpec<'_>) -> ! {
    let mut first = 3u32;
    for raw in spec.keep {
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
    if libc::syscall(libc::SYS_prctl, libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
        || libc::getppid() != spec.parent_pid
    {
        libc::_exit(121);
    }
    let mut p = libc::pollfd {
        fd: spec.parent_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    if libc::poll(&mut p, 1, 0) != 0 {
        libc::_exit(122);
    }
    let byte = b'R';
    if libc::write(spec.ready, (&byte as *const u8).cast(), 1) != 1 {
        libc::_exit(123);
    }
    let mut byte = 0u8;
    loop {
        let n = libc::read(spec.go, (&mut byte as *mut u8).cast(), 1);
        if n < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        if n != 1 || byte != b'G' {
            libc::_exit(124);
        }
        break;
    }
    p.revents = 0;
    if libc::poll(&mut p, 1, 0) != 0 || libc::getppid() != spec.parent_pid {
        libc::_exit(125);
    }
    // Signal mask is deliberately still blocked at exec. A real launcher must
    // establish its intended mask/dispositions with no inherited-handler race.
    libc::syscall(
        libc::SYS_execveat,
        spec.exe,
        c"".as_ptr(),
        spec.argv.as_ptr(),
        spec.env.as_ptr(),
        libc::AT_EMPTY_PATH,
    );
    libc::_exit(126);
}

/// Prepare a stopped-before-GO child and place it in the guarded cgroup.
/// Every error after clone returns the Worker, including its exact pidfd.
/// No success is reported on guard, close_range, placement or pidfd failures.
// The error owns Worker without a new post-spawn allocation, retaining pidfd.
#[allow(clippy::result_large_err)]
pub fn prepare<G: ExternalGuard>(
    guard: &mut G,
    group: File,
    command: PinnedCommand,
) -> Result<Worker, StartFailure> {
    macro_rules! pre {
        ($e:expr) => {
            $e.map_err(StartFailure::BeforeSpawn)?
        };
    }
    pre!(guard.validate(&group));
    pre!(require_sole_reaper());
    pre!(require_sealed_elf(&command.executable));
    if command.argv.is_empty() {
        return Err(StartFailure::BeforeSpawn(invalid("empty argv")));
    }
    pre!(require_cgroup(&group));
    let mut events = pre!(openat(&group, c"cgroup.events", libc::O_RDONLY));
    let kill = pre!(openat(&group, c"cgroup.kill", libc::O_WRONLY));
    let procs = pre!(openat(&group, c"cgroup.procs", libc::O_RDWR));
    if pre!(group_populated(&mut events)) {
        return Err(StartFailure::BeforeSpawn(invalid("cgroup not empty")));
    }
    let (go_read, go_write) = pre!(socket_pair());
    let (mut ready_read, ready_write) = pre!(pipe());
    let parent_fd = pre!(pidfd_open_self());
    // Force kept child descriptors >= 3 even if the caller closed standard FDs.
    let child_exe = pre!(dup_min(command.executable.as_raw_fd()));
    let child_go = pre!(dup_min(go_read.as_raw_fd()));
    let child_ready = pre!(dup_min(ready_write.as_raw_fd()));
    let child_parent = pre!(dup_min(parent_fd.as_raw_fd()));
    let mut keep = [
        child_exe.as_raw_fd(),
        child_go.as_raw_fd(),
        child_ready.as_raw_fd(),
        child_parent.as_raw_fd(),
    ];
    keep.sort_unstable();
    if keep.windows(2).any(|v| v[0] == v[1]) {
        return Err(StartFailure::BeforeSpawn(invalid("duplicate keep fd")));
    }
    let mut argv: Vec<_> = command.argv.iter().map(|x| x.as_ptr()).collect();
    argv.push(ptr::null());
    let mut env: Vec<_> = command.environment.iter().map(|x| x.as_ptr()).collect();
    env.push(ptr::null());
    let spec = ChildSpec {
        keep,
        exe: child_exe.as_raw_fd(),
        go: child_go.as_raw_fd(),
        ready: child_ready.as_raw_fd(),
        parent_fd: child_parent.as_raw_fd(),
        parent_pid: unsafe { libc::getpid() },
        argv: &argv,
        env: &env,
    };
    let mut blocked: libc::sigset_t = unsafe { zeroed() };
    let mut old: libc::sigset_t = unsafe { zeroed() };
    if unsafe { libc::sigfillset(&mut blocked) } != 0 {
        return Err(StartFailure::BeforeSpawn(io::Error::last_os_error()));
    }
    let mask = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut old) };
    if mask != 0 {
        return Err(StartFailure::BeforeSpawn(io::Error::from_raw_os_error(
            mask,
        )));
    }
    // Recheck after blocking signals; no signal handler can change SIGCHLD
    // between the sole-reaper validation and clone in this single thread.
    if let Err(error) = require_sole_reaper() {
        let restore = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, ptr::null_mut()) };
        return Err(StartFailure::BeforeSpawn(if restore == 0 {
            error
        } else {
            io::Error::other(format!(
                "sole-reaper check failed: {error}; restoring signal mask failed: {restore}"
            ))
        }));
    }
    let mut raw_pidfd: i32 = -1;
    let mut args: libc::clone_args = unsafe { zeroed() };
    args.flags = libc::CLONE_PIDFD as u64;
    args.pidfd = (&mut raw_pidfd as *mut i32) as u64;
    args.exit_signal = libc::SIGCHLD as u64;
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const libc::clone_args,
            size_of::<libc::clone_args>(),
        )
    };
    if result == 0 {
        unsafe { child(&spec) }
    }
    let clone_error = if result < 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    if let Some(error) = clone_error {
        let restore = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, ptr::null_mut()) };
        return Err(StartFailure::BeforeSpawn(if restore == 0 {
            error
        } else {
            io::Error::other(format!(
                "clone3 failed: {error}; restoring signal mask failed: {restore}"
            ))
        }));
    }
    // Linux clone3(CLONE_PIDFD) guarantees a valid pidfd on successful return.
    // Keep all signals blocked until the child is reaped: no inherited handler
    // can install a SIGCHLD handler or wait on this child in this single thread.
    let worker_pidfd = unsafe { File::from_raw_fd(raw_pidfd) };
    let mut worker = Worker {
        pid: result as libc::pid_t,
        pidfd: worker_pidfd,
        go: Some(go_write),
        group,
        kill,
        events,
        procs,
        started: false,
        reaped: false,
        old_signal_mask: Some(old),
        not_send_or_sync: PhantomData,
    };
    macro_rules! post {
        ($e:expr) => {
            match $e {
                Ok(value) => value,
                Err(cause) => {
                    worker.go.take();
                    return Err(StartFailure::AfterSpawn { cause, worker });
                }
            }
        };
    }
    drop(go_read);
    drop(ready_write);
    drop(child_exe);
    drop(child_go);
    drop(child_ready);
    drop(child_parent);
    if !post!(ready(ready_read.as_raw_fd(), WAIT_LIMIT.as_millis() as i32)) {
        worker.go.take();
        return Err(StartFailure::AfterSpawn {
            cause: invalid("child READY timeout"),
            worker,
        });
    }
    let mut byte = [0];
    post!(ready_read.read_exact(&mut byte));
    if byte != [b'R'] || post!(ready(worker.pidfd.as_raw_fd(), 0)) {
        worker.go.take();
        return Err(StartFailure::AfterSpawn {
            cause: invalid("child exited before placement"),
            worker,
        });
    }
    post!(guard.validate(&worker.group));
    post!(require_sole_reaper());
    // The child remains unreaped: its numeric PID cannot yet be reused.
    let text = worker.pid.to_string();
    let n = unsafe { libc::write(worker.procs.as_raw_fd(), text.as_ptr().cast(), text.len()) };
    if n != text.len() as isize {
        let cause = if n < 0 {
            io::Error::last_os_error()
        } else {
            invalid("short cgroup.procs write")
        };
        worker.go.take();
        return Err(StartFailure::AfterSpawn { cause, worker });
    }
    if unsafe { libc::lseek(worker.procs.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        let cause = io::Error::last_os_error();
        worker.go.take();
        return Err(StartFailure::AfterSpawn { cause, worker });
    }
    let mut data = String::new();
    post!((&worker.procs).take(4097).read_to_string(&mut data));
    if data.len() > 4096
        || data.lines().collect::<Vec<_>>() != [text.as_str()]
        || post!(ready(worker.pidfd.as_raw_fd(), 0))
    {
        worker.go.take();
        return Err(StartFailure::AfterSpawn {
            cause: invalid("cgroup membership mismatch"),
            worker,
        });
    }
    post!(guard.validate(&worker.group));
    Ok(worker)
}

impl Worker {
    pub fn pidfd(&self) -> &File {
        &self.pidfd
    }
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Explicit GO only after external guard validation and membership check.
    /// On any failure the caller retains self/pidfd and must stop and wait.
    pub fn go<G: ExternalGuard>(&mut self, guard: &mut G) -> io::Result<()> {
        if self.started || self.reaped {
            return Err(invalid("worker not prepared"));
        }
        let result = (|| -> io::Result<()> {
            guard.validate(&self.group)?;
            require_sole_reaper()?;
            if unsafe { libc::lseek(self.procs.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut members = String::new();
            (&self.procs).take(4097).read_to_string(&mut members)?;
            let expected = self.pid.to_string();
            if members.len() > 4096 || members.lines().collect::<Vec<_>>() != [expected.as_str()] {
                return Err(invalid("worker left dedicated cgroup"));
            }
            if ready(self.pidfd.as_raw_fd(), 0)? || !group_populated(&mut self.events)? {
                return Err(invalid("worker or cgroup no longer live"));
            }
            let go = self.go.as_ref().ok_or_else(|| invalid("GO closed"))?;
            let n =
                unsafe { libc::send(go.as_raw_fd(), b"G".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
            if n != 1 {
                return Err(if n < 0 {
                    io::Error::last_os_error()
                } else {
                    invalid("short GO send")
                });
            }
            self.started = true;
            Ok(())
        })();
        // A failed guard or GO attempt irreversibly closes the launch gate.
        self.go.take();
        result
    }

    /// Attempt both signals even if one fails. Errors are returned separately;
    /// a signal success is not proof that the worker or cgroup has stopped.
    pub fn stop(&mut self) -> Result<(), StopError> {
        self.go.take();
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        let worker_signal = if result == 0 {
            None
        } else {
            Some(io::Error::last_os_error())
        };
        let one = b'1';
        let n = unsafe { libc::write(self.kill.as_raw_fd(), (&one as *const u8).cast(), 1) };
        let cgroup_kill = if n == 1 {
            None
        } else if n < 0 {
            Some(io::Error::last_os_error())
        } else {
            Some(invalid("short cgroup.kill write"))
        };
        if worker_signal.is_none() && cgroup_kill.is_none() {
            Ok(())
        } else {
            Err(StopError {
                worker_signal,
                cgroup_kill,
            })
        }
    }

    /// Restore the creating thread's signal mask after successful reaping.
    /// An error is returned and the saved mask is retained for explicit retry.
    pub fn restore_signal_mask(&mut self) -> io::Result<()> {
        if !self.reaped {
            return Err(invalid("cannot restore mask before reaping"));
        }
        if let Some(old) = self.old_signal_mask.as_ref() {
            let result = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, old, ptr::null_mut()) };
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
            self.old_signal_mask = None;
        }
        Ok(())
    }

    /// Confirm the direct child is dead and the cgroup is empty, then reap it.
    /// An error retains the pidfd; do not treat a timeout/ambiguous status as success.
    pub fn wait_stopped(&mut self) -> io::Result<libc::c_int> {
        if self.reaped {
            return Err(invalid("already reaped"));
        }
        let deadline = Instant::now() + WAIT_LIMIT;
        while !ready(self.pidfd.as_raw_fd(), 0)? || group_populated(&mut self.events)? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "worker or cgroup still alive",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut status = 0;
        loop {
            let n = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if n == self.pid {
                self.reaped = true;
                self.restore_signal_mask()?;
                return Ok(status);
            }
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RejectedGuard;
    impl ExternalGuard for RejectedGuard {
        fn validate(&mut self, _: &File) -> io::Result<()> {
            Err(invalid("guard intentionally unready"))
        }
    }

    #[test]
    fn unready_guard_rejects_before_child_creation() {
        let group = File::open("/dev/null").unwrap();
        let executable = File::open("/dev/null").unwrap();
        let command = PinnedCommand {
            executable,
            argv: vec![CString::new("fixture").unwrap()],
            environment: Vec::new(),
        };
        assert!(matches!(
            prepare(&mut RejectedGuard, group, command),
            Err(StartFailure::BeforeSpawn(_))
        ));
    }

    #[test]
    fn failed_go_permanently_closes_gate_and_retains_pidfd() {
        let (peer, write) = socket_pair().unwrap();
        let null = || File::open("/dev/null").unwrap();
        let mut worker = Worker {
            pid: 123,
            pidfd: null(),
            go: Some(write),
            group: null(),
            kill: null(),
            events: null(),
            procs: null(),
            started: false,
            reaped: false,
            old_signal_mask: None,
            not_send_or_sync: PhantomData,
        };
        let pidfd_number = worker.pidfd().as_raw_fd();
        assert!(worker.go(&mut RejectedGuard).is_err());
        assert!(worker.go.is_none());
        assert_eq!(worker.pidfd().as_raw_fd(), pidfd_number);
        let mut byte = 0u8;
        assert_eq!(
            unsafe {
                libc::recv(
                    peer.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    libc::MSG_DONTWAIT,
                )
            },
            0
        );
    }
}
