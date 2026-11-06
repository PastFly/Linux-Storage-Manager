//! Disposable Linux-only launch experiment. This is NOT a production guard.
//!
//! The launcher is single-threaded, owns SIGCHLD, and never reaps its child
//! until placement is complete. Its only payload is this binary's `--worker`.
//! No block device or arbitrary executable is opened. An external test manager
//! must kill/wait the whole test cgroup if the launcher dies after GO. There is
//! no backup lease, durable journal, observer/manager watchdog, or guarantee
//! against forced lease break, kernel I/O already submitted, concurrent root,
//! arbitrary process migration, or failure of multiple supervising processes.
//!
//! Build in a temporary Cargo project with libc = "=0.2.189"; see harness.
#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem::zeroed;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;
    use std::time::{Duration, Instant};

    const CGROUP2_MAGIC: u64 = 0x6367_7270;
    // Linux UAPI: libc 0.2.189's signed constant overflows for this flag.
    const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
    const MAX_BINARY: u64 = 64 * 1024 * 1024;
    const MFD_EXEC: libc::c_uint = 0x0010;

    fn error(msg: &'static str) -> io::Error {
        io::Error::other(msg)
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
    fn pipe() -> io::Result<(File, File)> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
    }
    fn openat(dir: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
        file(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        })
    }
    fn live(pidfd: RawFd) -> io::Result<bool> {
        let mut p = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let mut interruptions = 0;
        loop {
            let n = unsafe { libc::poll(&mut p, 1, 0) };
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                interruptions += 1;
                if interruptions > 64 {
                    return Err(error("pidfd poll repeatedly interrupted"));
                }
                continue;
            }
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(n == 0 && p.revents == 0);
        }
    }
    fn wait_dead(pidfd: RawFd) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut p = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child pidfd wait timed out",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
            let n = unsafe { libc::poll(&mut p, 1, timeout) };
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                continue;
            }
            if p.revents & libc::POLLIN != 0 {
                return Ok(());
            }
            return Err(error("child pidfd polling failed"));
        }
    }
    // Never reap here: stop_and_reap is the sole owner of the child's status.
    fn bounded_stopped(pid: libc::pid_t, pidfd: RawFd, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut info: libc::siginfo_t = unsafe { zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WSTOPPED | libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            } else if unsafe { info.si_pid() } != 0 {
                if info.si_code == libc::CLD_STOPPED && live(pidfd)? {
                    return Ok(());
                }
                return Err(error("child exited before stop"));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child stop timed out",
                ));
            }
            // pidfds do not become readable on stop; periodically recheck waitid.
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining.as_millis().clamp(1, 10) as i32;
            let mut p = libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut p, 1, millis) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            } else if n > 0 {
                return Err(error("child exited or pidfd polling failed before stop"));
            }
        }
    }
    fn bounded_ready(reader: &mut File, pidfd: RawFd, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child READY timed out",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut fds = [
                libc::pollfd {
                    fd: reader.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: pidfd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
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
            if fds[1].revents != 0 {
                return Err(error("child exited or pidfd polling failed before READY"));
            }
            if fds[0].revents != libc::POLLIN {
                return Err(error("READY pipe closed or polling failed"));
            }
            let mut byte = [0];
            let count = unsafe { libc::read(reader.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
            if count < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if count == 1 && byte == [b'R'] && live(pidfd)? {
                return Ok(());
            }
            return Err(error("child not ready/live"));
        }
    }
    fn combine_results(run: io::Result<()>, cleanup: io::Result<()>) -> io::Result<()> {
        match (run, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
            (Err(run), Err(cleanup)) => Err(io::Error::other(format!(
                "run failed: {run}; cleanup failed: {cleanup}"
            ))),
        }
    }
    fn populated(events: &mut File) -> io::Result<bool> {
        if unsafe { libc::lseek(events.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut data = String::new();
        events.take(513).read_to_string(&mut data)?;
        if data.len() > 512 {
            return Err(error("oversized events"));
        }
        let mut state = None;
        for line in data.lines() {
            let value = match line {
                "populated 0" => Some(false),
                "populated 1" => Some(true),
                _ => None,
            };
            if let Some(value) = value {
                if state.replace(value).is_some() {
                    return Err(error("duplicate populated"));
                }
            }
        }
        state.ok_or_else(|| error("missing populated"))
    }
    fn kill_group(kill: &File) -> io::Result<()> {
        let one = b'1';
        let mut interruptions = 0;
        loop {
            let n = unsafe { libc::write(kill.as_raw_fd(), (&one as *const u8).cast(), 1) };
            if n == 1 {
                return Ok(());
            }
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                interruptions += 1;
                if interruptions > 64 {
                    return Err(io::Error::other("cgroup.kill repeatedly interrupted"));
                }
                continue;
            }
            return Err(if n < 0 {
                io::Error::last_os_error()
            } else {
                error("short cgroup.kill write")
            });
        }
    }
    fn signal_pidfd(fd: RawFd) -> io::Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                libc::SIGKILL,
                ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    fn stop_and_reap(
        child: libc::pid_t,
        child_pidfd: RawFd,
        kill: &File,
        events: &mut File,
    ) -> io::Result<()> {
        // Both operations are attempted and their individual errors retained.
        let signal_result = signal_pidfd(child_pidfd);
        let group_result = kill_group(kill);
        let mut errors = Vec::new();
        if let Err(ref error) = signal_result {
            errors.push(format!("pidfd signal: {error}"));
        }
        if let Err(ref error) = group_result {
            errors.push(format!("cgroup kill: {error}"));
        }
        if signal_result.is_err() && group_result.is_err() {
            return Err(io::Error::other(errors.join("; ")));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let wait_result = loop {
            if Instant::now() >= deadline {
                break Err(error("child or cgroup did not stop before deadline"));
            }
            let mut item = libc::pollfd {
                fd: child_pidfd,
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut item, 1, 0) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break Err(error);
            }
            if item.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                break Err(error("worker pidfd poll failed"));
            }
            let empty = match populated(events) {
                Ok(value) => !value,
                Err(error) => break Err(error),
            };
            if item.revents & libc::POLLIN != 0 && empty {
                let mut status = 0;
                let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
                if waited == child {
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        break Ok(());
                    }
                    break Err(error("unexpected worker wait status"));
                }
                if waited < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break Err(error);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if let Err(error) = wait_result {
            errors.push(format!("stop confirmation: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }
    fn sealed_self() -> io::Result<File> {
        let original = File::open("/proc/self/exe")?;
        let size = original.metadata()?.len();
        if size == 0 || size > MAX_BINARY {
            return Err(error("invalid test executable size"));
        }
        let mut fd = unsafe {
            libc::memfd_create(
                c"lsm-test-worker".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | MFD_EXEC,
            )
        };
        if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            fd = unsafe {
                libc::memfd_create(
                    c"lsm-test-worker".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                )
            };
        }
        let mut snapshot = file(fd)?;
        let copied = io::copy(&mut original.take(MAX_BINARY + 1), &mut snapshot)?;
        if copied != size {
            return Err(error("test executable changed"));
        }
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(snapshot)
    }
    fn allowed_group_path(path: &Path) -> bool {
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
        let suffix = name.strip_prefix("lsm-gated-proof-").unwrap_or_default();
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn open_group(path: &Path) -> io::Result<(File, File, File)> {
        if !path.is_absolute() || !allowed_group_path(path) {
            return Err(error("not an isolated test group"));
        }
        let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| error("invalid path"))?;
        let group = file(unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        let mut fs: libc::statfs = unsafe { zeroed() };
        if unsafe { libc::fstatfs(group.as_raw_fd(), &mut fs) } < 0
            || fs.f_type as u64 != CGROUP2_MAGIC
        {
            return Err(error("not cgroup v2"));
        }
        let events = openat(&group, c"cgroup.events", libc::O_RDONLY)?;
        let kill = openat(&group, c"cgroup.kill", libc::O_WRONLY)?;
        Ok((group, events, kill))
    }
    fn thread_count() -> io::Result<u32> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("Threads:")?.trim().parse().ok())
            .ok_or_else(|| error("missing thread count"))
    }
    fn status_line(label: &str, pid: libc::pid_t) -> io::Result<()> {
        let mut out = io::stdout().lock();
        writeln!(out, "{label} {pid}")?;
        out.flush()
    }

    // Only kernel/libc operations and stack data in the post-fork child.
    // _exit never runs Rust destructors; no inherited handlers run before exec.
    struct ChildSpec<'a> {
        keep: [RawFd; 4],
        exe: RawFd,
        go: RawFd,
        ready: RawFd,
        parent_fd: RawFd,
        expected_parent: libc::pid_t,
        stop_early: bool,
        argv: &'a [*const libc::c_char],
        env: &'a [*const libc::c_char],
    }
    unsafe fn child_entry(spec: &ChildSpec<'_>) -> ! {
        let ChildSpec {
            keep,
            exe,
            go,
            ready,
            parent_fd,
            expected_parent,
            stop_early,
            argv,
            env,
        } = *spec;
        let mut first = 3u32;
        for raw in keep {
            let end = raw as u32;
            if first < end && libc::syscall(libc::SYS_close_range, first, end - 1, 0u32) != 0 {
                libc::_exit(120);
            }
            first = end + 1;
        }
        if libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32) != 0 {
            libc::_exit(120);
        }
        // stdin is the external test control channel; do not pass it to worker.
        libc::close(libc::STDIN_FILENO);
        if stop_early {
            // The test manager obtains child pidfd before authorizing SIGSTOP.
            // If the launcher dies earlier, EOF exits without leaving a stopped orphan.
            let mut command = 0u8;
            let n = libc::read(go, (&mut command as *mut u8).cast(), 1);
            if n != 1 || command != b'S' {
                libc::_exit(121);
            }
            if libc::kill(libc::getpid(), libc::SIGSTOP) != 0 {
                libc::_exit(121);
            }
        }
        if libc::syscall(libc::SYS_prctl, libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
            || libc::getppid() != expected_parent
        {
            libc::_exit(122);
        }
        let mut p = libc::pollfd {
            fd: parent_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if libc::poll(&mut p, 1, 0) != 0 {
            libc::_exit(123);
        }
        let b = b'R';
        if libc::write(ready, (&b as *const u8).cast(), 1) != 1 {
            libc::_exit(124);
        }
        let mut go_byte = 0u8;
        loop {
            let n = libc::read(go, (&mut go_byte as *mut u8).cast(), 1);
            if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            if n != 1 || go_byte != b'G' {
                libc::_exit(125);
            }
            break;
        }
        p.revents = 0;
        if libc::poll(&mut p, 1, 0) != 0 || libc::getppid() != expected_parent {
            libc::_exit(126);
        }
        libc::syscall(
            libc::SYS_execveat,
            exe,
            c"".as_ptr(),
            argv.as_ptr(),
            env.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
        libc::_exit(127);
    }

    fn launcher(path: &Path, case: &str) -> io::Result<()> {
        if unsafe { libc::geteuid() } != 0 || thread_count()? != 1 {
            return Err(error("root and a single thread required"));
        }
        if !matches!(case, "before-pdeath" | "before-go" | "after-go") {
            return Err(error("invalid case"));
        }
        let (group, mut events, kill) = open_group(path)?;
        if populated(&mut events)? {
            return Err(error("cgroup not empty"));
        }
        // Default disposition and no SA_NOCLDWAIT. This process is the only reaper.
        let mut action: libc::sigaction = unsafe { zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
            || unsafe { libc::sigaction(libc::SIGCHLD, &action, ptr::null_mut()) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let exe = sealed_self()?;
        let parent_pid = unsafe { libc::getpid() };
        let parent_fd = pidfd(parent_pid)?;
        let (go_read, mut go_write) = pipe()?;
        let (mut ready_read, ready_write) = pipe()?;
        let args = [
            CString::new("lsm-gated-test").unwrap(),
            CString::new("--worker").unwrap(),
        ];
        let argv = [args[0].as_ptr(), args[1].as_ptr(), ptr::null()];
        let env = [ptr::null()];
        let mut keep = [
            exe.as_raw_fd(),
            go_read.as_raw_fd(),
            ready_write.as_raw_fd(),
            parent_fd.as_raw_fd(),
        ];
        keep.sort_unstable();
        if keep.windows(2).any(|w| w[0] == w[1]) {
            return Err(error("duplicate keep fd"));
        }
        let mut blocked: libc::sigset_t = unsafe { zeroed() };
        let mut old_mask: libc::sigset_t = unsafe { zeroed() };
        if unsafe { libc::sigfillset(&mut blocked) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mask_err = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut old_mask) };
        if mask_err != 0 {
            return Err(io::Error::from_raw_os_error(mask_err));
        }
        let spec = ChildSpec {
            keep,
            exe: exe.as_raw_fd(),
            go: go_read.as_raw_fd(),
            ready: ready_write.as_raw_fd(),
            parent_fd: parent_fd.as_raw_fd(),
            expected_parent: parent_pid,
            stop_early: case == "before-pdeath",
            argv: &argv,
            env: &env,
        };
        let mut raw_child_pidfd: libc::c_int = -1;
        let mut clone_args: libc::clone_args = unsafe { zeroed() };
        clone_args.flags = libc::CLONE_PIDFD as u64 | CLONE_INTO_CGROUP;
        clone_args.pidfd = (&mut raw_child_pidfd as *mut libc::c_int) as u64;
        clone_args.exit_signal = libc::SIGCHLD as u64;
        clone_args.cgroup = group.as_raw_fd() as u64;
        // No fallback: the child must be born in the exact cgroup.
        let result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &clone_args as *const libc::clone_args,
                std::mem::size_of::<libc::clone_args>(),
            )
        };
        if result == 0 {
            unsafe { child_entry(&spec) }
        }
        let clone_error = if result < 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        let restore_err =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_mask, ptr::null_mut()) };
        drop(go_read);
        drop(ready_write);
        if let Some(e) = clone_error {
            return Err(if restore_err == 0 {
                e
            } else {
                io::Error::other(format!(
                    "clone3 failed: {e}; signal mask restore failed: {restore_err}"
                ))
            });
        }
        let child = result as libc::pid_t;
        if raw_child_pidfd < 0 {
            // Kernel contract violation: do not report a normal pre-spawn
            // failure while a child may exist. An external test controller
            // remains responsible for waiting on the disposable group.
            let one = b'1';
            let _ = unsafe { libc::write(kill.as_raw_fd(), (&one as *const u8).cast(), 1) };
            unsafe { libc::_exit(125) }
        }
        let child_pidfd = unsafe { File::from_raw_fd(raw_child_pidfd) };
        if restore_err != 0 {
            drop(go_write);
            let cleanup = stop_and_reap(child, child_pidfd.as_raw_fd(), &kill, &mut events);
            return Err(io::Error::other(format!(
                "signal mask restore failed: {restore_err}; cleanup: {cleanup:?}"
            )));
        }
        let run = (|| -> io::Result<()> {
            // The external manager must acquire a pidfd before early-stop testing.
            status_line("FORKED", child)?;
            if case == "before-pdeath" {
                let mut command = [0];
                io::stdin().read_exact(&mut command)?;
                if command != [b'S'] {
                    return Err(error("early stop refused"));
                }
                go_write.write_all(b"S")?;
                bounded_stopped(child, child_pidfd.as_raw_fd(), Duration::from_secs(10))?;
                status_line("STOPPED", child)?;
                // Test manager will kill the launcher and then SIGCONT the exact pidfd.
                let mut byte = [0];
                io::stdin().read_exact(&mut byte)?;
                return Err(error("unexpected early control"));
            }
            bounded_ready(
                &mut ready_read,
                child_pidfd.as_raw_fd(),
                Duration::from_secs(10),
            )?;
            let procs = openat(&group, c"cgroup.procs", libc::O_RDWR)?;
            let pid_bytes = child.to_string();
            if unsafe { libc::lseek(procs.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut contents = String::new();
            (&procs).take(4097).read_to_string(&mut contents)?;
            if contents.len() > 4096
                || contents.lines().collect::<Vec<_>>() != [pid_bytes.as_str()]
                || !live(child_pidfd.as_raw_fd())?
            {
                return Err(error("cgroup membership mismatch"));
            }
            status_line("READY", child)?;
            let mut command = [0];
            io::stdin().read_exact(&mut command)?;
            if command != [b'G'] || !live(child_pidfd.as_raw_fd())? || !populated(&mut events)? {
                return Err(error("GO refused"));
            }
            go_write.write_all(b"G")?;
            drop(go_write);
            // Observe death without reaping; cleanup remains the sole reaper.
            wait_dead(child_pidfd.as_raw_fd())?;
            Err(error("test worker exited without external manager"))
        })();
        // The exact pidfd and group remain cleanup authorities even before GO.
        let cleanup = stop_and_reap(child, child_pidfd.as_raw_fd(), &kill, &mut events);
        combine_results(run, cleanup)
    }

    fn worker() -> io::Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(error("root test worker required"));
        }
        let cgroup = std::fs::read_to_string("/proc/self/cgroup")?;
        let group_path = cgroup
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| error("missing cgroup v2 membership"))?;
        if !allowed_group_path(Path::new(group_path)) {
            return Err(error("worker outside test group"));
        }
        let (mut read_end, write_end) = pipe()?;
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(io::Error::last_os_error());
        }
        if child == 0 {
            unsafe {
                libc::close(read_end.as_raw_fd());
                if libc::setsid() < 0 {
                    libc::_exit(128);
                }
                let b = b'S';
                if libc::write(write_end.as_raw_fd(), (&b as *const u8).cast(), 1) != 1 {
                    libc::_exit(129);
                }
                loop {
                    libc::pause();
                }
            }
        }
        drop(write_end);
        let mut ready = [0];
        read_end.read_exact(&mut ready)?;
        if ready != [b'S'] {
            return Err(error("grandchild not ready"));
        }
        status_line("RUNNING", child)?;
        loop {
            unsafe {
                libc::pause();
            }
        }
    }

    pub fn main() -> io::Result<()> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() == 2 && args[1] == "--worker" {
            return worker();
        }
        if args.len() != 3 {
            return Err(error("usage: gated-launch-proof GROUP CASE"));
        }
        let case = args[2].to_str().ok_or_else(|| error("invalid case"))?;
        launcher(Path::new(&args[1]), case)
    }
    #[cfg(test)]
    mod stop_tests {
        use super::*;
        use std::io::Write;

        #[test]
        fn ready_wait_times_out_with_open_silent_pipe() {
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("2")
                .spawn()
                .unwrap();
            let child_fd = pidfd(child.id() as libc::pid_t).unwrap();
            let (mut reader, writer) = pipe().unwrap();
            let closer = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(600));
                drop(writer);
            });
            let started = Instant::now();
            let result = bounded_ready(
                &mut reader,
                child_fd.as_raw_fd(),
                Duration::from_millis(100),
            );
            let elapsed = started.elapsed();
            child.kill().unwrap();
            child.wait().unwrap();
            closer.join().unwrap();
            assert!(result.is_err());
            assert!(
                elapsed < Duration::from_millis(400),
                "READY blocked for {elapsed:?}"
            );
        }

        #[test]
        fn stopped_wait_times_out_and_does_not_reap_a_live_child() {
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("1")
                .spawn()
                .unwrap();
            let child_fd = pidfd(child.id() as libc::pid_t).unwrap();
            let started = Instant::now();
            let result = bounded_stopped(
                child.id() as libc::pid_t,
                child_fd.as_raw_fd(),
                Duration::from_millis(100),
            );
            let elapsed = started.elapsed();
            match child.try_wait() {
                Ok(None) => {
                    child.kill().unwrap();
                    child.wait().unwrap();
                }
                Ok(Some(_)) => {}
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
                Err(error) => panic!("unexpected child state: {error}"),
            }
            assert!(result.is_err());
            assert!(
                elapsed < Duration::from_millis(400),
                "WUNTRACED blocked for {elapsed:?}"
            );
        }

        #[test]
        fn stopped_wait_observes_stop_without_reaping() {
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("10")
                .spawn()
                .unwrap();
            let pid = child.id() as libc::pid_t;
            let child_fd = pidfd(pid).unwrap();
            assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
            let result = bounded_stopped(pid, child_fd.as_raw_fd(), Duration::from_secs(2));
            child.kill().unwrap();
            let status = child.wait();
            assert!(result.is_ok(), "stop was not observed: {result:?}");
            assert!(status.is_ok(), "child was unexpectedly reaped");
        }

        #[test]
        fn stopped_wait_does_not_reap_early_exited_child() {
            let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
            let child_fd = pidfd(child.id() as libc::pid_t).unwrap();
            assert!(bounded_stopped(
                child.id() as libc::pid_t,
                child_fd.as_raw_fd(),
                Duration::from_secs(2)
            )
            .is_err());
            assert!(
                child.wait().is_ok(),
                "early exit must remain available to the sole reaper"
            );
        }

        #[test]
        fn run_and_cleanup_failures_are_both_reported() {
            let result = combine_results(Err(error("run-failure")), Err(error("cleanup-failure")));
            let message = result.unwrap_err().to_string();
            assert!(
                message.contains("run-failure") && message.contains("cleanup-failure"),
                "{message}"
            );
        }

        #[test]
        fn both_stop_failures_are_reported_without_blocking_on_live_child() {
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("2")
                .spawn()
                .unwrap();
            let path =
                std::env::temp_dir().join(format!("lsm-stop-test-events-{}", std::process::id()));
            let mut events = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            events.write_all(b"populated 0\n").unwrap();
            let kill = File::open("/dev/null").unwrap();
            let started = Instant::now();
            let result = stop_and_reap(child.id() as libc::pid_t, -1, &kill, &mut events);
            let elapsed = started.elapsed();
            match child.try_wait() {
                Ok(None) => {
                    child.kill().unwrap();
                    child.wait().unwrap();
                }
                Ok(Some(_)) => {}
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
                Err(error) => panic!("unexpected child state: {error}"),
            }
            std::fs::remove_file(path).unwrap();
            let error = result.expect_err("both stop operations failed");
            let message = error.to_string();
            assert!(
                elapsed < Duration::from_millis(500),
                "stop blocked for {elapsed:?}"
            );
            assert!(
                message.contains("pidfd") && message.contains("cgroup"),
                "both errors must be reported: {message}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::main() {
        eprintln!("gated-launch proof: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux only");
    std::process::exit(2);
}
