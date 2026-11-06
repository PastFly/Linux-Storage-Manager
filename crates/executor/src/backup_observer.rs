//! Experimental internal observer. Not an authorization or execution gate.
#[cfg(target_os = "linux")]
mod linux {
    use libc::{c_int, c_void};
    use std::ffi::{CString, OsStr};
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;
    use std::time::{Duration, Instant};

    const MAX_LEASES: usize = 32;
    const MAX_FDS: usize = MAX_LEASES + 2;
    const CONTROL_FD: c_int = 3;
    const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    // Linux UAPI values on x86_64 and aarch64, the prototype's supported targets.
    const F_SETSIG: c_int = 10;
    const F_SETOWN_EX: c_int = 15;
    const F_GETOWN_EX: c_int = 16;
    const F_OWNER_PID: c_int = 1;

    #[repr(C)]
    struct FOwnerEx {
        kind: c_int,
        pid: libc::pid_t,
    }

    fn signal_ready(fd: c_int) -> Option<bool> {
        let mut item = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut item, 1, 0) };
            if result < 0 && interrupted() {
                continue;
            }
            if result < 0 {
                return None;
            }
            return Some(item.revents != 0);
        }
    }

    fn trusted_read_file(fd: c_int, stat: &mut libc::stat) -> bool {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        flags >= 0
            && flags & (libc::O_ACCMODE | libc::O_PATH) == libc::O_RDONLY
            && unsafe { libc::fstat(fd, stat) } == 0
            && stat.st_mode & libc::S_IFMT == libc::S_IFREG
            && stat.st_uid == 0
            && stat.st_mode & 0o7777 == 0o600
            && stat.st_nlink == 1
    }

    fn take_read_lease(fd: c_int) -> bool {
        let mut stat: libc::stat = unsafe { zeroed() };
        if !trusted_read_file(fd, &mut stat)
            || unsafe { libc::fcntl(fd, libc::F_GETLEASE) } != libc::F_UNLCK
        {
            return false;
        }
        let owner = FOwnerEx {
            kind: F_OWNER_PID,
            pid: unsafe { libc::getpid() },
        };
        // Lease setup may itself reset the signal owner: set before and after.
        if unsafe { libc::fcntl(fd, F_SETSIG, 0) } < 0
            || unsafe { libc::fcntl(fd, F_SETOWN_EX, &owner) } < 0
            || unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK) } < 0
            || unsafe { libc::fcntl(fd, F_SETOWN_EX, &owner) } < 0
        {
            return false;
        }
        let mut actual = FOwnerEx { kind: -1, pid: -1 };
        (unsafe { libc::fcntl(fd, F_GETOWN_EX, &mut actual) }) == 0
            && actual.kind == owner.kind
            && actual.pid == owner.pid
            && unsafe { libc::fcntl(fd, libc::F_GETLEASE) } == libc::F_RDLCK
            && trusted_read_file(fd, &mut stat)
    }

    fn exit(code: c_int) -> ! {
        // No destructors: in particular, never issue F_UNLCK for any shared lease.
        unsafe { libc::_exit(code) }
    }

    fn interrupted() -> bool {
        io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
    }

    fn populated(fd: c_int) -> Option<bool> {
        let mut buf = [0u8; 512];
        if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
            return None;
        }
        let len = loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 && interrupted() {
                continue;
            }
            break usize::try_from(n).ok().filter(|&n| n > 0)?;
        };
        for line in buf[..len].split(|&b| b == b'\n') {
            if line == b"populated 0" {
                return Some(false);
            }
            if line == b"populated 1" {
                return Some(true);
            }
        }
        None
    }

    fn kill_and_wait(kill_fd: c_int, events_fd: c_int) {
        loop {
            let byte = b'1';
            let n = unsafe { libc::write(kill_fd, (&byte as *const u8).cast(), 1) };
            if n == 1 {
                break;
            }
            if n < 0 && interrupted() {
                continue;
            }
            // Hold all lease FDs on error. Never treat unknown state as success.
            std::thread::sleep(Duration::from_millis(100));
        }
        while populated(events_fd) != Some(false) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // `msg` must be the untouched result of recvmsg into our bounded buffer.
    // Even a rejected/truncated packet may have installed SCM_RIGHTS FDs.
    fn close_received_rights(msg: &libc::msghdr) -> bool {
        let mut header = unsafe { libc::CMSG_FIRSTHDR(msg) };
        let mut found = false;
        while !header.is_null() {
            let len = unsafe { (*header).cmsg_len };
            let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
            let offset = (header as usize).saturating_sub(msg.msg_control as usize);
            if len < minimum || offset > msg.msg_controllen || len > msg.msg_controllen - offset {
                return true;
            }
            if unsafe { (*header).cmsg_level } == libc::SOL_SOCKET
                && unsafe { (*header).cmsg_type } == libc::SCM_RIGHTS
            {
                found = true;
                let count = (len - minimum) / size_of::<c_int>();
                let data = unsafe { libc::CMSG_DATA(header).cast::<c_int>() };
                for index in 0..count {
                    let fd = unsafe { ptr::read_unaligned(data.add(index)) };
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
            header = unsafe { libc::CMSG_NXTHDR(msg, header) };
        }
        found
    }

    fn send_ack(fd: c_int, byte: u8) -> bool {
        unsafe {
            libc::send(
                fd,
                (&byte as *const u8).cast(),
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            ) == 1
        }
    }

    fn pidfd_for_peer(fd: c_int, peer_pid: libc::pid_t) -> Option<bool> {
        let target = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
        if target.as_os_str() != OsStr::from_bytes(b"anon_inode:[pidfd]") {
            return None;
        }
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?;
        let pid = info
            .lines()
            .find_map(|line| line.strip_prefix("Pid:")?.trim().parse::<i64>().ok())?;
        if pid == -1 {
            Some(true)
        } else if pid == i64::from(peer_pid) {
            Some(false)
        } else {
            None
        }
    }

    pub fn main() -> ! {
        let mut args = std::env::args_os();
        let _ = args.next();
        if args.next().as_deref() != Some(OsStr::new("__lsm_backup_observer"))
            || unsafe { libc::geteuid() } != 0
        {
            exit(2);
        }
        let raw = args
            .next()
            .and_then(|s| s.into_string().ok())
            .and_then(|s| s.parse::<c_int>().ok());
        let Some(raw) = raw.filter(|&fd| fd >= 3) else {
            exit(2)
        };
        let diagnostic = match args.next() {
            None => false,
            Some(arg)
                if cfg!(feature = "diagnostic-backup-watchdog")
                    && arg == OsStr::new("--diagnostic-watchdog") =>
            {
                true
            }
            _ => exit(2),
        };
        if args.next().is_some() {
            exit(2);
        }
        unsafe {
            if raw != CONTROL_FD && libc::dup2(raw, CONTROL_FD) != CONTROL_FD {
                exit(2);
            }
            if libc::fcntl(CONTROL_FD, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                exit(2);
            }
            if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) < 0 {
                exit(2);
            }
            libc::close(0);
            libc::close(1);
            libc::close(2);
        }

        // Block before resetting an inherited SIG_IGN disposition. This process is
        // single-threaded; SIGIO is synchronously consumed through signalfd.
        let mut signals: libc::sigset_t = unsafe { zeroed() };
        if unsafe { libc::sigemptyset(&mut signals) } != 0
            || unsafe { libc::sigaddset(&mut signals, libc::SIGIO) } != 0
            || unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signals, ptr::null_mut()) } != 0
        {
            exit(3);
        }
        let mut action: libc::sigaction = unsafe { zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
            || unsafe { libc::sigaction(libc::SIGIO, &action, ptr::null_mut()) } != 0
        {
            exit(3);
        }
        let signal_fd =
            unsafe { libc::signalfd(-1, &signals, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if signal_fd < 0 {
            exit(3);
        }

        let mut peer: libc::ucred = unsafe { zeroed() };
        let mut peer_len = size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                CONTROL_FD,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut peer_len,
            )
        } < 0
            || peer.uid != 0
            || peer_len as usize != size_of::<libc::ucred>()
            || peer.pid <= 0
        {
            exit(3);
        }

        let mut count = 0u32;
        let mut iov = libc::iovec {
            iov_base: (&mut count as *mut u32).cast(),
            iov_len: size_of::<u32>(),
        };
        // Word alignment is required for cmsghdr. This buffer is larger than the maximum cmsg.
        let mut ancillary = [0usize; 64];
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ancillary.as_mut_ptr().cast::<c_void>();
        msg.msg_controllen = size_of::<[usize; 64]>();
        let received = loop {
            let n = unsafe { libc::recvmsg(CONTROL_FD, &mut msg, libc::MSG_CMSG_CLOEXEC) };
            if n < 0 && interrupted() {
                continue;
            }
            break n;
        };
        if received != size_of::<u32>() as isize
            || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || count == 0
            || count as usize > MAX_LEASES
        {
            exit(3);
        }
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() {
            exit(3);
        }
        let expected =
            unsafe { libc::CMSG_LEN(((count as usize + 2) * size_of::<c_int>()) as u32) } as usize;
        let cmsg_len = unsafe { (*cmsg).cmsg_len as usize };
        let aligned = (cmsg_len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
        if unsafe { (*cmsg).cmsg_level } != libc::SOL_SOCKET
            || unsafe { (*cmsg).cmsg_type } != libc::SCM_RIGHTS
            || cmsg_len != expected
            || (aligned <= msg.msg_controllen
                && msg.msg_controllen - aligned >= size_of::<libc::cmsghdr>())
        {
            exit(3);
        }
        let mut fds = [0 as c_int; MAX_FDS];
        unsafe {
            ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg).cast::<c_int>(),
                fds.as_mut_ptr(),
                count as usize + 2,
            );
        }
        let manager = fds[0];
        let group = fds[1];
        let Some(manager_dead) = pidfd_for_peer(manager, peer.pid) else {
            exit(4)
        };
        let mut stat: libc::stat = unsafe { zeroed() };
        let mut fs: libc::statfs = unsafe { zeroed() };
        if unsafe { libc::fstat(group, &mut stat) } < 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || unsafe { libc::fstatfs(group, &mut fs) } < 0
            || fs.f_type as u64 != CGROUP2_SUPER_MAGIC
        {
            exit(4);
        }
        let events = unsafe {
            libc::openat(
                group,
                c"cgroup.events".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        let kill_fd = unsafe {
            libc::openat(
                group,
                c"cgroup.kill".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if events < 0 || kill_fd < 0 || populated(events) != Some(false) {
            exit(4);
        }
        // SCM_RIGHTS duplicates an open-file description, so putting the lease
        // on it would let a sender-side duplicate keep the lease after our exit.
        // Reopen each received inode in this single-threaded process instead.
        let proc_fd = unsafe {
            libc::open(
                c"/proc/self/fd".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        let mut proc_stat: libc::statfs = unsafe { zeroed() };
        if proc_fd < 0
            || unsafe { libc::fstatfs(proc_fd, &mut proc_stat) } != 0
            || proc_stat.f_type as u64 != PROC_SUPER_MAGIC
        {
            exit(4);
        }
        let mut identities = Vec::with_capacity(count as usize);
        for fd in &mut fds[2..count as usize + 2] {
            let mut original: libc::stat = unsafe { zeroed() };
            if !trusted_read_file(*fd, &mut original)
                || unsafe { libc::fcntl(*fd, libc::F_GETLEASE) } != libc::F_UNLCK
                || identities.contains(&(original.st_dev, original.st_ino))
            {
                exit(4);
            }
            identities.push((original.st_dev, original.st_ino));
            let name = CString::new(fd.to_string()).unwrap_or_else(|_| exit(4));
            let reopened = unsafe {
                libc::openat(
                    proc_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            let mut current: libc::stat = unsafe { zeroed() };
            if reopened < 0
                || unsafe { libc::fstat(reopened, &mut current) } != 0
                || current.st_dev != original.st_dev
                || current.st_ino != original.st_ino
                || !take_read_lease(reopened)
            {
                exit(4);
            }
            unsafe { libc::close(*fd) };
            *fd = reopened;
        }
        unsafe { libc::close(proc_fd) };
        if diagnostic {
            let enabled: c_int = 1;
            if unsafe {
                libc::setsockopt(
                    CONTROL_FD,
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enabled as *const c_int).cast(),
                    size_of::<c_int>() as libc::socklen_t,
                )
            } != 0
            {
                kill_and_wait(kill_fd, events);
                exit(5);
            }
        }
        if manager_dead || signal_ready(signal_fd) != Some(false) || !send_ack(CONTROL_FD, b'R') {
            kill_and_wait(kill_fd, events);
            exit(5);
        }
        let mut poll_fds = [
            libc::pollfd {
                fd: manager,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: CONTROL_FD,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signal_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // Diagnostic only; scheduling stalls and forced lease breaks remain unbounded.
        const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(2);
        let mut deadline = Instant::now() + WATCHDOG_TIMEOUT;
        loop {
            let timeout = if diagnostic {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                deadline
                    .saturating_duration_since(now)
                    .as_millis()
                    .clamp(1, i32::MAX as u128) as i32
            } else {
                -1
            };
            let result = unsafe {
                libc::poll(
                    poll_fds.as_mut_ptr(),
                    poll_fds.len() as libc::nfds_t,
                    timeout,
                )
            };
            if result < 0 && interrupted() {
                continue;
            }
            if result < 0
                || poll_fds[0].revents != 0
                || poll_fds[2].revents != 0
                || poll_fds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
            {
                break;
            }
            if diagnostic && Instant::now() >= deadline {
                break;
            }
            if poll_fds[1].revents & libc::POLLIN != 0 {
                let mut byte = 0u8;
                let mut iov = libc::iovec {
                    iov_base: (&mut byte as *mut u8).cast(),
                    iov_len: 1,
                };
                let mut msg: libc::msghdr = unsafe { zeroed() };
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                let mut control = [0usize; 16];
                if diagnostic {
                    msg.msg_control = control.as_mut_ptr().cast();
                    msg.msg_controllen = size_of::<[usize; 16]>();
                }
                let n = unsafe { libc::recvmsg(CONTROL_FD, &mut msg, libc::MSG_CMSG_CLOEXEC) };
                let received_rights = n >= 0 && close_received_rights(&msg);
                let authenticated = if diagnostic && !received_rights {
                    let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                    if header.is_null() {
                        false
                    } else {
                        let len = unsafe { (*header).cmsg_len };
                        let expected =
                            unsafe { libc::CMSG_LEN(size_of::<libc::ucred>() as u32) } as usize;
                        let space =
                            unsafe { libc::CMSG_SPACE(size_of::<libc::ucred>() as u32) } as usize;
                        if unsafe { (*header).cmsg_level } != libc::SOL_SOCKET
                            || unsafe { (*header).cmsg_type } != libc::SCM_CREDENTIALS
                            || len != expected
                            || msg.msg_controllen != space
                        {
                            false
                        } else {
                            let credentials = unsafe {
                                ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
                            };
                            credentials.pid == peer.pid && credentials.uid == peer.uid
                        }
                    }
                } else {
                    !diagnostic && !received_rights && msg.msg_controllen == 0
                };
                if diagnostic
                    && n == 1
                    && byte == b'H'
                    && msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                    && authenticated
                    && signal_ready(signal_fd) == Some(false)
                    && signal_ready(manager) == Some(false)
                    && fds[2..count as usize + 2]
                        .iter()
                        .all(|&fd| unsafe { libc::fcntl(fd, libc::F_GETLEASE) } == libc::F_RDLCK)
                {
                    if !send_ack(CONTROL_FD, b'H') {
                        break;
                    }
                    deadline = Instant::now() + WATCHDOG_TIMEOUT;
                    continue;
                }
                if n == 1
                    && byte == b'Q'
                    && msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                    && authenticated
                    && populated(events) == Some(false)
                    && signal_ready(signal_fd) == Some(false)
                    && fds[2..count as usize + 2]
                        .iter()
                        .all(|&fd| unsafe { libc::fcntl(fd, libc::F_GETLEASE) } == libc::F_RDLCK)
                    && send_ack(CONTROL_FD, b'Q')
                {
                    exit(0);
                }
                break;
            }
        }
        kill_and_wait(kill_fd, events);
        exit(0);
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ready_heartbeat_and_disarm_ack_fail_promptly_when_socket_queue_is_full() {
            let mut fds = [-1; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                        0,
                        fds.as_mut_ptr(),
                    )
                },
                0
            );
            for _ in 0..100_000 {
                if !send_ack(fds[0], b'H') {
                    break;
                }
            }
            let started = Instant::now();
            assert!(!send_ack(fds[0], b'R'));
            assert!(!send_ack(fds[0], b'H'));
            assert!(!send_ack(fds[0], b'Q'));
            assert!(started.elapsed() < Duration::from_millis(250));
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
        }

        #[test]
        fn received_rights_are_closed_even_when_control_is_truncated() {
            let mut sockets = [-1; 2];
            let mut pipes = [-1; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                        0,
                        sockets.as_mut_ptr(),
                    )
                },
                0
            );
            assert_eq!(
                unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let enabled: c_int = 1;
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        sockets[1],
                        libc::SOL_SOCKET,
                        libc::SO_PASSCRED,
                        (&enabled as *const c_int).cast(),
                        size_of::<c_int>() as libc::socklen_t,
                    )
                },
                0
            );
            let sent_fds = [pipes[0], pipes[1], pipes[0]];
            let mut byte = b'H';
            let mut iov = libc::iovec {
                iov_base: (&mut byte as *mut u8).cast(),
                iov_len: 1,
            };
            let mut outgoing = [0usize; 16];
            let mut msg: libc::msghdr = unsafe { zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = outgoing.as_mut_ptr().cast();
            msg.msg_controllen =
                unsafe { libc::CMSG_SPACE((3 * size_of::<c_int>()) as u32) } as usize;
            let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            unsafe {
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN((3 * size_of::<c_int>()) as u32) as usize;
                ptr::copy_nonoverlapping(
                    sent_fds.as_ptr(),
                    libc::CMSG_DATA(header).cast::<c_int>(),
                    3,
                );
            }
            assert_eq!(unsafe { libc::sendmsg(sockets[0], &msg, 0) }, 1);
            let mut incoming = [0usize; 16];
            msg.msg_control = incoming.as_mut_ptr().cast();
            // Credentials fit, but only two of three passed FDs fit.
            msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::ucred>() as u32) }
                as usize
                + unsafe { libc::CMSG_LEN((2 * size_of::<c_int>()) as u32) } as usize;
            assert_eq!(
                unsafe { libc::recvmsg(sockets[1], &mut msg, libc::MSG_CMSG_CLOEXEC) },
                1
            );
            assert_ne!(msg.msg_flags & libc::MSG_CTRUNC, 0);
            let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            assert!(!header.is_null());
            assert_eq!(unsafe { (*header).cmsg_type }, libc::SCM_CREDENTIALS);
            let rights = unsafe { libc::CMSG_NXTHDR(&msg, header) };
            assert!(!rights.is_null());
            assert_eq!(unsafe { (*rights).cmsg_type }, libc::SCM_RIGHTS);
            let data = unsafe { libc::CMSG_DATA(rights).cast::<c_int>() };
            let received = unsafe { [ptr::read_unaligned(data), ptr::read_unaligned(data.add(1))] };
            assert!(close_received_rights(&msg));
            for fd in received {
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            }
            for fd in sockets.into_iter().chain(pipes) {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

pub fn run_backup_observer() -> ! {
    linux::main()
}
