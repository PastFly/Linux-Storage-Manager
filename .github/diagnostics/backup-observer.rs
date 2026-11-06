//! Disposable Linux observer; research prototype, not production code.
//! See README.md for its strict READY/GO contract and limitations.
#[cfg(target_os = "linux")]
mod linux {
    use libc::{c_int, c_void};
    use std::ffi::OsStr;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;
    use std::time::Duration;

    const MAX_LEASES: usize = 32;
    const MAX_FDS: usize = MAX_LEASES + 2;
    const CONTROL_FD: c_int = 3;
    const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

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
        let raw = args
            .next()
            .and_then(|s| s.into_string().ok())
            .and_then(|s| s.parse::<c_int>().ok());
        let Some(raw) = raw.filter(|&fd| fd >= 3) else {
            exit(2)
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
        for &fd in &fds[2..count as usize + 2] {
            if unsafe { libc::fcntl(fd, libc::F_GETLEASE) } != libc::F_RDLCK {
                exit(4);
            }
        }
        let ack = || unsafe { libc::send(CONTROL_FD, b"R".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
        if manager_dead || ack() != 1 {
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
        ];
        loop {
            let result =
                unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, -1) };
            if result < 0 && interrupted() {
                continue;
            }
            if result < 0
                || poll_fds[0].revents != 0
                || poll_fds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
            {
                break;
            }
            if poll_fds[1].revents & libc::POLLIN != 0 {
                let mut byte = 0u8;
                let n = unsafe { libc::recv(CONTROL_FD, (&mut byte as *mut u8).cast(), 1, 0) };
                if n == 1 && byte == b'Q' && populated(events) == Some(false) {
                    let n = unsafe {
                        libc::send(CONTROL_FD, b"Q".as_ptr().cast(), 1, libc::MSG_NOSIGNAL)
                    };
                    if n == 1 {
                        exit(0);
                    }
                }
                break;
            }
        }
        kill_and_wait(kill_fd, events);
        exit(0);
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This observer requires Linux.");
    std::process::exit(2);
}
