//! Diagnostic manager/launcher channel tests; never an operator authorization.
//! Linux disposable CI only. This is a transport, not a worker binding or guard.
#![cfg(test)]
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::time::{Duration, Instant};

fn require_packet_socket(fd: RawFd) -> io::Result<()> {
    for (option, expected) in [
        (libc::SO_TYPE, libc::SOCK_SEQPACKET),
        (libc::SO_DOMAIN, libc::AF_UNIX),
    ] {
        let mut actual: libc::c_int = 0;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&mut actual as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if actual != expected || length as usize != size_of::<libc::c_int>() {
            return Err(io::Error::other("unexpected socket type/domain"));
        }
    }
    Ok(())
}

fn require_live_sender(pidfd: RawFd, sender: libc::pid_t) -> io::Result<()> {
    if sender <= 0
        || std::fs::read_link(format!("/proc/self/fd/{pidfd}"))?.as_os_str() != "anon_inode:[pidfd]"
    {
        return Err(io::Error::other("invalid sender pidfd"));
    }
    let data = std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}"))?;
    let mut matches = data.lines().filter_map(|line| line.strip_prefix("Pid:"));
    let identity = matches
        .next()
        .and_then(|value| value.trim().parse::<libc::pid_t>().ok());
    if identity != Some(sender) || matches.next().is_some() {
        return Err(io::Error::other("sender pidfd identity mismatch"));
    }
    let mut item = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    // A signal storm is a failure, not a reason to wait indefinitely.
    for _ in 0..64 {
        let n = unsafe { libc::poll(&mut item, 1, 0) };
        if n == 0 && item.revents == 0 {
            return Ok(());
        }
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(io::Error::other("sender pidfd is dead or unavailable"));
    }
    Err(io::Error::other("sender pidfd poll interrupted repeatedly"))
}

fn send_worker_pidfd(socket: RawFd, pidfd: RawFd) -> io::Result<()> {
    require_packet_socket(socket)?;
    let mut byte = b'W';
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
    let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), pidfd);
    }
    let n = unsafe { libc::sendmsg(socket, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if n == 1 {
        Ok(())
    } else if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("short pidfd message"))
    }
}

// This authenticates the *sender* and owns the received descriptor. It does
// not yet authorize GO: the manager must independently bind that descriptor
// to the worker and pinned cgroup before use.
fn receive_worker_pidfd(
    socket: RawFd,
    sender_pidfd: RawFd,
    sender: libc::pid_t,
) -> io::Result<File> {
    require_packet_socket(socket)?;
    require_live_sender(sender_pidfd, sender)?;
    let mut enabled: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&mut enabled as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if enabled == 0 || length as usize != size_of::<libc::c_int>() || sender <= 0 {
        return Err(io::Error::other("unauthenticated channel"));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pidfd transfer timed out",
            ));
        }
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: socket,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pollfd, 1, timeout) };
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
        if pollfd.revents & libc::POLLIN == 0
            || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Err(io::Error::other("pidfd socket failed"));
        }
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
                socket,
                &mut msg,
                libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(
                e.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(e);
        }
        let mut descriptors = Vec::new();
        let mut credentials = None;
        let mut valid =
            n == 1 && byte == b'W' && msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0;
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !header.is_null() {
            let len = unsafe { (*header).cmsg_len };
            let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
            let offset = (header as usize).saturating_sub(msg.msg_control as usize);
            if len < minimum || offset > msg.msg_controllen || len > msg.msg_controllen - offset {
                valid = false;
                break;
            }
            let level = unsafe { (*header).cmsg_level };
            let kind = unsafe { (*header).cmsg_type };
            if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
                let bytes = len - minimum;
                if bytes % size_of::<libc::c_int>() != 0 {
                    valid = false;
                }
                let data = unsafe { libc::CMSG_DATA(header).cast::<libc::c_int>() };
                for index in 0..bytes / size_of::<libc::c_int>() {
                    let fd = unsafe { std::ptr::read_unaligned(data.add(index)) };
                    if fd >= 0 {
                        descriptors.push(unsafe { File::from_raw_fd(fd) });
                    } else {
                        valid = false;
                    }
                }
            } else if level == libc::SOL_SOCKET
                && kind == libc::SCM_CREDENTIALS
                && len == unsafe { libc::CMSG_LEN(size_of::<libc::ucred>() as u32) } as usize
            {
                let cred = unsafe {
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
                };
                if credentials.replace(cred).is_some() {
                    valid = false;
                }
            } else {
                valid = false;
            }
            header = unsafe { libc::CMSG_NXTHDR(&msg, header) };
        }
        valid &=
            credentials.is_some_and(|c| c.pid == sender && c.uid == unsafe { libc::geteuid() });
        if !valid || descriptors.len() != 1 {
            return Err(io::Error::other("invalid pidfd message"));
        }
        let fd = descriptors.pop().unwrap();
        if std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?.as_os_str()
            != "anon_inode:[pidfd]"
        {
            return Err(io::Error::other("descriptor is not pidfd"));
        }
        require_live_sender(sender_pidfd, sender)?;
        return Ok(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn pair() -> (File, File) {
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
        let on: libc::c_int = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    fds[0],
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&on as *const libc::c_int).cast(),
                    std::mem::size_of_val(&on) as libc::socklen_t,
                )
            },
            0
        );
        unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
    }

    // The launcher transfers its own real pidfd across a socket to its parent.
    // The sender stays alive until the parent releases it, making fdinfo stable.
    fn transfer(sender_expected: bool) {
        let (manager, launcher) = pair();
        let mut gate = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(gate[1]);
            }
            let own_pid = unsafe { libc::getpid() };
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, own_pid, 0) as i32 };
            if raw < 0 || send_worker_pidfd(launcher.as_raw_fd(), raw).is_err() {
                unsafe { libc::_exit(1) }
            }
            let mut byte = 0u8;
            unsafe {
                libc::read(gate[0], (&mut byte as *mut u8).cast(), 1);
                libc::_exit(0)
            }
        }
        unsafe {
            libc::close(gate[0]);
        }
        let expected = if sender_expected {
            pid
        } else {
            unsafe { libc::getpid() }
        };
        let pinned = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        assert!(pinned >= 0);
        let received = receive_worker_pidfd(manager.as_raw_fd(), pinned, expected);
        unsafe {
            libc::close(pinned);
        }
        let verification = received.as_ref().ok().and_then(|fd| {
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()
        });
        unsafe {
            libc::close(gate[1]);
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        if sender_expected {
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "sender failed"
            );
            assert!(
                received.is_ok(),
                "real SCM_RIGHTS transfer rejected: {received:?}"
            );
            let expected_line = format!("Pid:\t{pid}");
            assert!(
                verification
                    .unwrap()
                    .lines()
                    .any(|line| line == expected_line),
                "wrong pidfd"
            );
        } else {
            assert!(
                received.is_err(),
                "message from unexpected process was accepted"
            );
        }
    }

    #[test]
    fn rejects_stream_socket_even_if_message_starts_with_valid_pidfd_packet() {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let on: libc::c_int = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    fds[0],
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&on as *const libc::c_int).cast(),
                    std::mem::size_of_val(&on) as libc::socklen_t,
                )
            },
            0
        );
        let own = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
        assert!(own >= 0);
        // Stream sockets do not preserve this message boundary.
        let sent = send_worker_pidfd(fds[1], own);
        let result = if let Err(error) = sent {
            Err(error)
        } else {
            assert_eq!(
                unsafe { libc::send(fds[1], b"extra".as_ptr().cast(), 5, 0) },
                5
            );
            receive_worker_pidfd(fds[0], own, unsafe { libc::getpid() })
        };
        for fd in fds.into_iter().chain([own]) {
            unsafe {
                libc::close(fd);
            }
        }
        assert!(
            result.is_err(),
            "stream accepted as an authenticated packet channel"
        );
    }

    #[test]
    fn rejects_dead_pinned_sender_even_if_numeric_credentials_match() {
        let (manager, launcher) = pair();
        let dead = unsafe { libc::fork() };
        assert!(dead >= 0);
        if dead == 0 {
            unsafe { libc::_exit(0) }
        }
        let dead_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, dead, 0) as i32 };
        assert!(dead_fd >= 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(dead, &mut status, 0) }, dead);
        let own = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
        assert!(own >= 0);
        send_worker_pidfd(launcher.as_raw_fd(), own).unwrap();
        let result = receive_worker_pidfd(manager.as_raw_fd(), dead_fd, unsafe { libc::getpid() });
        unsafe {
            libc::close(dead_fd);
            libc::close(own);
        }
        assert!(result.is_err(), "dead sender pidfd was ignored");
    }

    #[test]
    fn manager_receives_real_pidfd_from_authenticated_launcher() {
        transfer(true);
    }
    #[test]
    fn manager_rejects_pidfd_from_unexpected_process() {
        transfer(false);
    }
}
