//! Diagnostic manager/launcher channel tests; never an operator authorization.
//! Linux disposable CI only. Red-phase contract for a real SCM_RIGHTS transfer.
#![cfg(test)]
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, RawFd};

fn send_worker_pidfd(_socket: RawFd, _pidfd: RawFd) -> io::Result<()> {
    Err(io::Error::other("worker pidfd transfer not implemented"))
}
fn receive_worker_pidfd(_socket: RawFd, _sender: libc::pid_t) -> io::Result<File> {
    Err(io::Error::other("worker pidfd transfer not implemented"))
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
        let received = receive_worker_pidfd(manager.as_raw_fd(), expected);
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
    fn manager_receives_real_pidfd_from_authenticated_launcher() {
        transfer(true);
    }
    #[test]
    fn manager_rejects_pidfd_from_unexpected_process() {
        transfer(false);
    }
}
