//! Experimental backup observer manager. Not connected to apply.
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io;
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd};

    // Temporary red-phase stubs; replaced by the production implementation.
    fn validate_cgroup_directory(_directory: &File) -> io::Result<()> {
        Ok(())
    }

    fn receive_ready(_socket: &File, _expected_pid: libc::pid_t) -> io::Result<()> {
        Ok(())
    }

    #[test]
    fn supervisor_rejects_non_cgroup_filesystem_before_mutating_it() {
        let directory = File::open(std::env::temp_dir()).unwrap();
        assert!(validate_cgroup_directory(&directory).is_err());
    }

    #[test]
    fn supervisor_rejects_ready_from_wrong_process() {
        let mut pair = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        let receiver = unsafe { File::from_raw_fd(pair[0]) };
        let sender = unsafe { File::from_raw_fd(pair[1]) };
        let enabled: libc::c_int = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    receiver.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enabled as *const libc::c_int).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            },
            0
        );
        assert_eq!(
            unsafe { libc::send(sender.as_raw_fd(), b"R".as_ptr().cast(), 1, 0) },
            1
        );
        assert!(receive_ready(&receiver, unsafe { libc::getpid() } + 1).is_err());
    }
}
