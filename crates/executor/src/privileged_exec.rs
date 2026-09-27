use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PinnedPrivilegedTools, PrivilegedCommandSpec, PrivilegedDescriptorLaunchSpec,
    PrivilegedLaunchPermit, PrivilegedProgram, MUTATION_ENABLED,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorExecOutcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedDescriptorSequenceOutcome {
    pub primary: DescriptorExecOutcome,
    pub kernel_refresh: Option<DescriptorExecOutcome>,
}

#[derive(Debug, Error)]
pub enum PrivilegedDescriptorExecError {
    #[error("launch permit integrity check failed")]
    PermitIntegrityMismatch,
    #[error("descriptor launch specification integrity check failed")]
    LaunchIntegrityMismatch,
    #[error("pinned executable receipt integrity check failed")]
    PinIntegrityMismatch,
    #[error("launch permit does not match the exact descriptor launch")]
    BindingMismatch,
    #[error("command stdin payload does not match the descriptor launch contract")]
    StdinBindingMismatch,
    #[error("kernel-refresh command does not match the descriptor launch contract")]
    KernelRefreshBindingMismatch,
    #[error("production descriptor execution remains disabled")]
    ProductionMutationDisabled,
    #[error("descriptor exec argument contains an embedded NUL byte")]
    EmbeddedNul,
    #[error("descriptor exec child terminated by signal")]
    ChildSignaled,
    #[error("descriptor exec I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("descriptor exec serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn cstring(value: &str) -> Result<CString, PrivilegedDescriptorExecError> {
    CString::new(value).map_err(|_| PrivilegedDescriptorExecError::EmbeddedNul)
}

fn write_all_fd(fd: libc::c_int, mut bytes: &[u8]) -> Result<(), io::Error> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "descriptor stdin pipe accepted zero bytes",
            ));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

const OUTPUT_CAPTURE_LIMIT: usize = 64 * 1024;

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_bounded(mut file: File) -> Result<CapturedOutput, io::Error> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = OUTPUT_CAPTURE_LIMIT.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = remaining.min(read);
            bytes.extend_from_slice(&buffer[..keep]);
            if keep < read {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok(CapturedOutput { bytes, truncated })
}

fn pipe_cloexec() -> Result<[libc::c_int; 2], io::Error> {
    let mut fds = [-1_i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fds)
}

fn close_fd(fd: libc::c_int) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn execute_descriptor_stage(
    file: &File,
    program: PrivilegedProgram,
    argv: &[String],
    fixed_path: &str,
    fixed_locale: &str,
    stdin_payload: Option<&[u8]>,
) -> Result<DescriptorExecOutcome, PrivilegedDescriptorExecError> {
    if argv.first().map(String::as_str) != Some(program.as_str()) {
        return Err(PrivilegedDescriptorExecError::BindingMismatch);
    }

    let argv_c = argv
        .iter()
        .map(|arg| cstring(arg))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv_ptrs = argv_c
        .iter()
        .map(|arg| arg.as_ptr())
        .collect::<Vec<*const libc::c_char>>();
    argv_ptrs.push(std::ptr::null());

    let path_env = cstring(&format!("PATH={fixed_path}"))?;
    let locale_env = cstring(&format!("LC_ALL={fixed_locale}"))?;
    let mut env_ptrs = vec![path_env.as_ptr(), locale_env.as_ptr(), std::ptr::null()];

    let dev_null = File::open("/dev/null")?;
    let stdin_pipe = if stdin_payload.is_some() {
        Some(pipe_cloexec()?)
    } else {
        None
    };
    let stdout_pipe = pipe_cloexec()?;
    let stderr_pipe = match pipe_cloexec() {
        Ok(pipe) => pipe,
        Err(error) => {
            close_fd(stdout_pipe[0]);
            close_fd(stdout_pipe[1]);
            if let Some(pipe) = stdin_pipe {
                close_fd(pipe[0]);
                close_fd(pipe[1]);
            }
            return Err(error.into());
        }
    };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        close_fd(stdout_pipe[0]);
        close_fd(stdout_pipe[1]);
        close_fd(stderr_pipe[0]);
        close_fd(stderr_pipe[1]);
        if let Some(pipe) = stdin_pipe {
            close_fd(pipe[0]);
            close_fd(pipe[1]);
        }
        return Err(io::Error::last_os_error().into());
    }

    if pid == 0 {
        close_fd(stdout_pipe[0]);
        close_fd(stderr_pipe[0]);

        let stdin_fd = if let Some(pipe) = stdin_pipe {
            close_fd(pipe[1]);
            pipe[0]
        } else {
            dev_null.as_raw_fd()
        };
        if unsafe { libc::dup2(stdin_fd, libc::STDIN_FILENO) } < 0
            || unsafe { libc::dup2(stdout_pipe[1], libc::STDOUT_FILENO) } < 0
            || unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) } < 0
        {
            unsafe { libc::_exit(126) };
        }
        if stdin_fd != libc::STDIN_FILENO {
            close_fd(stdin_fd);
        }
        if stdout_pipe[1] != libc::STDOUT_FILENO {
            close_fd(stdout_pipe[1]);
        }
        if stderr_pipe[1] != libc::STDERR_FILENO {
            close_fd(stderr_pipe[1]);
        }

        let result = unsafe {
            libc::fexecve(
                file.as_raw_fd(),
                argv_ptrs.as_ptr(),
                env_ptrs.as_mut_ptr().cast_const(),
            )
        };
        let _ = result;
        unsafe { libc::_exit(127) };
    }

    close_fd(stdout_pipe[1]);
    close_fd(stderr_pipe[1]);

    let stdout_file = unsafe { File::from_raw_fd(stdout_pipe[0]) };
    let stderr_file = unsafe { File::from_raw_fd(stderr_pipe[0]) };
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout_file));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr_file));

    let mut write_error = None;
    if let (Some(payload), Some(pipe)) = (stdin_payload, stdin_pipe) {
        close_fd(pipe[0]);
        if let Err(error) = write_all_fd(pipe[1], payload) {
            write_error = Some(error);
        }
        close_fd(pipe[1]);
    }

    let mut status = 0_i32;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            break;
        }
        if waited < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
    }

    let stdout = stdout_reader
        .join()
        .map_err(|_| io::Error::other("stdout capture thread panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| io::Error::other("stderr capture thread panicked"))??;

    if let Some(error) = write_error {
        return Err(error.into());
    }
    if libc::WIFEXITED(status) {
        return Ok(DescriptorExecOutcome {
            exit_code: libc::WEXITSTATUS(status),
            stdout: stdout.bytes,
            stderr: stderr.bytes,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
        });
    }
    Err(PrivilegedDescriptorExecError::ChildSignaled)
}

fn stdin_matches_launch(
    command: &PrivilegedCommandSpec,
    launch: &PrivilegedDescriptorLaunchSpec,
) -> bool {
    match command.stdin_payload.as_deref() {
        Some(payload) => {
            let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
            launch.stdin_len == payload.len() as u64
                && launch.stdin_sha256.as_deref() == Some(digest.as_str())
        }
        None => launch.stdin_len == 0 && launch.stdin_sha256.is_none(),
    }
}

fn kernel_refresh_matches_launch(
    command: &PrivilegedCommandSpec,
    launch: &PrivilegedDescriptorLaunchSpec,
) -> bool {
    match (&command.kernel_refresh, &launch.kernel_refresh) {
        (Some(command), Some(launch)) => {
            command.program == launch.program
                && launch.argv.first().map(String::as_str) == Some(command.program.as_str())
                && launch.argv.get(1..) == Some(command.args.as_slice())
        }
        (None, None) => true,
        _ => false,
    }
}

/// Validate the complete M1B27 launch chain against the pinned descriptors.
///
/// M1B29 additionally binds exact stdin bytes and the optional kernel-refresh
/// stage. The low-level descriptor runner is unit-tested with benign ELF
/// utilities, but production storage-tool spawning remains hard-disabled while
/// MUTATION_ENABLED is false.
pub fn execute_privileged_descriptor_launch(
    permit: &PrivilegedLaunchPermit,
    launch: &PrivilegedDescriptorLaunchSpec,
    pinned: &PinnedPrivilegedTools,
    command: &PrivilegedCommandSpec,
) -> Result<PrivilegedDescriptorSequenceOutcome, PrivilegedDescriptorExecError> {
    if !permit.integrity_matches()? {
        return Err(PrivilegedDescriptorExecError::PermitIntegrityMismatch);
    }
    if !launch.integrity_matches()? {
        return Err(PrivilegedDescriptorExecError::LaunchIntegrityMismatch);
    }
    if !pinned.integrity_matches()? {
        return Err(PrivilegedDescriptorExecError::PinIntegrityMismatch);
    }
    let command_digest = command
        .digest()
        .map_err(|_| PrivilegedDescriptorExecError::BindingMismatch)?;
    if permit.launch_id != launch.launch_id
        || permit.authorization_id != launch.authorization_id
        || permit.plan_step_id != launch.plan_step_id
        || permit.command_digest != launch.command_digest
        || launch.command_digest != command_digest
        || pinned.pin_id != launch.pin_id
        || pinned.authorization_id != launch.authorization_id
        || pinned.plan_step_id != launch.plan_step_id
        || pinned.command_digest != launch.command_digest
        || command.plan_step_id != launch.plan_step_id
        || permit.mutation_enabled
        || permit.process_spawned
        || launch.process_spawned
    {
        return Err(PrivilegedDescriptorExecError::BindingMismatch);
    }
    if !stdin_matches_launch(command, launch) {
        return Err(PrivilegedDescriptorExecError::StdinBindingMismatch);
    }
    if !kernel_refresh_matches_launch(command, launch) {
        return Err(PrivilegedDescriptorExecError::KernelRefreshBindingMismatch);
    }

    if !MUTATION_ENABLED {
        return Err(PrivilegedDescriptorExecError::ProductionMutationDisabled);
    }

    let primary = execute_descriptor_stage(
        pinned.primary_file(),
        launch.primary.program,
        &launch.primary.argv,
        &launch.fixed_path,
        &launch.fixed_locale,
        command.stdin_payload.as_deref().map(str::as_bytes),
    )?;

    let kernel_refresh = if primary.exit_code == 0 {
        match (pinned.kernel_refresh_file(), launch.kernel_refresh.as_ref()) {
            (Some(file), Some(refresh)) => Some(execute_descriptor_stage(
                file,
                refresh.program,
                &refresh.argv,
                &launch.fixed_path,
                &launch.fixed_locale,
                None,
            )?),
            (None, None) => None,
            _ => return Err(PrivilegedDescriptorExecError::KernelRefreshBindingMismatch),
        }
    } else {
        None
    };

    Ok(PrivilegedDescriptorSequenceOutcome {
        primary,
        kernel_refresh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn benign_elf(name: &str) -> File {
        File::open(format!("/usr/bin/{name}"))
            .or_else(|_| File::open(format!("/bin/{name}")))
            .unwrap()
    }

    #[test]
    fn descriptor_exec_runs_benign_true_without_path_lookup() {
        let file = benign_elf("true");
        let outcome = execute_descriptor_stage(
            &file,
            PrivilegedProgram::Lvextend,
            &["lvextend".into()],
            "/usr/sbin:/usr/bin:/sbin:/bin",
            "C",
            None,
        )
        .unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.is_empty());
        assert!(outcome.stderr.is_empty());
    }

    #[test]
    fn descriptor_exec_observes_child_exit_status() {
        let file = benign_elf("false");
        let outcome = execute_descriptor_stage(
            &file,
            PrivilegedProgram::Lvextend,
            &["lvextend".into()],
            "/usr/sbin:/usr/bin:/sbin:/bin",
            "C",
            None,
        )
        .unwrap();
        assert_eq!(outcome.exit_code, 1);
    }

    #[test]
    fn descriptor_exec_delivers_exact_stdin_bytes() {
        let root =
            std::env::temp_dir().join(format!("lsm-descriptor-stdin-{}", std::process::id()));
        let payload = b"exact-sfdisk-style-payload\n";
        fs::write(&root, payload).unwrap();

        let file = benign_elf("cmp");
        let argv = vec![
            "lvextend".into(),
            "-s".into(),
            "-".into(),
            root.to_string_lossy().into_owned(),
        ];
        let outcome = execute_descriptor_stage(
            &file,
            PrivilegedProgram::Lvextend,
            &argv,
            "/usr/sbin:/usr/bin:/sbin:/bin",
            "C",
            Some(payload),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, 0);

        fs::remove_file(root).unwrap();
    }

    #[test]
    fn descriptor_exec_uses_dev_null_when_no_stdin_payload_exists() {
        let file = benign_elf("cat");
        let outcome = execute_descriptor_stage(
            &file,
            PrivilegedProgram::Lvextend,
            &["lvextend".into()],
            "/usr/sbin:/usr/bin:/sbin:/bin",
            "C",
            None,
        )
        .unwrap();
        assert_eq!(outcome.exit_code, 0);
    }

    #[test]
    fn descriptor_exec_captures_stdout_without_inheriting_parent_output() {
        let file = benign_elf("printf");
        let outcome = execute_descriptor_stage(
            &file,
            PrivilegedProgram::Lvextend,
            &["lvextend".into(), "captured-output".into()],
            "/usr/sbin:/usr/bin:/sbin:/bin",
            "C",
            None,
        )
        .unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.stdout, b"captured-output");
        assert!(outcome.stderr.is_empty());
        assert!(!outcome.stdout_truncated);
    }

    #[test]
    fn descriptor_exec_captures_stderr_for_failed_child() {
        let file = benign_elf("ls");
        let outcome = execute_descriptor_stage(
            &file,
            PrivilegedProgram::Lvextend,
            &[
                "lvextend".into(),
                "--".into(),
                "/definitely-not-present-lsm-descriptor-test".into(),
            ],
            "/usr/sbin:/usr/bin:/sbin:/bin",
            "C",
            None,
        )
        .unwrap();
        assert_ne!(outcome.exit_code, 0);
        assert!(outcome.stdout.is_empty());
        assert!(!outcome.stderr.is_empty());
        assert!(!outcome.stderr_truncated);
    }

    #[test]
    fn descriptor_exec_rejects_argv_program_mismatch_before_fork() {
        let file = benign_elf("true");
        assert!(matches!(
            execute_descriptor_stage(
                &file,
                PrivilegedProgram::Lvextend,
                &["resize2fs".into()],
                "/usr/sbin:/usr/bin:/sbin:/bin",
                "C",
                None,
            ),
            Err(PrivilegedDescriptorExecError::BindingMismatch)
        ));
    }
}
