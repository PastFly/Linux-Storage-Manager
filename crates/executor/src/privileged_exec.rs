use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PinnedPrivilegedTools, PrivilegedCommandSpec, PrivilegedDescriptorLaunchSpec,
    PrivilegedLaunchPermit, PrivilegedProgram, MUTATION_ENABLED,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorExecOutcome {
    pub exit_code: i32,
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
    let mut pipe_fds = [-1_i32; 2];
    if stdin_payload.is_some() {
        let result = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        if pipe_fds[0] >= 0 {
            unsafe {
                libc::close(pipe_fds[0]);
                libc::close(pipe_fds[1]);
            }
        }
        return Err(io::Error::last_os_error().into());
    }

    if pid == 0 {
        let stdin_fd = if stdin_payload.is_some() {
            unsafe {
                libc::close(pipe_fds[1]);
            }
            pipe_fds[0]
        } else {
            dev_null.as_raw_fd()
        };
        if unsafe { libc::dup2(stdin_fd, libc::STDIN_FILENO) } < 0 {
            unsafe { libc::_exit(126) };
        }
        if stdin_payload.is_some() && stdin_fd != libc::STDIN_FILENO {
            unsafe {
                libc::close(stdin_fd);
            }
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

    let mut write_error = None;
    if let Some(payload) = stdin_payload {
        unsafe {
            libc::close(pipe_fds[0]);
        }
        if let Err(error) = write_all_fd(pipe_fds[1], payload) {
            write_error = Some(error);
        }
        unsafe {
            libc::close(pipe_fds[1]);
        }
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

    if let Some(error) = write_error {
        return Err(error.into());
    }
    if libc::WIFEXITED(status) {
        return Ok(DescriptorExecOutcome {
            exit_code: libc::WEXITSTATUS(status),
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
