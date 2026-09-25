use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

use thiserror::Error;

use crate::{
    PinnedPrivilegedTools, PrivilegedDescriptorLaunchSpec, PrivilegedLaunchPermit,
    PrivilegedProgram, MUTATION_ENABLED,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorExecOutcome {
    pub exit_code: i32,
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

fn execute_descriptor_stage(
    file: &File,
    program: PrivilegedProgram,
    argv: &[String],
    fixed_path: &str,
    fixed_locale: &str,
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

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error().into());
    }

    if pid == 0 {
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

    let mut status = 0_i32;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited != pid {
        return Err(io::Error::last_os_error().into());
    }
    if libc::WIFEXITED(status) {
        return Ok(DescriptorExecOutcome {
            exit_code: libc::WEXITSTATUS(status),
        });
    }
    Err(PrivilegedDescriptorExecError::ChildSignaled)
}

/// Validate the complete M1B27 launch chain against the pinned descriptors.
///
/// The descriptor-exec primitive is implemented and unit-tested with benign
/// ELF utilities, but production storage-tool spawning remains hard-disabled
/// while MUTATION_ENABLED is false. No production caller can cross this gate.
pub fn execute_privileged_descriptor_launch(
    permit: &PrivilegedLaunchPermit,
    launch: &PrivilegedDescriptorLaunchSpec,
    pinned: &PinnedPrivilegedTools,
) -> Result<DescriptorExecOutcome, PrivilegedDescriptorExecError> {
    if !permit.integrity_matches()? {
        return Err(PrivilegedDescriptorExecError::PermitIntegrityMismatch);
    }
    if !launch.integrity_matches()? {
        return Err(PrivilegedDescriptorExecError::LaunchIntegrityMismatch);
    }
    if !pinned.integrity_matches()? {
        return Err(PrivilegedDescriptorExecError::PinIntegrityMismatch);
    }
    if permit.launch_id != launch.launch_id
        || permit.authorization_id != launch.authorization_id
        || permit.plan_step_id != launch.plan_step_id
        || permit.command_digest != launch.command_digest
        || pinned.pin_id != launch.pin_id
        || pinned.authorization_id != launch.authorization_id
        || pinned.plan_step_id != launch.plan_step_id
        || pinned.command_digest != launch.command_digest
        || permit.mutation_enabled
        || permit.process_spawned
        || launch.process_spawned
    {
        return Err(PrivilegedDescriptorExecError::BindingMismatch);
    }

    if !MUTATION_ENABLED {
        return Err(PrivilegedDescriptorExecError::ProductionMutationDisabled);
    }

    execute_descriptor_stage(
        pinned.primary_file(),
        launch.primary.program,
        &launch.primary.argv,
        &launch.fixed_path,
        &launch.fixed_locale,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        )
        .unwrap();
        assert_eq!(outcome.exit_code, 1);
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
            ),
            Err(PrivilegedDescriptorExecError::BindingMismatch)
        ));
    }
}
