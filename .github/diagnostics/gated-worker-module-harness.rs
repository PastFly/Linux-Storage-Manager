//! Disposable test wrapper for gated-worker-module.rs; NOT a production manager.
#[path = "gated-worker-module.rs"]
mod gated;

#[cfg(feature = "diagnostic-backup-watchdog")]
#[path = "../../crates/executor/src/backup_supervisor.rs"]
mod backup_supervisor;
#[cfg(feature = "diagnostic-backup-watchdog")]
#[path = "diagnostic-controller-channel.rs"]
mod diagnostic_channel;
#[cfg(feature = "diagnostic-backup-watchdog")]
#[path = "diagnostic-controller-manager.rs"]
mod diagnostic_manager;

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

struct TestGuard {
    device: u64,
    inode: u64,
    calls: usize,
    reject_at: Option<usize>,
    worker_pidfd: Option<File>,
}
impl gated::ExternalGuard for TestGuard {
    fn validate(&mut self, group: &File) -> io::Result<()> {
        self.calls += 1;
        if self.reject_at == Some(self.calls) {
            return Err(io::Error::other("injected guard failure"));
        }
        if self.calls > 1 && self.worker_pidfd.is_none() {
            return Err(io::Error::other(
                "worker pidfd was not registered before READY",
            ));
        }
        let metadata = group.metadata()?;
        if (metadata.dev(), metadata.ino()) != (self.device, self.inode) {
            return Err(io::Error::other("wrong test group"));
        }
        Ok(())
    }

    // This local duplicate checks callback ordering only. It is not a
    // protected transfer to an independent manager.
    fn register_worker(&mut self, worker_pidfd: &File) -> io::Result<()> {
        if std::env::var_os("LSM_TEST_REGISTER_FAIL").as_deref() == Some(std::ffi::OsStr::new("1"))
        {
            return Err(io::Error::other("injected pidfd registration failure"));
        }
        if self.worker_pidfd.is_some() {
            return Err(io::Error::other("worker pidfd registered twice"));
        }
        self.worker_pidfd = Some(worker_pidfd.try_clone()?);
        Ok(())
    }
}
fn snapshot() -> io::Result<File> {
    let source = File::open("/proc/self/exe")?;
    let mut fd = unsafe {
        libc::memfd_create(
            c"gated-worker-test".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | 0x10,
        )
    };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        fd = unsafe {
            libc::memfd_create(
                c"gated-worker-test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
    }
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut target = unsafe { File::from_raw_fd(fd) };
    let copied = io::copy(&mut source.take(64 * 1024 * 1024), &mut target)?;
    if copied == 0 || copied == 64 * 1024 * 1024 {
        return Err(io::Error::other("invalid snapshot size"));
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(target.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(target)
}
fn stop_wait_outcome(
    stop: Result<(), gated::StopError>,
    wait: io::Result<libc::c_int>,
) -> io::Result<()> {
    let wait = wait.and_then(|status| {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            Ok(())
        } else {
            Err(io::Error::other("unexpected child status"))
        }
    });
    match (stop, wait) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(wait)) => Err(wait),
        (Err(stop), Ok(()))
            if stop.cgroup_kill.is_none()
                && stop
                    .worker_signal
                    .as_ref()
                    .and_then(io::Error::raw_os_error)
                    == Some(libc::ESRCH) =>
        {
            Ok(())
        }
        (Err(stop), Ok(())) => Err(io::Error::other(format!("stop failed: {stop:?}"))),
        (Err(stop), Err(wait)) => Err(io::Error::other(format!(
            "stop failed: {stop:?}; wait failed: {wait}"
        ))),
    }
}
fn stop_and_wait(worker: &mut gated::Worker) -> io::Result<()> {
    let stop = worker.stop();
    let wait = worker.wait_stopped();
    stop_wait_outcome(stop, wait)
}

fn run(group_path: &Path, mode: &str, marker: &Path) -> io::Result<()> {
    let group = File::open(group_path)?;
    let meta = group.metadata()?;
    let mut guard = TestGuard {
        device: meta.dev(),
        inode: meta.ino(),
        calls: 0,
        worker_pidfd: None,
        reject_at: match mode {
            "before" => Some(1),
            "after-spawn" => Some(2),
            "before-go" => Some(4),
            "success" => None,
            _ => return Err(io::Error::other("bad mode")),
        },
    };
    let command = gated::PinnedCommand {
        executable: snapshot()?,
        argv: vec![
            CString::new("gated-test").unwrap(),
            CString::new("--payload").unwrap(),
            CString::new(marker.as_os_str().as_encoded_bytes())
                .map_err(|_| io::Error::other("bad marker"))?,
        ],
        environment: Vec::new(),
    };
    let mut worker = match gated::prepare(&mut guard, group, command) {
        Err(gated::StartFailure::BeforeSpawn(error)) if mode == "before" => {
            eprintln!("expected pre-spawn failure: {error}");
            return Ok(());
        }
        Err(gated::StartFailure::BeforeSpawn(error)) => return Err(error),
        Err(gated::StartFailure::AfterSpawn { cause, mut worker }) if mode == "after-spawn" => {
            eprintln!(
                "expected post-spawn failure with pidfd {}: {cause}",
                worker.pidfd().as_raw_fd()
            );
            stop_and_wait(&mut worker)?;
            return Ok(());
        }
        Err(gated::StartFailure::AfterSpawn { cause, mut worker }) => {
            let cleanup = stop_and_wait(&mut worker);
            return Err(io::Error::other(format!(
                "unexpected post-spawn failure: {cause}; cleanup: {cleanup:?}"
            )));
        }
        Ok(worker) => worker,
    };
    if marker.exists() {
        return Err(io::Error::other("payload started before GO"));
    }
    if mode == "before-go" {
        if worker.go(&mut guard).is_ok() {
            return Err(io::Error::other("GO accepted unready guard"));
        }
        stop_and_wait(&mut worker)?;
        if marker.exists() {
            return Err(io::Error::other("payload ran despite rejected GO"));
        }
        return Ok(());
    }
    if let Err(error) = worker.go(&mut guard) {
        let cleanup = stop_and_wait(&mut worker);
        return Err(io::Error::other(format!(
            "GO failed: {error}; cleanup: {cleanup:?}"
        )));
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !marker.exists() {
        let cleanup = stop_and_wait(&mut worker);
        return Err(io::Error::other(format!(
            "payload did not run; cleanup: {cleanup:?}"
        )));
    }
    stop_and_wait(&mut worker)
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    #[cfg(feature = "diagnostic-backup-watchdog")]
    if args.len() == 5 && args[1] == "--diagnostic-manager" {
        if let Err(error) = diagnostic_manager::manager(
            Path::new(&args[2]),
            args[3].as_os_str(),
            Path::new(&args[4]),
        ) {
            eprintln!("diagnostic manager: {error}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(feature = "diagnostic-backup-watchdog")]
    if args.len() == 6 && args[1] == "--diagnostic-launcher" {
        if let Err(error) = diagnostic_manager::launcher(
            Path::new(&args[2]),
            &args[3],
            &args[4],
            Path::new(&args[5]),
        ) {
            eprintln!("diagnostic launcher: {error}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(feature = "diagnostic-backup-watchdog")]
    if args.len() == 3 && args[1] == "--payload-session" {
        if let Err(error) = diagnostic_manager::payload(Path::new(&args[2])) {
            eprintln!("diagnostic payload: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() == 3 && args[1] == "--payload" {
        if let Err(error) = std::fs::write(&args[2], b"started") {
            eprintln!("payload: {error}");
            std::process::exit(1);
        }
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
    if args.len() != 4 {
        eprintln!("usage: harness CGROUP MODE MARKER");
        std::process::exit(2);
    }
    if let Err(error) = run(
        Path::new(&args[1]),
        &args[2].to_string_lossy(),
        Path::new(&args[3]),
    ) {
        eprintln!("harness failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    #[test]
    fn stop_and_wait_failures_are_both_retained() {
        let stop = gated::StopError {
            worker_signal: Some(io::Error::other("signal-failed")),
            cgroup_kill: Some(io::Error::other("group-failed")),
        };
        let error = stop_wait_outcome(Err(stop), Err(io::Error::other("wait-failed")))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("signal-failed")
                && error.contains("group-failed")
                && error.contains("wait-failed"),
            "{error}"
        );
    }
}
