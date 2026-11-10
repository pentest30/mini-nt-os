//! Windows: the QEMU processes of a run die with `xtask`.
//!
//! Each QEMU a watched boot starts goes into one job object of the `xtask`
//! process, created with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: when `xtask`
//! ends, however it ends (finished, interrupted, killed with the shell that
//! ran it), the system closes the job's last handle and ends its QEMU. No QEMU
//! outlives its run, so nothing has to end QEMU processes by name
//! (`taskkill /IM qemu-system-x86_64.exe`), which would also end the runs of
//! other sessions on the machine.
//!
//! The process is put in the job just after it starts: an `xtask` killed in
//! between leaves that one QEMU behind.

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::sync::OnceLock;

type Handle = *mut c_void;

/// JOBOBJECT_BASIC_LIMIT_INFORMATION.
#[repr(C)]
#[derive(Default)]
struct BasicLimitInformation {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

/// JOBOBJECT_EXTENDED_LIMIT_INFORMATION (with IO_COUNTERS, six counters).
#[repr(C)]
#[derive(Default)]
struct ExtendedLimitInformation {
    basic_limit_information: BasicLimitInformation,
    io_info: [u64; 6],
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<BasicLimitInformation>() == 64);
    assert!(size_of::<ExtendedLimitInformation>() == 144);
};

/// JobObjectExtendedLimitInformation.
const EXTENDED_LIMIT_INFORMATION: i32 = 9;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;

#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> Handle;
    fn SetInformationJobObject(job: Handle, class: i32, information: *const c_void, length: u32) -> i32;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
}

/// The job's handle, kept open for the life of `xtask` (never closed: its end
/// closes it). As an address, which is `Send` and `Sync`.
struct Job(usize);

/// The job of this `xtask`, created on first use.
fn job() -> Result<&'static Job, String> {
    static JOB: OnceLock<Result<Job, String>> = OnceLock::new();
    JOB.get_or_init(|| {
        // SAFETY: no security attributes, no name: an anonymous job.
        let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
        if job.is_null() {
            return Err(format!("CreateJobObjectW: {}", std::io::Error::last_os_error()));
        }
        let mut limits = ExtendedLimitInformation::default();
        limits.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `job` is the job just created; `limits` is a live
        // JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the length given.
        let set = unsafe {
            SetInformationJobObject(
                job,
                EXTENDED_LIMIT_INFORMATION,
                (&raw const limits).cast(),
                size_of::<ExtendedLimitInformation>() as u32,
            )
        };
        if set == 0 {
            return Err(format!("SetInformationJobObject: {}", std::io::Error::last_os_error()));
        }
        Ok(Job(job as usize))
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// Puts `child` in the job of this `xtask`: it ends with it.
pub fn contain(child: &Child) -> Result<(), String> {
    let job = job()?;
    // SAFETY: the job's handle stays open for the life of the process, and
    // `child` holds its process handle open during the call.
    let assigned = unsafe { AssignProcessToJobObject(job.0 as Handle, child.as_raw_handle()) };
    if assigned == 0 {
        return Err(format!("AssignProcessToJobObject: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}
