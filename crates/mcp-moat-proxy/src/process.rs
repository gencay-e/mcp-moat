//! Process-tree cleanup for wrapped servers.

#[cfg(windows)]
mod windows {
    use std::io;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// Keeps a Windows job alive. Dropping it terminates remaining job members.
    pub struct ChildJob(HANDLE);

    // Job handles may be used and closed from any thread.
    unsafe impl Send for ChildJob {}
    unsafe impl Sync for ChildJob {}

    /// Configure a command before spawn so no child code can run before job assignment.
    pub fn prepare(command: &mut tokio::process::Command) {
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED);
    }

    /// Assign a prepared child to a job, then resume its sole initial thread.
    /// On failure, request termination before returning the error.
    pub fn attach_and_resume(child: &mut tokio::process::Child) -> io::Result<ChildJob> {
        let result = (|| {
            let job = ChildJob::attach(child)?;
            resume_initial_thread(
                child
                    .id()
                    .ok_or_else(|| io::Error::other("child has exited"))?,
            )?;
            Ok(job)
        })();
        if result.is_err() {
            let _ = child.start_kill();
        }
        result
    }

    fn resume_initial_thread(pid: u32) -> io::Result<()> {
        use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        };
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        struct Handle(HANDLE);
        impl Drop for Handle {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let _snapshot = Handle(snapshot);
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if unsafe { Thread32First(snapshot, &mut entry) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut thread_id = None;
        loop {
            if entry.th32OwnerProcessID == pid && thread_id.replace(entry.th32ThreadID).is_some() {
                return Err(io::Error::other("suspended child has multiple threads"));
            }
            if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                    return Err(error);
                }
                break;
            }
        }
        let id = thread_id.ok_or_else(|| io::Error::other("suspended child thread not found"))?;
        let raw = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, id) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let thread = Handle(raw);
        let previous = unsafe { ResumeThread(thread.0) };
        if previous == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        if previous != 1 {
            return Err(io::Error::other("unexpected child thread suspend count"));
        }
        Ok(())
    }

    impl ChildJob {
        pub fn attach(child: &tokio::process::Child) -> io::Result<Self> {
            let raw = child
                .raw_handle()
                .ok_or_else(|| io::Error::other("child has exited"))?;
            // SAFETY: null attributes/name request an unnamed job with default security.
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let guard = Self(job);
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: the job and structure are valid, and the size matches the information class.
            let ok = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const _,
                    std::mem::size_of_val(&limits) as u32,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the child owns a live process handle throughout this call.
            if unsafe { AssignProcessToJobObject(job, raw as HANDLE) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(guard)
        }
    }
    impl Drop for ChildJob {
        fn drop(&mut self) {
            // SAFETY: this is the unique owner of the job handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
#[cfg(windows)]
pub use windows::{attach_and_resume, prepare, ChildJob};
