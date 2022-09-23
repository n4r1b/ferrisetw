//! Native API - Event Tracing evntrace header
//!
//! The `evntrace` module is an abstraction layer for the Windows evntrace library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `evntrace` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the crate level provide a safe API to interact
//! with the crate
use windows::core::{GUID, PCSTR};
use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows::Win32::Foundation::ERROR_CTX_CLOSE_PENDING;
use windows::Win32::Foundation::ERROR_WMI_INSTANCE_NOT_FOUND;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Diagnostics::Etw::{
    self, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_QUERY_INFO_CLASS,
};
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

use std::panic::AssertUnwindSafe;
use std::sync::RwLock;

use super::etw_types::*;
use crate::provider::Provider;
use crate::trace::{TraceData, TraceProperties, TraceTrait};
use crate::traits::*;

/// Evntrace native module errors
#[derive(Debug)]
pub enum EvntraceNativeError {
    /// Represents an Invalid Handle Error
    InvalidHandle,
    /// Represents an ERROR_ALREADY_EXISTS
    AlreadyExist,
    /// Represents an standard IO Error
    IoError(std::io::Error),
}

impl LastOsError<EvntraceNativeError> for EvntraceNativeError {}

impl From<std::io::Error> for EvntraceNativeError {
    fn from(err: std::io::Error) -> Self {
        EvntraceNativeError::IoError(err)
    }
}

pub(crate) type EvntraceNativeResult<T> = Result<T, EvntraceNativeError>;

unsafe extern "system" fn trace_callback_thunk(event_record: PEventRecord) {
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        let ctx: &TraceData = TraceData::unsafe_get_callback_ctx((*event_record).UserContext);
        ctx.on_event(*event_record);
    })) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("UNIMPLEMENTED PANIC: {e:?}");
            std::process::exit(1);
        }
    }
}

#[derive(Debug)]
pub(crate) struct NativeEtw {
    info: TraceInfo,
    session_handle: TraceHandle,
    registration_handle: TraceHandle,
}

impl NativeEtw {
    pub(crate) fn new() -> Self {
        NativeEtw {
            info: TraceInfo::default(),
            session_handle: INVALID_TRACE_HANDLE,
            registration_handle: INVALID_TRACE_HANDLE,
        }
    }

    pub(crate) fn session_handle(&self) -> TraceHandle {
        self.session_handle
    }

    // Not a big fan of this...
    pub(crate) fn fill_info<T>(
        &mut self,
        name: &str,
        properties: &TraceProperties,
        providers: &RwLock<Vec<Provider>>,
    ) where
        T: TraceTrait,
    {
        self.info.fill::<T>(name, properties, providers);
    }

    pub(crate) fn open(
        &mut self,
        trace_data: &TraceData,
    ) -> EvntraceNativeResult<EventTraceLogfile> {
        self.open_trace(trace_data)
    }

    pub(crate) fn close(&mut self) -> EvntraceNativeResult<()> {
        self.close_trace()
    }

    pub(crate) fn start(&mut self, trace_data: &TraceData) -> EvntraceNativeResult<()> {
        self.start_trace(trace_data)
    }

    pub(crate) fn stop(&self, trace_data: &TraceData) -> EvntraceNativeResult<()> {
        self.stop_trace(trace_data)
    }

    pub(crate) fn process(&self) -> EvntraceNativeResult<()> {
        if self.session_handle == INVALID_TRACE_HANDLE {
            return Err(EvntraceNativeError::InvalidHandle);
        }

        let mut now = FILETIME::default();
        unsafe {
            GetSystemTimeAsFileTime(&mut now);

            match Etw::ProcessTrace(&[self.session_handle], &mut now, std::ptr::null_mut()) {
                0 => Ok(()),
                e => Err(EvntraceNativeError::IoError(
                    std::io::Error::from_raw_os_error(e as i32),
                )),
            }
        }
    }

    pub(crate) fn register_trace(&mut self, trace_data: &TraceData) -> EvntraceNativeResult<()> {
        if let Err(err) = self.start_trace(trace_data) {
            if matches!(err, EvntraceNativeError::AlreadyExist) {
                // TODO: Check need admin errors
                self.stop_trace(trace_data)?;
                self.start_trace(trace_data)?;
            } else {
                return Err(err);
            }
        }
        Ok(())
    }

    fn start_trace(&mut self, trace_data: &TraceData) -> EvntraceNativeResult<()> {
        unsafe {
            let status = Etw::StartTraceA(
                &mut self.registration_handle,
                PCSTR::from_raw(trace_data.name.as_ptr()),
                &mut *self.info.properties,
            );

            if status == ERROR_ALREADY_EXISTS.0 {
                return Err(EvntraceNativeError::AlreadyExist);
            } else if status != 0 {
                return Err(EvntraceNativeError::IoError(
                    std::io::Error::from_raw_os_error(status as i32),
                ));
            }
        }
        Ok(())
    }

    fn open_trace(&mut self, trace_data: &TraceData) -> EvntraceNativeResult<EventTraceLogfile> {
        let mut log_file = EventTraceLogfile::create(trace_data, trace_callback_thunk);

        unsafe {
            self.session_handle = Etw::OpenTraceA(&mut *log_file);
            if self.session_handle == INVALID_TRACE_HANDLE {
                return Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()));
            }
        }

        Ok(log_file)
    }

    fn stop_trace(&self, trace_data: &TraceData) -> EvntraceNativeResult<()> {
        // FIXME: The session handle is no longer valid after this call.
        self.control_trace(
            trace_data,
            windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL_STOP,
        )?;
        Ok(())
    }

    fn close_trace(&mut self) -> EvntraceNativeResult<()> {
        if self.session_handle == INVALID_TRACE_HANDLE {
            return Err(EvntraceNativeError::InvalidHandle);
        }

        unsafe {
            let status = Etw::CloseTrace(self.session_handle);
            if status != 0 && status != ERROR_CTX_CLOSE_PENDING.0 {
                return Err(EvntraceNativeError::IoError(
                    std::io::Error::from_raw_os_error(status as i32),
                ));
            }
        }

        self.session_handle = INVALID_TRACE_HANDLE;
        Ok(())
    }

    fn control_trace(
        &self,
        trace_data: &TraceData,
        control_code: EvenTraceControl,
    ) -> EvntraceNativeResult<()> {
        unsafe {
            let status = Etw::ControlTraceA(
                0,
                PCSTR::from_raw(trace_data.name.as_ptr()),
                &*self.info.properties as *const _ as *mut _,
                control_code,
            );

            if status != 0 && status != ERROR_WMI_INSTANCE_NOT_FOUND.0 {
                return Err(EvntraceNativeError::IoError(
                    std::io::Error::from_raw_os_error(status as i32),
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn enable_provider(
        &self,
        guid: GUID,
        any: u64,
        all: u64,
        level: u8,
        parameters: EnableTraceParameters,
    ) -> EvntraceNativeResult<()> {
        match unsafe {
            Etw::EnableTraceEx2(
                self.registration_handle,
                &guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                level,
                any,
                all,
                0,
                &*parameters,
            )
        } {
            0 => Ok(()),
            e => Err(EvntraceNativeError::IoError(
                std::io::Error::from_raw_os_error(e as i32),
            )),
        }
    }
}

/// Queries the system for system-wide ETW information (that does not require an active session).
pub(crate) fn query_info(class: TraceInformation, buf: &mut [u8]) -> EvntraceNativeResult<()> {
    match unsafe {
        Etw::TraceQueryInformation(
            0,
            TRACE_QUERY_INFO_CLASS(class as i32),
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len() as u32,
            std::ptr::null_mut(),
        )
    } {
        0 => Ok(()),
        e => Err(EvntraceNativeError::IoError(
            std::io::Error::from_raw_os_error(e as i32),
        )),
    }
}
