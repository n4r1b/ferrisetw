//! Native API - Event Tracing evntrace header
//!
//! The `evntrace` module is an abstraction layer for the Windows evntrace library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `evntrace` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the crate level provide a safe API to interact
//! with the crate
use windows::core::{GUID, PCSTR};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Diagnostics::Etw;
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows::Win32::Foundation::ERROR_CTX_CLOSE_PENDING;
use windows::Win32::Foundation::ERROR_WMI_INSTANCE_NOT_FOUND;


use super::etw_types::*;
use crate::provider::Provider;
use crate::trace::{TraceData, TraceProperties, TraceTrait};
use crate::traits::*;
use std::sync::RwLock;

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
    let ctx: &mut TraceData = TraceData::unsafe_get_callback_ctx((*event_record).UserContext);
    ctx.on_event(*event_record);
}

#[derive(Debug, Clone)]
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

    pub(crate) fn start(&mut self) -> EvntraceNativeResult<()> {
        if self.session_handle == INVALID_TRACE_HANDLE {
            return Err(EvntraceNativeError::InvalidHandle);
        }
        self.process()
    }

    pub(crate) fn open<'a>(
        &mut self,
        trace_data: &'a Box<TraceData>,
    ) -> EvntraceNativeResult<EventTraceLogfile<'a>> {
        self.open_trace(trace_data)
    }

    pub(crate) fn stop(&mut self, trace_data: &TraceData) -> EvntraceNativeResult<()> {
        self.stop_trace(trace_data)?;
        self.close_trace()?;
        Ok(())
    }

    pub(crate) fn process(&mut self) -> EvntraceNativeResult<()> {
        if self.session_handle == INVALID_TRACE_HANDLE {
            return Err(EvntraceNativeError::InvalidHandle);
        }

        let clone_handle = self.session_handle;
        std::thread::spawn(move || {
            let mut now = FILETIME::default();
            unsafe {
                GetSystemTimeAsFileTime(&mut now);

                Etw::ProcessTrace(&[clone_handle], &now, std::ptr::null_mut());
                // if Etw::ProcessTrace(&[clone_handlee], &mut now, std::ptr::null_mut()) != 0 {
                //     return Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()));
                // }
            }
        });

        Ok(())
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
                return Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    fn open_trace<'a>(&mut self, trace_data: &'a Box<TraceData>) -> EvntraceNativeResult<EventTraceLogfile<'a>> {
        let mut log_file = EventTraceLogfile::create(trace_data, trace_callback_thunk);

        unsafe {
            self.session_handle = Etw::OpenTraceA(log_file.as_mut_ptr());
            if self.session_handle == INVALID_TRACE_HANDLE {
                return Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()));
            }
        }

        Ok(log_file)
    }

    fn stop_trace(&mut self, trace_data: &TraceData) -> EvntraceNativeResult<()> {
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
        &mut self,
        trace_data: &TraceData,
        control_code: EvenTraceControl,
    ) -> EvntraceNativeResult<()> {
        unsafe {
            let status = Etw::ControlTraceA(
                0,
                PCSTR::from_raw(trace_data.name.as_ptr()),
                &mut *self.info.properties,
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

    pub(crate) fn enable_trace(
        &self,
        guid: GUID,
        any: u64,
        all: u64,
        level: u8,
        parameters: EnableTraceParameters,
    ) -> EvntraceNativeResult<()> {
        unsafe {
            if Etw::EnableTraceEx2(
                self.registration_handle,
                &guid,
                1, // Fixme: EVENT_CONTROL_CODE_ENABLE_PROVIDER
                level,
                any,
                all,
                0,
                &*parameters,
            ) != 0
            {
                return Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}
