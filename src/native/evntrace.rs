//! Native API - Event Tracing evntrace header
//!
//! The `evntrace` module is an abstraction layer for the Windows evntrace library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `evntrace` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the crate level provide a safe API to interact
//! with the crate
use windows::core::GUID;
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

unsafe fn trace_callback_thunk(event_record: PEventRecord) {
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
        self.session_handle.clone()
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
        Ok(self.process()?)
    }

    pub(crate) fn open(
        &mut self,
        trace_data: &TraceData,
    ) -> EvntraceNativeResult<EventTraceLogfile> {
        Ok(self.open_trace(trace_data)?)
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

        let mut clone_handle = self.session_handle.clone();
        std::thread::spawn(move || {
            let mut now = WindowsProgramming::FILETIME::default();
            unsafe {
                WindowsProgramming::GetSystemTimeAsFileTime(&mut now);

                Etw::ProcessTrace(&mut clone_handle, 1, &mut now, std::ptr::null_mut());
                // if Etw::ProcessTrace(&mut clone_handle, 1, &mut now, std::ptr::null_mut()) != 0 {
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
                trace_data.name.clone(),
                &mut *self.info.properties,
            );

            if status == WIN32_ERROR::ERROR_ALREADY_EXISTS.0 {
                return Err(EvntraceNativeError::AlreadyExist);
            } else if status != 0 {
                return Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()));
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

    fn stop_trace(&mut self, trace_data: &TraceData) -> EvntraceNativeResult<()> {
        self.control_trace(
            trace_data,
            EvenTraceControl::from(ControlValues::ControlStop as u32),
        )?;
        Ok(())
    }

    fn close_trace(&mut self) -> EvntraceNativeResult<()> {
        if self.session_handle == INVALID_TRACE_HANDLE {
            return Err(EvntraceNativeError::InvalidHandle);
        }

        unsafe {
            let status = Etw::CloseTrace(self.session_handle);
            if status != 0 && status != WIN32_ERROR::ERROR_CTX_CLOSE_PENDING.0 {
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
                trace_data.name.clone(),
                &mut *self.info.properties,
                control_code,
            );

            if status != 0 && status != WIN32_ERROR::ERROR_WMI_INSTANCE_NOT_FOUND.0 {
                return Err(EvntraceNativeError::IoError(
                    std::io::Error::from_raw_os_error(status as i32),
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn enable_trace(
        &self,
        mut guid: GUID,
        any: u64,
        all: u64,
        level: u8,
        mut paramaters: EnableTraceParameters,
    ) -> EvntraceNativeResult<()> {
        unsafe {
            if Etw::EnableTraceEx2(
                self.registration_handle,
                &mut guid,
                1, // Fixme: EVENT_CONTROL_CODE_ENABLE_PROVIDER
                level,
                any,
                all,
                0,
                &mut *paramaters,
            ) != 0
            {
                return Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}
