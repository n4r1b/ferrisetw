//! Native API - Event Tracing evntrace header
//!
//! The `evntrace` module is an abstraction layer for the Windows evntrace library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `evntrace` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the crate level provide a safe API to interact
//! with the crate
use std::panic::AssertUnwindSafe;

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Diagnostics::Etw;
use windows::Win32::System::Diagnostics::Etw::TRACE_QUERY_INFO_CLASS;
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows::Win32::Foundation::ERROR_CTX_CLOSE_PENDING;
use windows::Win32::Foundation::ERROR_WMI_INSTANCE_NOT_FOUND;


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

extern "system" fn trace_callback_thunk(p_record: *mut Etw::EVENT_RECORD) {
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        let record_from_ptr = unsafe {
            // Safety: lifetime is valid at least until the end of the callback. A correct lifetime will be attached when we pass the reference to the child function
            EventRecord::from_ptr(p_record)
        };

        if let Some(event_record) = record_from_ptr {
            let p_user_context = event_record.user_context().cast::<TraceData>();
            let user_context = unsafe {
                // Safety:
                //  * the API of this create guarantees this points to a `TraceData` already allocated and created
                //  * TODO (#45): the API of this crate does not yet guarantee this `TraceData` is not mutated during the trace (e.g. modifying the list of providers) (although this may not be critical memory-safety-wise)
                //  * TODO (#45): the API of this create does not yet guarantee this `TraceData` has not been dropped
                p_user_context.as_ref()
            };
            if let Some(user_context) = user_context {
                user_context.on_event(event_record);
            }
        }
    })) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("UNIMPLEMENTED PANIC: {e:?}");
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NativeEtw {
    info: EventTraceProperties,
    session_handle: TraceHandle,
    registration_handle: TraceHandle,
}

impl NativeEtw {
    pub(crate) fn new<T>(name: &str, properties: &TraceProperties, providers: &[Provider]) -> Self
    where
        T: TraceTrait,
    {
        NativeEtw {
            info: EventTraceProperties::new::<T>(name, properties, providers),
            session_handle: INVALID_TRACE_HANDLE,
            registration_handle: INVALID_TRACE_HANDLE,
        }
    }

    pub(crate) fn session_handle(&self) -> TraceHandle {
        self.session_handle
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
        if let Err(err) = self.start_trace() {
            if matches!(err, EvntraceNativeError::AlreadyExist) {
                // TODO: Check need admin errors
                self.stop_trace(trace_data)?;
                self.start_trace()?;
            } else {
                return Err(err);
            }
        }
        Ok(())
    }

    fn start_trace(&mut self) -> EvntraceNativeResult<()> {
        let status = unsafe {
            // Safety:
            //  * first argument points to a valid and allocated address (this is an output and will be modified)
            //  * second argument is a valid, null terminated widestring (note that it will be copied to the EventTraceProperties...from where it already comes. This will probably be overwritten by Windows, but heck.)
            //  * third argument is a valid, allocated EVENT_TRACE_PROPERTIES (and will be mutated)
            //  * Note: the string (that will be overwritten to itself) ends with a null widechar before the end of its buffer (see EventTraceProperties::new())
            Etw::StartTraceW(
                &mut self.registration_handle,
                PCWSTR::from_raw(self.info.trace_name_array().as_ptr()),
                self.info.as_mut_ptr(),
            )
        };

        if status == ERROR_ALREADY_EXISTS.0 {
            return Err(EvntraceNativeError::AlreadyExist);
        } else if status != 0 {
            return Err(EvntraceNativeError::IoError(
                std::io::Error::from_raw_os_error(status as i32),
            ));
        } else if self.registration_handle == 0 {
            // Because Microsoft says that
            // > The session handle is 0 if the handle is not valid.
            // (https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew)
            return Err(EvntraceNativeError::InvalidHandle);
        }
        Ok(())
    }

    fn open_trace<'a>(&mut self, trace_data: &'a Box<TraceData>) -> EvntraceNativeResult<EventTraceLogfile<'a>> {
        let mut log_file = EventTraceLogfile::create(trace_data, trace_callback_thunk);

        self.session_handle = unsafe {
            // This function modifies the data pointed to by log_file.
            // This is fine because there is currently no other ref `self` (the current function takes a `&mut self`, and `self` is not used anywhere else in the current function)
            //
            // > On success, OpenTrace will update the structure with information from the opened file or session.
            // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracea
            Etw::OpenTraceW(log_file.as_mut_ptr())
        };

        if self.session_handle == INVALID_TRACE_HANDLE {
            return Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()));
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

        let status = unsafe {
            // Safety: the handle is valid
            Etw::CloseTrace(self.session_handle)
        };
        if status != 0 && status != ERROR_CTX_CLOSE_PENDING.0 {
            return Err(EvntraceNativeError::IoError(
                std::io::Error::from_raw_os_error(status as i32),
            ));
        }

        self.session_handle = INVALID_TRACE_HANDLE;
        Ok(())
    }

    fn control_trace(
        &mut self,
        trace_data: &TraceData,
        control_code: EvenTraceControl,
    ) -> EvntraceNativeResult<()> {
        let status = unsafe {
            // Safety:
            //  * depending on the control code, the `Properties` can be mutated
            Etw::ControlTraceA(
                0,
                PCSTR::from_raw(trace_data.name.as_ptr()),
                self.info.as_mut_ptr(),
                control_code,
            )
        };

        if status != 0 && status != ERROR_WMI_INSTANCE_NOT_FOUND.0 {
            return Err(EvntraceNativeError::IoError(
                std::io::Error::from_raw_os_error(status as i32),
            ));
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
        match unsafe {
            Etw::EnableTraceEx2(
                self.registration_handle,
                &guid,
                1, // Fixme: EVENT_CONTROL_CODE_ENABLE_PROVIDER
                level,
                any,
                all,
                0,
                parameters.as_ptr(),
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
