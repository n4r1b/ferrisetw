//! Safe wrappers for the native ETW API
//!
//! This module makes sure the calls are safe memory-wise, but does not attempt to ensure they are called in the right order.<br/>
//! Thus, you should prefer using `UserTrace`s, `KernelTrace`s and `TraceBuilder`s, that will ensure these API are correctly used.
use std::panic::AssertUnwindSafe;

use widestring::{U16CString, U16CStr};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::EVENT_CONTROL_CODE_ENABLE_PROVIDER;
use windows::core::GUID;
use windows::core::PCWSTR;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Diagnostics::Etw;
use windows::Win32::System::Diagnostics::Etw::TRACE_QUERY_INFO_CLASS;
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows::Win32::Foundation::ERROR_CTX_CLOSE_PENDING;
use windows::Win32::Foundation::ERROR_WMI_INSTANCE_NOT_FOUND;


use super::etw_types::*;
use crate::provider::Provider;
use crate::provider::event_filter::EventFilterDescriptor;
use crate::trace::{CallbackData, TraceProperties, TraceTrait};

pub type TraceHandle = u64;
pub type ControlHandle = u64;

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

pub(crate) type EvntraceNativeResult<T> = Result<T, EvntraceNativeError>;

/// This will be called by the ETW framework whenever an ETW event is available
extern "system" fn trace_callback_thunk(p_record: *mut Etw::EVENT_RECORD) {
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        let record_from_ptr = unsafe {
            // Safety: lifetime is valid at least until the end of the callback. A correct lifetime will be attached when we pass the reference to the child function
            EventRecord::from_ptr(p_record)
        };

        if let Some(event_record) = record_from_ptr {
            let p_user_context = event_record.user_context().cast::<CallbackData>();
            let user_context = unsafe {
                // Safety:
                //  * the API of this create guarantees this points to a `CallbackData` already allocated and created
                //  * TODO (#45): the API of this create does not yet guarantee this `CallbackData` has not been dropped
                //  * the API of this crate guarantees this `CallbackData` is not mutated from another thread during the trace:
                //      * we're the only one to change CallbackData::events_handled (and that's an atomic, so it's fine)
                //      * the list of Providers is a constant (may change in the future with #54)
                //      * the schema_locator only has interior mutability
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

fn filter_invalid_trace_handles(h: TraceHandle) -> Option<TraceHandle> {
    // See https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew#return-value
    // We're conservative and we always filter out u32::MAX, although it could be valid on 64-bit setups.
    // But it turns out runtime detection of the current OS bitness is not that easy. Plus, it is not clear whether this depends on how the architecture the binary is compiled for, or the actual OS architecture.
    if h == u64::MAX || h == u32::MAX as u64 {
        None
    } else {
        Some(h)
    }
}

fn filter_invalid_control_handle(h: ControlHandle) -> Option<ControlHandle> {
    // The control handle is 0 if the handle is not valid.
    // (https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew)
    if h == 0 {
        None
    } else {
        Some(h)
    }
}

/// Create a new session.
///
/// This builds an `EventTraceProperties`, calls `StartTraceW` and returns the built `EventTraceProperties` as well as the trace ControlHandle
pub fn start_trace<T>(trace_name: &U16CStr, trace_properties: &TraceProperties, enable_flags: Etw::EVENT_TRACE_FLAG) -> EvntraceNativeResult<(EventTraceProperties, ControlHandle)>
where
    T: TraceTrait
{
    let mut properties = EventTraceProperties::new::<T>(trace_name, trace_properties, enable_flags);

    let mut control_handle = ControlHandle::default();
    let status = unsafe {
        // Safety:
        //  * first argument points to a valid and allocated address (this is an output and will be modified)
        //  * second argument is a valid, null terminated widestring (note that it will be copied to the EventTraceProperties...from where it already comes. This will probably be overwritten by Windows, but heck.)
        //  * third argument is a valid, allocated EVENT_TRACE_PROPERTIES (and will be mutated)
        //  * Note: the string (that will be overwritten to itself) ends with a null widechar before the end of its buffer (see EventTraceProperties::new())
        Etw::StartTraceW(
            &mut control_handle,
            PCWSTR::from_raw(properties.trace_name_array().as_ptr()),
            properties.as_mut_ptr(),
        )
    };

    if status == ERROR_ALREADY_EXISTS.0 {
        return Err(EvntraceNativeError::AlreadyExist);
    } else if status != 0 {
        return Err(EvntraceNativeError::IoError(
            std::io::Error::from_raw_os_error(status as i32),
        ));
    }

    match filter_invalid_control_handle(control_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => Ok((properties, handle)),
    }
}


/// Subscribe to a started trace
///
/// Microsoft calls this "opening" the trace (and this calls `OpenTraceW`)
pub fn open_trace(trace_name: U16CString, callback_data: &Box<CallbackData>) -> EvntraceNativeResult<TraceHandle> {
    let mut log_file = EventTraceLogfile::create(&callback_data, trace_name, trace_callback_thunk);

    let trace_handle = unsafe {
        // This function modifies the data pointed to by log_file.
        // This is fine because there is currently no other ref `self` (the current function takes a `&mut self`, and `self` is not used anywhere else in the current function)
        //
        // > On success, OpenTrace will update the structure with information from the opened file or session.
        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracea
        Etw::OpenTraceW(log_file.as_mut_ptr())
    };

    if filter_invalid_trace_handles(trace_handle).is_none() {
        Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()))
    } else {
        Ok(trace_handle)
    }
}

/// Attach a provider to a trace
pub fn enable_provider(control_handle: ControlHandle, provider: &Provider) -> EvntraceNativeResult<()> {
    match filter_invalid_control_handle(control_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            let owned_event_filter_descriptors: Vec<EventFilterDescriptor> = provider.filters()
                .iter()
                .filter_map(|filter| filter.to_event_filter_descriptor().ok()) // Silently ignoring invalid filters (basically, empty ones)
                .collect();

            let parameters =
                EnableTraceParameters::create(provider.guid(), provider.trace_flags(), &owned_event_filter_descriptors);

            let res = unsafe {
                Etw::EnableTraceEx2(
                    handle,
                    &provider.guid() as *const GUID,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    provider.level(),
                    provider.any(),
                    provider.all(),
                    0,
                    parameters.as_ptr(),
                )
            };

            if res == ERROR_SUCCESS.0 {
                Ok(())
            } else {
                Err(
                    EvntraceNativeError::IoError(
                        std::io::Error::from_raw_os_error(res as i32)
                    )
                )
            }
        }
    }
}

/// Start processing a trace (this call is blocking until the trace is stopped)
///
/// You probably want to spawn a thread that will block on this call.
pub fn process_trace(trace_handle: TraceHandle) -> EvntraceNativeResult<()> {
    if filter_invalid_trace_handles(trace_handle).is_none() {
        return Err(EvntraceNativeError::InvalidHandle);
    } else {
        let mut now = FILETIME::default();
        let result = unsafe {
            GetSystemTimeAsFileTime(&mut now);
            Etw::ProcessTrace(&[trace_handle], &mut now, std::ptr::null_mut())
        };

        if result == ERROR_SUCCESS.0 {
            Ok(())
        } else {
            Err(EvntraceNativeError::IoError(std::io::Error::from_raw_os_error(result as i32)))
        }
    }
}

/// Call `ControlTraceW` on the trace
///
/// # Notes
///
/// In case you want to close the trace, you probably want to drop the instance rather than calling `control(EVENT_TRACE_CONTROL_STOP)` yourself,
/// because closing the trace makes the trace handle invalid.
/// A closed trace could theoretically(?) be re-used, but the trace handle should be re-created, so `open` should be called again.
pub fn control_trace(
    properties: &mut EventTraceProperties,
    control_handle: ControlHandle,
    control_code: Etw::EVENT_TRACE_CONTROL,
) -> EvntraceNativeResult<()> {
    match filter_invalid_control_handle(control_handle) {
        None => return Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            let status = unsafe {
                // Safety:
                //  * the trace handle is valid (by construction)
                //  * depending on the control code, the `Properties` can be mutated. This is fine because properties is declared as `&mut` in this function, which means no other Rust function has a reference to it, and the mutation can only happen in the call to `ControlTraceW`, which returns immediately.
                Etw::ControlTraceW(
                    handle,
                    PCWSTR::null(),
                    properties.as_mut_ptr(),
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
    }
}

/// Close the trace
///
/// It is suggested to stop the trace immediately after `close`ing it (that's what it done in the `impl Drop`), because I'm not sure how sensible it is to call other methods (apart from `stop`) afterwards
///
/// In case ETW reports there are still events in the queue that are still to trigger callbacks, this returns Ok(true).<br/>
/// If no further event callback will be invoked, this returns Ok(false)<br/>
/// On error, this returns an `Err`
pub fn close_trace(trace_handle: TraceHandle) -> EvntraceNativeResult<bool> {
    match filter_invalid_trace_handles(trace_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            let status = unsafe {
                Etw::CloseTrace(handle)
            };

            match WIN32_ERROR(status) {
                ERROR_SUCCESS => Ok(false),
                ERROR_CTX_CLOSE_PENDING => Ok(true),
                status @ _ => Err(EvntraceNativeError::IoError(
                    std::io::Error::from_raw_os_error(status.0 as i32),
                ))
            }
        },
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
