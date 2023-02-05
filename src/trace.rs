//! ETW Tracing/Session abstraction
//!
//! Provides both a Kernel and User trace that allows to start an ETW session
use std::ffi::OsString;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use self::private::PrivateTraceTrait;

use crate::native::etw_types::EventTraceProperties;
use crate::native::version_helper;
use crate::native::evntrace::{ControlHandle, TraceHandle, start_trace, open_trace, process_trace, enable_provider, control_trace, control_trace_by_name, close_trace};
use crate::provider::Provider;
use crate::utils;
use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw;
use widestring::U16CString;

pub use crate::native::etw_types::LoggingMode;

pub(crate) mod callback_data;
use callback_data::CallbackData;

const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";
const SYSTEM_TRACE_CONTROL_GUID: &str = "9e814aad-3204-11d2-9a82-006008a86939";
const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x02000000;

/// Trace module errors
#[derive(Debug)]
pub enum TraceError {
    InvalidTraceName,
    /// Wrapper over an internal [EvntraceNativeError](crate::native::EvntraceNativeError)
    EtwNativeError(crate::native::EvntraceNativeError),
}

impl From<crate::native::EvntraceNativeError> for TraceError {
    fn from(err: crate::native::EvntraceNativeError) -> Self {
        TraceError::EtwNativeError(err)
    }
}

type TraceResult<T> = Result<T, TraceError>;

/// Trace Properties struct
///
/// These are some configuration settings that will be included in an [`EVENT_TRACE_PROPERTIES`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
///
/// [More info](https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings#configuring-the-etw-session)
#[derive(Debug, Copy, Clone)]
pub struct TraceProperties {
    /// Represents the ETW Session in KB
    pub buffer_size: u32,
    /// Represents the ETW Session minimum number of buffers to use
    pub min_buffer: u32,
    /// Represents the ETW Session maximum number of buffers in the buffer pool
    pub max_buffer: u32,
    /// Represents the ETW Session flush interval.
    ///
    /// This duration will be rounded to the closest second (and 0 will be translated as 1 second)
    pub flush_timer: Duration,
    /// Represents the ETW Session [Logging Mode](https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
    pub log_file_mode: LoggingMode,
}

impl Default for TraceProperties {
    fn default() -> Self {
        // Sane defaults, inspired by https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
        TraceProperties {
            buffer_size: 32,
            min_buffer: 0,
            max_buffer: 0,
            flush_timer: Duration::from_secs(1),
            log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
        }
    }
}

/// Trait for common methods to user and kernel traces
pub trait TraceTrait: private::PrivateTraceTrait + Sized {
    // This differs between UserTrace and KernelTrace
    fn trace_guid() -> GUID;

    // This must be implemented for every trace, as this getter is needed by other methods from this trait
    fn trace_handle(&self) -> TraceHandle;

    // These utilities should be implemented for every trace
    fn trace_name(&self) -> OsString;
    fn events_handled(&self) -> usize;

    // The following are default implementations, that work on both user and kernel traces

    /// This is blocking and starts triggerring the callbacks.
    ///
    /// Because this call is blocking, you probably want to call this from a background thread.<br/>
    /// See [`TraceBuilder::start`] for alternative and more convenient ways to start a trace.
    fn process(&mut self) -> TraceResult<()> {
        process_trace(self.trace_handle())
            .map_err(|e| e.into())
    }

    /// Process a trace given its handle.
    ///
    /// See [`TraceBuilder::start`] for alternative and more convenient ways to start a trace.
    fn process_from_handle(handle: TraceHandle) -> TraceResult<()> {
        process_trace(handle)
            .map_err(|e| e.into())
    }

    /// Stops the trace
    ///
    /// This consumes the trace, that can no longer be used afterwards.
    /// The same result is achieved by dropping `Self`
    fn stop(mut self) -> TraceResult<()> {
        self.non_consuming_stop()
    }
}

impl TraceTrait for UserTrace {
    fn trace_handle(&self) -> TraceHandle {
        self.trace_handle
    }

    fn trace_name(&self) -> OsString {
        self.properties.name()
    }

    fn events_handled(&self) -> usize {
        self.callback_data.events_handled()
    }

    fn trace_guid() -> GUID {
        GUID::new().unwrap_or(GUID::zeroed())
    }
}

// TODO: Implement enable_provider function for providers that require call to TraceSetInformation with extended PERFINFO_GROUPMASK
impl TraceTrait for KernelTrace {
    fn trace_handle(&self) -> TraceHandle {
        self.trace_handle
    }

    fn trace_name(&self) -> OsString {
        self.properties.name()
    }

    fn events_handled(&self) -> usize {
        self.callback_data.events_handled()
    }

    fn trace_guid() -> GUID {
        if version_helper::is_win8_or_greater() {
            GUID::new().unwrap_or(GUID::zeroed())
        } else {
            GUID::from(SYSTEM_TRACE_CONTROL_GUID)
        }
    }
}




/// A trace session to collect events from user-mode applications
///
/// To stop the session, you can drop this instance
#[derive(Debug)]
#[allow(clippy::redundant_allocation)] // see https://github.com/n4r1b/ferrisetw/issues/72
pub struct UserTrace {
    properties: EventTraceProperties,
    control_handle: ControlHandle,
    trace_handle: TraceHandle,
    // CallbackData is
    // * `Arc`ed, so that dropping a Trace while a callback is still running is not an issue
    // * `Boxed`, so that the `UserTrace` can be moved around the stack (e.g. returned by a function) but the pointers to the `CallbackData` given to Windows ETW API stay valid
    callback_data: Box<Arc<CallbackData>>,
}

/// A trace session to collect events from kernel-mode drivers
///
/// To stop the session, you can drop this instance
#[derive(Debug)]
#[allow(clippy::redundant_allocation)] // see https://github.com/n4r1b/ferrisetw/issues/72
pub struct KernelTrace {
    properties: EventTraceProperties,
    control_handle: ControlHandle,
    trace_handle: TraceHandle,
    // CallbackData is
    // * `Arc`ed, so that dropping a Trace while a callback is still running is not an issue
    // * `Boxed`, so that the `UserTrace` can be moved around the stack (e.g. returned by a function) but the pointers to the `CallbackData` given to Windows ETW API stay valid
    callback_data: Box<Arc<CallbackData>>,
}

/// Provides a way to crate Trace objects.
///
/// These builders are created using [`UserTrace::new`] or [`KernelTrace::new`]
pub struct TraceBuilder<T: TraceTrait> {
    name: String,
    properties: TraceProperties,
    callback_data: CallbackData,
    trace_kind: PhantomData<T>,
}

impl UserTrace {
    /// Create a UserTrace builder
    pub fn new() -> TraceBuilder<UserTrace> {
        let name = format!("n4r1b-trace-{}", utils::rand_string());
        TraceBuilder {
            name,
            callback_data: CallbackData::new(),
            properties: TraceProperties::default(),
            trace_kind: PhantomData,
        }
    }

    /// Stops the trace
    ///
    /// This consumes the trace, that can no longer be used afterwards.
    /// The same result is achieved by dropping `Self`
    pub fn stop(mut self) -> TraceResult<()> {
        self.non_consuming_stop()
    }
}

impl KernelTrace {
    /// Create a KernelTrace builder
    pub fn new() -> TraceBuilder<KernelTrace> {
        let builder = TraceBuilder {
            name: String::new(),
            callback_data: CallbackData::new(),
            properties: TraceProperties::default(),
            trace_kind: PhantomData,
        };
        // Not all names are valid. Let's use the setter to check them for us
        builder.named(format!("n4r1b-trace-{}", utils::rand_string()))
    }

    /// Stops the trace
    ///
    /// This consumes the trace, that can no longer be used afterwards.
    /// The same result is achieved by dropping `Self`
    pub fn stop(mut self) -> TraceResult<()> {
        self.non_consuming_stop()
    }
}

mod private {
    //! The only reason for this private module is to have a "private" trait in an otherwise publicly exported type (`TraceBuilder`)
    //!
    //! See <https://github.com/rust-lang/rust/issues/34537>
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    pub enum TraceKind {
        User,
        Kernel,
    }

    pub trait PrivateTraceTrait {
        const TRACE_KIND: TraceKind;
        #[allow(clippy::redundant_allocation)] // Being Boxed is really important, let's keep the Box<...> in the function signature to make the intent clearer (see https://github.com/n4r1b/ferrisetw/issues/72)
        fn build(properties: EventTraceProperties, control_handle: ControlHandle, trace_handle: TraceHandle, callback_data: Box<Arc<CallbackData>>) -> Self;
        fn augmented_file_mode() -> u32;
        fn enable_flags(_providers: &[Provider]) -> u32;
        // This function aims at de-deduplicating code called by `impl Drop` and `Trace::stop`.
        // It is basically [`Self::stop`], without consuming self (because the `impl Drop` only has a `&mut self`, not a `self`)
        fn non_consuming_stop(&mut self) -> TraceResult<()>;
    }
}

impl private::PrivateTraceTrait for UserTrace {
    const TRACE_KIND: private::TraceKind = private::TraceKind::User;

    fn build(properties: EventTraceProperties, control_handle: ControlHandle, trace_handle: TraceHandle, callback_data: Box<Arc<CallbackData>>) -> Self {
        UserTrace {
            properties,
            control_handle,
            trace_handle,
            callback_data,
        }
    }

    fn augmented_file_mode() -> u32 {
        0
    }
    fn enable_flags(_providers: &[Provider]) -> u32 {
        0
    }

    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        close_trace(self.trace_handle, &self.callback_data)?;
        control_trace(&mut self.properties, self.control_handle, Etw::EVENT_TRACE_CONTROL_STOP)?;
        Ok(())
    }
}

impl private::PrivateTraceTrait for KernelTrace {
    const TRACE_KIND: private::TraceKind = private::TraceKind::Kernel;

    fn build(properties: EventTraceProperties, control_handle: ControlHandle, trace_handle: TraceHandle, callback_data: Box<Arc<CallbackData>>) -> Self {
        KernelTrace {
            properties,
            control_handle,
            trace_handle,
            callback_data,
        }
    }

    fn augmented_file_mode() -> u32 {
        if version_helper::is_win8_or_greater() {
            EVENT_TRACE_SYSTEM_LOGGER_MODE
        } else {
            0
        }
    }

    fn enable_flags(providers: &[Provider]) -> u32 {
        providers.iter().fold(0, |acc, x| acc | x.kernel_flags())
    }

    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        close_trace(self.trace_handle, &self.callback_data)?;
        control_trace(&mut self.properties, self.control_handle, Etw::EVENT_TRACE_CONTROL_STOP)?;
        Ok(())
    }
}

impl<T: TraceTrait + PrivateTraceTrait> TraceBuilder<T> {
    /// Define the trace name
    ///
    /// For kernel traces on Windows Versions older than Win8, this method won't change the trace name. In those versions the trace name will be set to "NT Kernel Logger"
    pub fn named(mut self, name: String) -> Self {
        if T::TRACE_KIND == private::TraceKind::Kernel && version_helper::is_win8_or_greater() == false {
            self.name = String::from(KERNEL_LOGGER_NAME);
        } else {
            self.name = name;
        };

        self
    }

    /// Define several low-level properties of the trace at once.
    ///
    /// These are part of [`EVENT_TRACE_PROPERTIES`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
    pub fn set_trace_properties(mut self, props: TraceProperties) -> Self {
        self.properties = props;
        self
    }

    /// Enable a Provider for this trace
    ///
    /// This will invoke the provider's callback whenever an event is available
    ///
    /// # Note
    /// Windows API seems to support removing providers, or changing its properties when the session is processing events (see <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks>)    /// Currently, this crate only supports defining Providers and their settings when building the trace, because it is easier to ensure memory-safety this way.
    /// It probably would be possible to support changing Providers when the trace is processing, but this is left as a TODO (see <https://github.com/n4r1b/ferrisetw/issues/54>)
    pub fn enable(mut self, provider: Provider) -> Self {
        self.callback_data.add_provider(provider);
        self
    }

    /// Build the `UserTrace` and start the trace session
    ///
    /// Internally, this calls the `StartTraceW`, `EnableTraceEx2` and `OpenTraceW`.
    ///
    /// To start receiving events, you'll still have to call either:
    /// * Worst option: `process()` on the returned `T`. This will block the current thread until the trace is stopped.<br/>
    ///   This means you'll probably want to call this on a spawned thread, where the `T` must be moved to. This will prevent you from re-using it from the another thread.<br/>
    ///   This means you will not be able to explicitly stop the trace, because you'll no longer have a `T` to drop or to call `stop` on. The trace will stop when the program exits, or when the ETW API hits an error.<br/>
    /// * Most powerful option: `T::process_from_handle()` with the returned [`TraceHandle`].<br/>
    ///   This will block, so this also has to be run in a spawned thread. But, as this does not "consume" the `T`, you'll be able to call `stop` on it (or to drop it) to explicitly close the trace. Stopping a trace will make the `process` function return.
    /// * Easiest option: [`TraceBuilder::start_and_process()`].<br/>
    ///   This convenience function spawns a thread for you, call [`TraceBuilder::start`] on the trace, and returns immediately.<br/>
    ///   This option returns a `T`, so you can explicitly stop the trace, but there is no way to get the status code of the ProcessTrace API.
    pub fn start(self) -> TraceResult<(T, TraceHandle)> {
        let trace_wide_name = U16CString::from_str_truncate(self.name);
        let mut trace_wide_vec = trace_wide_name.into_vec();
        trace_wide_vec.truncate(crate::native::etw_types::TRACE_NAME_MAX_CHARS);
        let trace_wide_name = U16CString::from_vec_truncate(trace_wide_vec);

        let callback_data = Box::new(Arc::new(self.callback_data));
        let flags = callback_data.provider_flags::<T>();
        let (full_properties, control_handle) = start_trace::<T>(
            &trace_wide_name,
            &self.properties,
            flags)?;

        // TODO: For kernel traces, implement enable_provider function for providers that require call to TraceSetInformation with extended PERFINFO_GROUPMASK

        if T::TRACE_KIND == private::TraceKind::User {
            for prov in callback_data.providers() {
                enable_provider(control_handle, prov)?;
            }
        }

        let trace_handle = open_trace(trace_wide_name, &callback_data)?;

        Ok((T::build(
                full_properties,
                control_handle,
                trace_handle,
                callback_data,
            ),
            trace_handle)
        )
    }

    /// Convenience method that calls [`TraceBuilder::start`] then `process`
    ///
    /// # Notes
    /// * See the documentation of [`TraceBuilder::start`] for more info
    /// * `process` is called on a spawned thread, and thus this method does not give any way to retrieve the error of `process` (if any)
    pub fn start_and_process(self) -> TraceResult<T> {
        let (trace, trace_handle) = self.start()?;

        std::thread::spawn(move || UserTrace::process_from_handle(trace_handle));

        Ok(trace)
    }
}

impl Drop for UserTrace {
    fn drop(&mut self) {
        let _ignored_error_in_drop = self.non_consuming_stop();
    }
}

impl Drop for KernelTrace {
    fn drop(&mut self) {
        let _ignored_error_in_drop = self.non_consuming_stop();
    }
}


/// Stop a trace given its name.
///
/// This function is intended to close a trace you did not start yourself.
/// Otherwise, you should prefer [`UserTrace::stop()`] or [`KernelTrace::stop()`]
pub fn stop_trace_by_name(trace_name: &str) -> TraceResult<()> {
    let trace_properties = TraceProperties::default();
    let flags = Etw::EVENT_TRACE_FLAG::default();
    let wide_name = U16CString::from_str(trace_name)
        .map_err(|_| TraceError::InvalidTraceName)?;

    let mut properties = EventTraceProperties::new::<UserTrace>( // for EVENT_TRACE_CONTROL_STOP, we don't really care about most of the contents of the EventTraceProperties, so using new::<UserTrace>() is fine, even when stopping a kernel trace
        &wide_name,
        &trace_properties,
        flags);

    control_trace_by_name(
        &mut properties,
        &wide_name,
        Etw::EVENT_TRACE_CONTROL_STOP,
    )?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_enable_multiple_providers() {
        let prov = Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716").build();
        let prov1 = Provider::by_guid("A0C1853B-5C40-4B15-8766-3CF1C58F985A").build();

        let trace = UserTrace::new().enable(prov).enable(prov1);

        assert_eq!(trace.callback_data.providers().len(), 2);
    }
}
