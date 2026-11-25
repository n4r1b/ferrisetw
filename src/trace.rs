//! ETW Tracing/Session abstraction
//!
//! Provides both a Kernel and User trace that allows to start an ETW session
use std::ffi::OsString;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use widestring::U16CString;
use windows::core::GUID;
use windows::Win32::Foundation::ERROR_WMI_INSTANCE_NOT_FOUND;
use windows::Win32::System::Diagnostics::Etw;

use self::private::{PrivateRealTimeTraceTrait, PrivateTraceTrait};

use crate::native::etw_types::{EventTraceProperties, SubscriptionSource, PERFINFO_GROUPMASK};
use crate::native::evntrace::{
    close_trace, control_trace, control_trace_by_name, enable_provider, open_trace, process_trace,
    set_kernel_group_mask, start_trace, ControlHandle, TraceHandle,
};
use crate::native::{version_helper, EvntraceNativeError};
use crate::provider::Provider;
use crate::utils;
use crate::EventRecord;
use crate::SchemaLocator;

pub use crate::native::etw_types::DumpFileLoggingMode;
pub use crate::native::etw_types::LoggingMode;

pub(crate) mod callback_data;
use callback_data::CallbackData;
use callback_data::CallbackDataFromFile;
use callback_data::RealTimeCallbackData;
pub(crate) use private::TraceKind;

const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";
const SYSTEM_TRACE_CONTROL_GUID: GUID = GUID::from_u128(0x9e814aad_3204_11d2_9a82_006008a86939);
const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x02000000;

#[cfg(test)]
thread_local! {
    static STARTUP_FAILPOINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static STARTUP_FAILPOINT_REACHED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn injected_startup_error(stage: u8) -> Result<(), EvntraceNativeError> {
    if STARTUP_FAILPOINT.with(|point| point.get() == stage || (point.get() == 3 && stage == 1)) {
        STARTUP_FAILPOINT_REACHED.with(|reached| reached.set(true));
        Err(EvntraceNativeError::IoError(
            std::io::Error::from_raw_os_error(12345),
        ))
    } else {
        Ok(())
    }
}

/// Trace module errors
#[derive(Debug)]
pub enum TraceError {
    InvalidTraceName,
    /// Wrapper over an internal [EvntraceNativeError]
    EtwNativeError(crate::native::EvntraceNativeError),
    /// Startup failed and the newly created session could not be stopped.
    StartupRollback {
        /// The error that caused startup to fail.
        startup: crate::native::EvntraceNativeError,
        /// The error returned when stopping the session.
        rollback: crate::native::EvntraceNativeError,
    },
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
            log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE
                | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
        }
    }
}

/// Trait for common methods to user, kernel and file traces
pub trait TraceTrait: private::PrivateTraceTrait + Sized {
    // This must be implemented for every trace, as this getter is needed by other methods from this trait
    fn trace_handle(&self) -> TraceHandle;

    // This utility function should be implemented for every trace
    fn events_handled(&self) -> usize;

    fn close(self) -> TraceResult<bool>;

    // The following are default implementations, that work on both user and kernel traces

    /// This is blocking and starts triggerring the callbacks.
    ///
    /// Because this call is blocking, you probably want to call this from a background thread.<br/>
    /// See [`TraceBuilder::start`] for alternative and more convenient ways to start a trace.
    fn process(&mut self) -> TraceResult<()> {
        process_trace(self.trace_handle()).map_err(|e| e.into())
    }

    /// Process a trace given its handle.
    ///
    /// See [`TraceBuilder::start`] for alternative and more convenient ways to start a trace.
    fn process_from_handle(handle: TraceHandle) -> TraceResult<()> {
        process_trace(handle).map_err(|e| e.into())
    }

    /// Stops the trace
    ///
    /// This consumes the trace, that can no longer be used afterwards.
    /// The same result is achieved by dropping `Self`
    fn stop(mut self) -> TraceResult<()> {
        self.non_consuming_stop()
    }
}

/// Trait for common methods to real-time traces
pub trait RealTimeTraceTrait: TraceTrait + private::PrivateRealTimeTraceTrait {
    // This differs between UserTrace and KernelTrace
    fn trace_guid() -> GUID;

    // This utility function should be implemented for every trace
    fn trace_name(&self) -> OsString;
}

impl TraceTrait for UserTrace {
    fn trace_handle(&self) -> TraceHandle {
        self.trace_handle
    }

    fn events_handled(&self) -> usize {
        self.callback_data.events_handled()
    }

    fn close(self) -> TraceResult<bool> {
        close_trace(self.trace_handle, &self.callback_data).map_err(TraceError::EtwNativeError)
    }
}

impl RealTimeTraceTrait for UserTrace {
    fn trace_guid() -> GUID {
        GUID::new().unwrap_or(GUID::zeroed())
    }

    fn trace_name(&self) -> OsString {
        self.properties.name()
    }
}

impl TraceTrait for KernelTrace {
    fn trace_handle(&self) -> TraceHandle {
        self.trace_handle
    }

    fn events_handled(&self) -> usize {
        self.callback_data.events_handled()
    }

    fn close(self) -> TraceResult<bool> {
        close_trace(self.trace_handle, &self.callback_data).map_err(TraceError::EtwNativeError)
    }
}

impl RealTimeTraceTrait for KernelTrace {
    fn trace_guid() -> GUID {
        if version_helper::is_win8_or_greater() {
            GUID::new().unwrap_or(GUID::zeroed())
        } else {
            SYSTEM_TRACE_CONTROL_GUID
        }
    }

    fn trace_name(&self) -> OsString {
        self.properties.name()
    }
}

impl TraceTrait for FileTrace {
    fn trace_handle(&self) -> TraceHandle {
        self.trace_handle
    }

    fn events_handled(&self) -> usize {
        self.callback_data.events_handled()
    }

    fn close(self) -> TraceResult<bool> {
        close_trace(self.trace_handle, &self.callback_data).map_err(TraceError::EtwNativeError)
    }
}

/// A real-time trace session to collect events from user-mode applications
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

/// A real-time trace session to collect events from kernel-mode drivers
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

/// A trace session that reads events from an ETL file
///
/// To stop the session, you can drop this instance
#[derive(Debug)]
#[allow(clippy::redundant_allocation)] // see https://github.com/n4r1b/ferrisetw/issues/72
pub struct FileTrace {
    trace_handle: TraceHandle,
    // CallbackData is
    // * `Arc`ed, so that dropping a Trace while a callback is still running is not an issue
    // * `Boxed`, so that the `UserTrace` can be moved around the stack (e.g. returned by a function) but the pointers to the `CallbackData` given to Windows ETW API stay valid
    callback_data: Box<Arc<CallbackData>>,
}

/// Various parameters related to an ETL dump file
#[derive(Clone, Default)]
pub struct DumpFileParams {
    pub file_path: PathBuf,
    /// Options that control how the file is written. If you're not sure, you can use [`DumpFileLoggingMode::default()`].
    pub file_logging_mode: DumpFileLoggingMode,
    /// Maximum size of the dump file. This is expressed in MB, unless `file_logging_mode` requires it otherwise.
    pub max_size: Option<u32>,
}

/// Provides a way to crate Trace objects.
///
/// These builders are created using [`UserTrace::new`] or [`KernelTrace::new`]
pub struct TraceBuilder<T: RealTimeTraceTrait> {
    name: String,
    etl_dump_file: Option<DumpFileParams>,
    properties: TraceProperties,
    rt_callback_data: RealTimeCallbackData,
    stop_if_exist: bool,
    trace_kind: PhantomData<T>,
}

pub struct FileTraceBuilder {
    etl_file_path: PathBuf,
    callback: crate::EtwCallback,
}

impl UserTrace {
    /// Create a UserTrace builder
    pub fn new() -> TraceBuilder<UserTrace> {
        let name = format!("n4r1b-trace-{}", utils::rand_string());
        TraceBuilder {
            name,
            etl_dump_file: None,
            rt_callback_data: RealTimeCallbackData::new(TraceKind::User),
            properties: TraceProperties::default(),
            stop_if_exist: true,
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
            etl_dump_file: None,
            rt_callback_data: RealTimeCallbackData::new(TraceKind::Kernel),
            properties: TraceProperties::default(),
            stop_if_exist: true,
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TraceKind {
        User,
        Kernel,
    }

    pub trait PrivateRealTimeTraceTrait: PrivateTraceTrait {
        const TRACE_KIND: TraceKind;
        #[allow(clippy::redundant_allocation)] // Being Boxed is really important, let's keep the Box<...> in the function signature to make the intent clearer (see https://github.com/n4r1b/ferrisetw/issues/72)
        fn build(
            properties: EventTraceProperties,
            control_handle: ControlHandle,
            trace_handle: TraceHandle,
            callback_data: Box<Arc<CallbackData>>,
        ) -> Self;
        fn augmented_file_mode() -> u32;
        fn enable_flags(_providers: &[Provider]) -> u32;
    }

    pub trait PrivateTraceTrait {
        // This function aims at de-deduplicating code called by `impl Drop` and `Trace::stop`.
        // It is basically [`Self::stop`], without consuming self (because the `impl Drop` only has a `&mut self`, not a `self`)
        fn non_consuming_stop(&mut self) -> TraceResult<()>;
    }
}

impl private::PrivateRealTimeTraceTrait for UserTrace {
    const TRACE_KIND: private::TraceKind = private::TraceKind::User;

    fn build(
        properties: EventTraceProperties,
        control_handle: ControlHandle,
        trace_handle: TraceHandle,
        callback_data: Box<Arc<CallbackData>>,
    ) -> Self {
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
}

impl private::PrivateTraceTrait for UserTrace {
    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        close_trace(self.trace_handle, &self.callback_data)?;
        control_trace(
            &mut self.properties,
            self.control_handle,
            Etw::EVENT_TRACE_CONTROL_STOP,
        )?;
        Ok(())
    }
}

impl private::PrivateRealTimeTraceTrait for KernelTrace {
    const TRACE_KIND: private::TraceKind = private::TraceKind::Kernel;

    fn build(
        properties: EventTraceProperties,
        control_handle: ControlHandle,
        trace_handle: TraceHandle,
        callback_data: Box<Arc<CallbackData>>,
    ) -> Self {
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
}

impl private::PrivateTraceTrait for KernelTrace {
    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        close_trace(self.trace_handle, &self.callback_data)?;
        control_trace(
            &mut self.properties,
            self.control_handle,
            Etw::EVENT_TRACE_CONTROL_STOP,
        )?;
        Ok(())
    }
}

impl private::PrivateTraceTrait for FileTrace {
    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        close_trace(self.trace_handle, &self.callback_data)?;
        Ok(())
    }
}

impl<T: RealTimeTraceTrait + PrivateRealTimeTraceTrait> TraceBuilder<T> {
    /// Define the trace name
    ///
    /// For kernel traces on Windows Versions older than Win8, this method won't change the trace name. In those versions the trace name will be set to "NT Kernel Logger".
    ///
    /// Note: this trace name may be truncated to a few hundred characters if it is too long.
    pub fn named(mut self, name: String) -> Self {
        if T::TRACE_KIND == private::TraceKind::Kernel && !version_helper::is_win8_or_greater() {
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

    /// Define a dump file for the events.
    ///
    /// If set, events will be dumped to a file on disk.<br/>
    /// Such files usually have a `.etl` extension.<br/>
    /// Dumped events will also be processed by the callbacks you'll specify with [`crate::provider::ProviderBuilder::add_callback`].
    ///
    /// It is possible to control many aspects of the logging file (whether its size is limited, whether it should be a circular buffer file, etc.).
    /// If you're not sure, `params` has a safe [`default` value](`DumpFileParams::default`).
    ///
    /// Note: the file name may be truncated to a few hundred characters if it is too long.
    pub fn set_etl_dump_file(mut self, params: DumpFileParams) -> Self {
        self.etl_dump_file = Some(params);
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
        self.rt_callback_data.add_provider(provider);
        self
    }

    pub fn stop_if_exist(mut self, b: bool) -> Self {
        self.stop_if_exist = b;
        self
    }

    /// Build the `UserTrace` and start the trace session
    ///
    /// Internally, this calls the `StartTraceW`, `EnableTraceEx2` and `OpenTraceW`.
    /// For kernel traces with providers that have a group mask, it also calls `TraceSetInformation`.
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
        if self.stop_if_exist {
            stop_trace_by_name(&self.name)?;
        }
        // Prepare a wide version of the trace name
        let trace_wide_name = U16CString::from_str_truncate(self.name);
        let mut trace_wide_vec = trace_wide_name.into_vec();
        trace_wide_vec.truncate(crate::native::etw_types::TRACE_NAME_MAX_CHARS);
        let trace_wide_name = U16CString::from_vec_truncate(trace_wide_vec);

        // Prepare a wide version of the ETL dump file path
        let wide_etl_dump_file = match self.etl_dump_file {
            None => None,
            Some(DumpFileParams {
                file_path,
                file_logging_mode,
                max_size,
            }) => {
                let wide_path = U16CString::from_os_str_truncate(file_path.as_os_str());
                let mut wide_path_vec = wide_path.into_vec();
                wide_path_vec.truncate(crate::native::etw_types::TRACE_NAME_MAX_CHARS);
                Some((
                    U16CString::from_vec_truncate(wide_path_vec),
                    file_logging_mode,
                    max_size,
                ))
            }
        };

        let flags = self.rt_callback_data.provider_flags::<T>();
        let (mut full_properties, control_handle) = start_trace::<T>(
            &trace_wide_name,
            wide_etl_dump_file
                .as_ref()
                .map(|(path, params, max_size)| (path.as_ucstr(), *params, *max_size)),
            &self.properties,
            flags,
        )?;

        let callback_data = Box::new(Arc::new(CallbackData::RealTime(self.rt_callback_data)));
        let startup = (|| -> Result<TraceHandle, EvntraceNativeError> {
            if T::TRACE_KIND == private::TraceKind::User {
                if let CallbackData::RealTime(data) = callback_data.as_ref().as_ref() {
                    for prov in data.providers() {
                        enable_provider(control_handle, prov)?;
                        #[cfg(test)]
                        injected_startup_error(1)?;
                    }
                }
            }
            if T::TRACE_KIND == private::TraceKind::Kernel {
                if let CallbackData::RealTime(data) = callback_data.as_ref().as_ref() {
                    if let Some(group_mask) = kernel_group_mask(data.providers()) {
                        set_kernel_group_mask(control_handle, &group_mask)?;
                        #[cfg(test)]
                        injected_startup_error(1)?;
                    }
                }
            }

            #[cfg(test)]
            if STARTUP_FAILPOINT.with(|point| point.get() == 2) {
                STARTUP_FAILPOINT_REACHED.with(|reached| reached.set(true));
                let missing = U16CString::from_str(format!(
                    "ferrisetw-missing-{}-{}.etl",
                    std::process::id(),
                    utils::rand_string()
                ))
                .unwrap();
                return open_trace(SubscriptionSource::FromFile(missing), &callback_data);
            }
            open_trace(
                SubscriptionSource::RealTimeSession(trace_wide_name),
                &callback_data,
            )
        })();
        let trace_handle = match startup {
            Ok(handle) => handle,
            Err(startup) => {
                #[cfg(test)]
                let stop = if STARTUP_FAILPOINT.with(|point| point.get() == 3) {
                    Err(EvntraceNativeError::IoError(
                        std::io::Error::from_raw_os_error(12346),
                    ))
                } else {
                    control_trace(
                        &mut full_properties,
                        control_handle,
                        Etw::EVENT_TRACE_CONTROL_STOP,
                    )
                };
                #[cfg(not(test))]
                let stop = control_trace(
                    &mut full_properties,
                    control_handle,
                    Etw::EVENT_TRACE_CONTROL_STOP,
                );
                return match stop {
                    Ok(()) => Err(TraceError::EtwNativeError(startup)),
                    Err(rollback) => Err(TraceError::StartupRollback { startup, rollback }),
                };
            }
        };

        Ok((
            T::build(full_properties, control_handle, trace_handle, callback_data),
            trace_handle,
        ))
    }

    /// Build the `UserTrace` by opening a trace session, without starting it
    ///
    /// Internally, this calls the `OpenTraceW`.
    ///
    /// This function is to be used when you want to receive events on a trace you don't own.
    /// This can be useful when dealing with sources that only authorize one trace to be created, such as EventLog-Security.
    ///
    /// Since the trace is not owed, it cannot be stopped using StopTraceW or controlled using ControlTraceW, but can be closed using CloseTraceW.
    ///
    /// To start receiving events, see the [`TraceBuilder::start`] function to see the options, while keeping in mind that the trace cannot be stopped.
    pub fn open_existing(self) -> TraceResult<(T, TraceHandle)> {
        // Prepare a wide version of the trace name
        let trace_wide_name = U16CString::from_str_truncate(self.name);
        let mut trace_wide_vec = trace_wide_name.into_vec();
        trace_wide_vec.truncate(crate::native::etw_types::TRACE_NAME_MAX_CHARS);
        let trace_wide_name = U16CString::from_vec_truncate(trace_wide_vec);

        let flags = self.rt_callback_data.provider_flags::<T>();
        let callback_data = Box::new(Arc::new(CallbackData::RealTime(self.rt_callback_data)));

        // Prepare a wide version of the ETL dump file path
        let wide_etl_dump_file = match self.etl_dump_file {
            None => None,
            Some(DumpFileParams {
                file_path,
                file_logging_mode,
                max_size,
            }) => {
                let wide_path = U16CString::from_os_str_truncate(file_path.as_os_str());
                let mut wide_path_vec = wide_path.into_vec();
                wide_path_vec.truncate(crate::native::etw_types::TRACE_NAME_MAX_CHARS);
                Some((
                    U16CString::from_vec_truncate(wide_path_vec),
                    file_logging_mode,
                    max_size,
                ))
            }
        };

        let trace_handle = open_trace(
            SubscriptionSource::RealTimeSession(trace_wide_name.clone()),
            &callback_data,
        )
        .map_err(TraceError::EtwNativeError)?;

        // Build the User/Kernel Trace using an invalid ControlHandle (value is 0)
        // This Trace will fail to stop, but the handle can still be closed to stop receiving events
        Ok((
            T::build(
                EventTraceProperties::new::<T>(
                    &trace_wide_name,
                    wide_etl_dump_file
                        .as_ref()
                        .map(|(path, params, max_size)| (path.as_ucstr(), *params, *max_size)),
                    &self.properties,
                    flags,
                ),
                ControlHandle { Value: 0 },
                trace_handle,
                callback_data,
            ),
            trace_handle,
        ))
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

impl FileTrace {
    /// Create a trace that will read events from a file
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T>(path: PathBuf, callback: T) -> FileTraceBuilder
    where
        T: FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static,
    {
        FileTraceBuilder {
            etl_file_path: path,
            callback: Box::new(callback),
        }
    }

    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        close_trace(self.trace_handle, &self.callback_data)?;
        Ok(())
    }
}

impl FileTraceBuilder {
    /// Build the `FileTrace` and start the trace session
    ///
    /// See the documentation for [`TraceBuilder::start`] for more information.
    pub fn start(self) -> TraceResult<(FileTrace, TraceHandle)> {
        // Prepare a wide version of the source ETL file path
        let wide_etl_file_path = U16CString::from_os_str_truncate(self.etl_file_path.as_os_str());

        let from_file_cb = CallbackDataFromFile::new(self.callback);
        let callback_data = Box::new(Arc::new(CallbackData::FromFile(from_file_cb)));
        let trace_handle = open_trace(
            SubscriptionSource::FromFile(wide_etl_file_path),
            &callback_data,
        )?;

        Ok((
            FileTrace {
                trace_handle,
                callback_data,
            },
            trace_handle,
        ))
    }

    /// Convenience method that calls [`TraceBuilder::start`] then `process`
    ///
    /// # Notes
    /// * See the documentation of [`TraceBuilder::start`] for more info
    /// * `process` is called on a spawned thread, and thus this method does not give any way to retrieve the error of `process` (if any)
    pub fn start_and_process(self) -> TraceResult<FileTrace> {
        let (trace, trace_handle) = self.start()?;

        std::thread::spawn(move || FileTrace::process_from_handle(trace_handle));

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

impl Drop for FileTrace {
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
    let wide_name = U16CString::from_str(trace_name).map_err(|_| TraceError::InvalidTraceName)?;

    let mut properties = EventTraceProperties::new::<UserTrace>(
        // for EVENT_TRACE_CONTROL_STOP, we don't really care about most of the contents of the EventTraceProperties, so using new::<UserTrace>() is fine, even when stopping a kernel trace
        &wide_name,
        None, // MSDN says the dump file name (if any) must be populated for a EVENT_TRACE_CONTROL_STOP, but experience shows this is not necessary.
        &trace_properties,
        flags,
    );

    let result = control_trace_by_name(&mut properties, &wide_name, Etw::EVENT_TRACE_CONTROL_STOP);
    if let Err(e) = result {
        if e.code() == ERROR_WMI_INSTANCE_NOT_FOUND.to_hresult() {
            // This is not an error, it just means the trace was not running
            return Ok(());
        }
        return Err(TraceError::EtwNativeError(EvntraceNativeError::IoError(
            std::io::Error::from_raw_os_error(e.code().0),
        )));
    }

    Ok(())
}

/// The full group mask to set on a kernel trace, or `None` if `EnableFlags` alone are enough
///
/// `TraceSetInformation(TraceSystemTraceEnableFlagsInfo)` is not supported before Windows 8,
/// so it is only used when a provider actually needs a group mask.
fn kernel_group_mask(providers: &[Provider]) -> Option<PERFINFO_GROUPMASK> {
    if providers.iter().all(|p| p.kernel_group_mask() == 0) {
        return None;
    }

    let mut group_mask =
        PERFINFO_GROUPMASK::with_enable_flags(KernelTrace::enable_flags(providers));
    for provider in providers {
        group_mask.or_assign_with_groupmask(provider.kernel_group_mask());
    }
    Some(group_mask)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::provider::kernel_providers;

    #[test]
    #[ignore = "requires permission to create and query an ETW session"]
    fn failed_start_rolls_back_session_and_allows_retry() {
        for stage in [1, 2] {
            let name = format!(
                "ferrisetw-rollback-{}-{}",
                std::process::id(),
                utils::rand_string()
            );
            let first = Provider::by_guid(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716).build();
            let second = Provider::by_guid(0xa0c1853b_5c40_4b15_8766_3cf1c58f985a).build();
            STARTUP_FAILPOINT_REACHED.with(|reached| reached.set(false));
            STARTUP_FAILPOINT.with(|point| point.set(stage));
            let result = UserTrace::new()
                .named(name.clone())
                .stop_if_exist(false)
                .enable(first)
                .enable(second)
                .start();
            STARTUP_FAILPOINT.with(|point| point.set(0));
            let reached = STARTUP_FAILPOINT_REACHED.with(|reached| reached.get());
            let wide_name = U16CString::from_str(&name).unwrap();
            let mut properties = EventTraceProperties::new::<UserTrace>(
                &wide_name,
                None,
                &TraceProperties::default(),
                Etw::EVENT_TRACE_FLAG::default(),
            );
            let query =
                control_trace_by_name(&mut properties, &wide_name, Etw::EVENT_TRACE_CONTROL_QUERY);
            if reached && query.is_ok() {
                stop_trace_by_name(&name).expect("clean up test-owned session");
            }
            assert!(reached, "test did not reach the startup failure injection");
            match result {
                Err(TraceError::EtwNativeError(EvntraceNativeError::IoError(error))) => {
                    if stage == 1 {
                        assert_eq!(error.raw_os_error(), Some(12345));
                    } else {
                        assert_ne!(error.raw_os_error(), Some(12345));
                    }
                }
                other => panic!("unexpected startup result: {:?}", other),
            }
            assert!(
                matches!(query, Err(ref error) if error.code() == ERROR_WMI_INSTANCE_NOT_FOUND.to_hresult()),
                "startup failure left its ETW session running"
            );
            let (trace, _) = UserTrace::new()
                .named(name)
                .stop_if_exist(false)
                .start()
                .unwrap();
            trace.stop().unwrap();
        }
    }

    #[test]
    #[ignore = "requires permission to create and query an ETW session"]
    fn failed_rollback_reports_both_errors() {
        let name = format!(
            "ferrisetw-rollback-{}-{}",
            std::process::id(),
            utils::rand_string()
        );
        let provider = Provider::by_guid(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716).build();
        STARTUP_FAILPOINT_REACHED.with(|reached| reached.set(false));
        STARTUP_FAILPOINT.with(|point| point.set(3));
        let result = UserTrace::new()
            .named(name.clone())
            .stop_if_exist(false)
            .enable(provider)
            .start();
        STARTUP_FAILPOINT.with(|point| point.set(0));
        let reached = STARTUP_FAILPOINT_REACHED.with(|reached| reached.get());
        if reached {
            stop_trace_by_name(&name)
                .expect("clean up test-owned session after injected stop failure");
        }
        assert!(reached, "test did not reach the startup failure injection");
        assert!(matches!(result, Err(TraceError::StartupRollback {
            startup: EvntraceNativeError::IoError(ref startup),
            rollback: EvntraceNativeError::IoError(ref rollback),
        }) if startup.raw_os_error() == Some(12345) && rollback.raw_os_error() == Some(12346)));
    }

    #[test]
    #[ignore = "requires permission to create and query a kernel ETW session"]
    fn failed_kernel_group_mask_rolls_back_session() {
        let name = format!(
            "ferrisetw-kernel-rollback-{}-{}",
            std::process::id(),
            utils::rand_string()
        );
        let provider =
            Provider::kernel_with_group_mask(&kernel_providers::OBJECT_MANAGER_PROVIDER).build();
        STARTUP_FAILPOINT_REACHED.with(|reached| reached.set(false));
        STARTUP_FAILPOINT.with(|point| point.set(1));
        let result = KernelTrace::new()
            .named(name.clone())
            .stop_if_exist(false)
            .enable(provider)
            .start();
        STARTUP_FAILPOINT.with(|point| point.set(0));
        let reached = STARTUP_FAILPOINT_REACHED.with(|reached| reached.get());
        let wide_name = U16CString::from_str(&name).unwrap();
        let mut properties = EventTraceProperties::new::<KernelTrace>(
            &wide_name,
            None,
            &TraceProperties::default(),
            Etw::EVENT_TRACE_FLAG::default(),
        );
        let query =
            control_trace_by_name(&mut properties, &wide_name, Etw::EVENT_TRACE_CONTROL_QUERY);
        if query.is_ok() {
            stop_trace_by_name(&name).expect("clean up test-owned session");
        }
        assert!(reached, "test did not reach the startup failure injection");
        assert!(
            matches!(result, Err(TraceError::EtwNativeError(EvntraceNativeError::IoError(ref error))) if error.raw_os_error() == Some(12345)),
            "unexpected startup result: {:?}",
            result.map(|_| ())
        );
        assert!(
            matches!(query, Err(ref error) if error.code() == ERROR_WMI_INSTANCE_NOT_FOUND.to_hresult()),
            "startup failure left its ETW session running"
        );
    }

    #[test]
    fn kernel_group_mask_is_skipped_for_flags_only_providers() {
        let providers = [
            Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER).build(),
            Provider::kernel(&kernel_providers::PROCESS_PROVIDER).build(),
        ];
        assert_eq!(kernel_group_mask(&providers), None);
    }

    #[test]
    fn kernel_group_mask_combines_flags_and_groups() {
        let image_load = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER).build();
        let image_load_flags = image_load.kernel_flags();
        let object_manager =
            Provider::kernel_with_group_mask(&kernel_providers::OBJECT_MANAGER_PROVIDER).build();
        let custom = Provider::by_guid(GUID::zeroed())
            .kernel_group_mask(0x8000_0001)
            .build();

        let group_mask = kernel_group_mask(&[image_load, object_manager, custom]).unwrap();
        assert_eq!(group_mask.masks, [image_load_flags, 0, 0, 0, 0x41, 0, 0, 0]);
    }

    #[test]
    fn test_enable_multiple_providers() {
        let prov = Provider::by_guid(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716).build();
        let prov1 = Provider::by_guid(0xa0c1853b_5c40_4b15_8766_3cf1c58f985a).build();

        let trace_builder = UserTrace::new().enable(prov).enable(prov1);

        assert_eq!(trace_builder.rt_callback_data.providers().len(), 2);
    }
}
