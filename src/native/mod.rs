//! Abstraction layer for Native functions and types
//!
//! This module interacts with the Windows native functions and should abstract all `unsafe` calls
pub(crate) mod etw_types;
pub(crate) mod evntrace;
pub(crate) mod pla;
pub(crate) mod sddl;
pub(crate) mod tdh;
pub(crate) mod tdh_types;
pub(crate) mod version_helper;
pub mod time;

// These are used in our custom error types, and must be part of the public API
pub use pla::PlaError;
pub use sddl::SddlNativeError;
pub use tdh::TdhNativeError;
pub use evntrace::EvntraceNativeError;

// These are returned by some of our public APIs
pub use etw_types::DecodingSource;
pub use etw_types::extended_data::ExtendedDataItem;
pub use etw_types::extended_data::EventHeaderExtendedDataItem;
pub use evntrace::TraceHandle;
pub use evntrace::ControlHandle;
pub use windows::Win32::System::Diagnostics::Etw::{
    EVENT_EXTENDED_ITEM_INSTANCE,
    EVENT_EXTENDED_ITEM_STACK_TRACE32,
    EVENT_EXTENDED_ITEM_STACK_TRACE64,
};
