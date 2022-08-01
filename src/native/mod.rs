//! Abstraction layer for Native functions and types
//!
//! This module interacts with the Windows native functions and should abstract all `unsafe` calls
pub mod etw_types;
pub mod evntrace;
pub mod pla;
pub mod sddl;
pub mod tdh;
pub mod tdh_types;
pub mod version_helper;
