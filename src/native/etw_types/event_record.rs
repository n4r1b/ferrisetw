use windows::Win32::System::Diagnostics::Etw;

/// Renaming type [EVENT_RECORD] type to match rust Naming Convention
///
/// [EVENT_RECORD]: https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Etw/struct.EVENT_RECORD.html
pub type EventRecord = Etw::EVENT_RECORD;
pub type PEventRecord = *mut EventRecord;
