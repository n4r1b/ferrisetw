use bitflags::bitflags;

use windows::Win32::System::Diagnostics::Etw;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TraceFlags: u32 {
        const EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 =  Etw::EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0;
        const EVENT_ENABLE_PROPERTY_PROVIDER_GROUP =    Etw::EVENT_ENABLE_PROPERTY_PROVIDER_GROUP;
        const EVENT_ENABLE_PROPERTY_PROCESS_START_KEY = Etw::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY;
        const EVENT_ENABLE_PROPERTY_EVENT_KEY =         Etw::EVENT_ENABLE_PROPERTY_EVENT_KEY;
        const EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE = Etw::EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE;
        const EVENT_ENABLE_PROPERTY_SID =               Etw::EVENT_ENABLE_PROPERTY_SID;
        const EVENT_ENABLE_PROPERTY_TS_ID =             Etw::EVENT_ENABLE_PROPERTY_TS_ID;
        const EVENT_ENABLE_PROPERTY_STACK_TRACE =       Etw::EVENT_ENABLE_PROPERTY_STACK_TRACE;
    }
}

impl TraceFlags {
    /// Constructs flags from their raw bits, preserving every bit.
    ///
    /// # Safety
    /// The caller must ensure that all bits correspond to defined flags or
    /// that any extra bits are valid for this flag type.
    #[inline]
    pub const unsafe fn from_bits_unchecked(bits: u32) -> Self {
        Self::from_bits_retain(bits)
    }
}
