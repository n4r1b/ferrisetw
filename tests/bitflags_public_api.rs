use ferrisetw::provider::TraceFlags;
use ferrisetw::trace::{DumpFileLoggingMode, LoggingMode};
use std::fmt::Debug;
use std::hash::Hash;

fn assert_legacy_traits<T: Debug + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Hash>() {}

macro_rules! check_flags {
    ($flags:ty, $first:expr, $second:expr) => {{
        assert_legacy_traits::<$flags>();
        let first = $first;
        let second = $second;
        let both = first | second;
        let known_bits = first.bits() | second.bits();

        assert_eq!(both.bits(), known_bits);
        assert_eq!(both & first, first);
        assert_eq!(both - first, second);
        assert_eq!(<$flags>::from_bits(known_bits), Some(both));

        let omitted_bits = !<$flags>::all().bits();
        let unknown = omitted_bits & omitted_bits.wrapping_neg();
        assert_ne!(unknown, 0);
        let mixed_bits = known_bits | unknown;
        let mixed = <$flags>::from_bits_retain(mixed_bits);
        assert_eq!(mixed.bits(), mixed_bits);
        assert_eq!(<$flags>::from_bits(mixed_bits), None);
        assert_eq!(<$flags>::from_bits_truncate(mixed_bits), both);
        assert_eq!((mixed - both).bits(), unknown);
    }};
}

#[test]
fn public_flags_preserve_const_constructor_traits_and_bits() {
    // All values passed to the legacy constructors contain only documented flags.
    const TRACE: TraceFlags =
        unsafe { TraceFlags::from_bits_unchecked(TraceFlags::EVENT_ENABLE_PROPERTY_SID.bits()) };
    const LOG: LoggingMode =
        unsafe { LoggingMode::from_bits_unchecked(LoggingMode::EVENT_TRACE_REAL_TIME_MODE.bits()) };
    const DUMP: DumpFileLoggingMode = unsafe {
        DumpFileLoggingMode::from_bits_unchecked(
            DumpFileLoggingMode::EVENT_TRACE_FILE_MODE_SEQUENTIAL.bits(),
        )
    };

    assert_eq!(TRACE, TraceFlags::EVENT_ENABLE_PROPERTY_SID);
    assert_eq!(LOG, LoggingMode::EVENT_TRACE_REAL_TIME_MODE);
    assert_eq!(DUMP, DumpFileLoggingMode::EVENT_TRACE_FILE_MODE_SEQUENTIAL);
    check_flags!(TraceFlags, TRACE, TraceFlags::EVENT_ENABLE_PROPERTY_TS_ID);
    check_flags!(
        LoggingMode,
        LOG,
        LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING
    );
    check_flags!(
        DumpFileLoggingMode,
        DUMP,
        DumpFileLoggingMode::EVENT_TRACE_FILE_MODE_CIRCULAR
    );
}
