use super::*;
use crate::trace::callback_data::RealTimeCallbackData;
use crate::trace::TraceKind;
use widestring::U16CString;

unsafe extern "system" fn ignored_callback(_: *mut Etw::EVENT_RECORD) {}

#[test]
fn raw_mode_is_explicit_and_preserves_existing_event_record_flags() {
    let data = Box::new(Arc::new(CallbackData::RealTime(RealTimeCallbackData::new(
        TraceKind::Kernel,
    ))));
    for raw in [false, true] {
        let source =
            SubscriptionSource::RealTimeSession(U16CString::from_str("raw-mode-test").unwrap());
        let logfile = EventTraceLogfile::create(&data, source, ignored_callback, raw);
        let flags = unsafe { logfile.native.Anonymous1.ProcessTraceMode };
        assert_ne!(flags & Etw::PROCESS_TRACE_MODE_REAL_TIME, 0);
        assert_ne!(flags & Etw::PROCESS_TRACE_MODE_EVENT_RECORD, 0);
        assert_eq!(flags & Etw::PROCESS_TRACE_MODE_RAW_TIMESTAMP != 0, raw);
    }
}

#[cfg(feature = "time_rs")]
#[test]
fn existing_wall_clock_timestamp_still_decodes_filetime() {
    let mut native = Etw::EVENT_RECORD::default();
    native.EventHeader.TimeStamp = 116_444_736_000_000_000;
    let record = crate::EventRecord(native);
    assert_eq!(record.timestamp().unix_timestamp(), 0);
}

#[test]
fn existing_file_trace_keeps_converted_timestamps() {
    let data = Box::new(Arc::new(CallbackData::RealTime(RealTimeCallbackData::new(
        TraceKind::Kernel,
    ))));
    let source = SubscriptionSource::FromFile(U16CString::from_str("existing.etl").unwrap());
    let logfile = EventTraceLogfile::create(&data, source, ignored_callback, false);
    let flags = unsafe { logfile.native.Anonymous1.ProcessTraceMode };
    assert_eq!(flags & Etw::PROCESS_TRACE_MODE_RAW_TIMESTAMP, 0);
    assert_eq!(flags & Etw::PROCESS_TRACE_MODE_REAL_TIME, 0);
    assert_ne!(flags & Etw::PROCESS_TRACE_MODE_EVENT_RECORD, 0);
}
