use ferrisetw::native::EvntraceNativeError;
use ferrisetw::trace::{KernelStackEvent, KernelTrace, TraceError};
use windows::core::GUID;

#[test]
fn rejects_more_than_256_stack_events_before_starting_session() {
    let event = KernelStackEvent::new(GUID::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc), 46);
    let result = KernelTrace::new()
        .named(format!("ferrisetw-stack-limit-{}", std::process::id()))
        .stop_if_exist(false)
        .stack_tracing(vec![event; 257])
        .start();
    assert!(
        matches!(result, Err(TraceError::EtwNativeError(EvntraceNativeError::IoError(ref e))) if e.kind() == std::io::ErrorKind::InvalidInput)
    );
}

#[test]
fn existing_session_rejects_stack_configuration_without_opening_it() {
    let event = KernelStackEvent::new(GUID::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc), 46);
    let result = KernelTrace::new()
        .named("ferrisetw-nonexistent-stack-session".into())
        .stack_tracing(vec![event])
        .open_existing();
    assert!(
        matches!(result, Err(TraceError::EtwNativeError(EvntraceNativeError::IoError(ref e))) if e.kind() == std::io::ErrorKind::InvalidInput)
    );
}
