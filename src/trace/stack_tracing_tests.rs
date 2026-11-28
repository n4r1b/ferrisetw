use super::*;
use crate::provider::kernel_providers;

#[test]
#[ignore = "requires permission to create and query a kernel ETW session"]
fn stack_configuration_failure_rolls_back_owned_session() {
    let name = format!(
        "ferrisetw-stack-rollback-{}-{}",
        std::process::id(),
        utils::rand_string()
    );
    let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER).build();
    let event = KernelStackEvent::new(kernel_providers::PROCESS_PROVIDER.guid, 1);
    STARTUP_FAILPOINT_REACHED.with(|reached| reached.set(false));
    STARTUP_FAILPOINT.with(|point| point.set(4));
    let result = KernelTrace::new()
        .named(name.clone())
        .stop_if_exist(false)
        .enable(provider)
        .stack_tracing(vec![event])
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
    let query = control_trace_by_name(&mut properties, &wide_name, Etw::EVENT_TRACE_CONTROL_QUERY);
    if query.is_ok() {
        stop_trace_by_name(&name).expect("clean up test-owned session");
    }
    assert!(
        reached,
        "stack configuration did not reach the injected failure"
    );
    assert!(
        matches!(result, Err(TraceError::EtwNativeError(EvntraceNativeError::IoError(ref error))) if error.raw_os_error() == Some(12345))
    );
    assert!(
        matches!(query, Err(ref error) if error.code() == ERROR_WMI_INSTANCE_NOT_FOUND.to_hresult()),
        "session survived startup failure"
    );
    let (trace, _) = KernelTrace::new()
        .named(name)
        .stop_if_exist(false)
        .start()
        .unwrap();
    trace.stop().unwrap();
}

#[test]
#[ignore = "requires SeSystemProfilePrivilege and a system supporting sampled profiling"]
fn sampled_profile_stack_events_require_stack_configuration() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    for enabled in [false, true] {
        let samples = Arc::new(AtomicUsize::new(0));
        let own_stacks = Arc::new(AtomicUsize::new(0));
        let sample_counter = samples.clone();
        let stack_counter = own_stacks.clone();
        let pid = std::process::id();
        let profile = Provider::kernel(&kernel_providers::PROFILE_PROVIDER)
            .add_callback(move |record: &EventRecord, _: &SchemaLocator| {
                if record.opcode() == 46 {
                    sample_counter.fetch_add(1, Ordering::Relaxed);
                }
            })
            .build();
        let stack = Provider::by_guid(0xdef2fe46_7bd6_4b80_bd94_f57fe20d0ce3)
            .add_callback(move |record: &EventRecord, _: &SchemaLocator| {
                let data = record.user_buffer();
                if record.opcode() == 32 && data.len() >= 16 + record.pointer_size() {
                    let stack_pid = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                    if stack_pid == pid {
                        stack_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
            .build();
        let mut builder = KernelTrace::new()
            .named(format!("ferrisetw-stack-profile-{}-{}", pid, enabled as u8))
            .stop_if_exist(false)
            .enable(profile)
            .enable(stack);
        if enabled {
            builder = builder.stack_tracing(vec![KernelStackEvent::new(
                kernel_providers::PROFILE_PROVIDER.guid,
                46,
            )]);
        }
        let trace = builder
            .start_and_process()
            .expect("start owned kernel trace");
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut value = 1u64;
        while Instant::now() < deadline {
            value = std::hint::black_box(value.wrapping_mul(1664525).wrapping_add(1013904223));
        }
        std::hint::black_box(value);
        std::thread::sleep(Duration::from_secs(1));
        trace.stop().expect("stop owned kernel trace");
        let samples = samples.load(Ordering::Relaxed);
        let own_stacks = own_stacks.load(Ordering::Relaxed);
        assert!(samples > 0, "no sampled profile events");
        if enabled {
            assert!(own_stacks > 0, "no stack with a frame for this process");
        } else {
            assert_eq!(own_stacks, 0, "stack capture unexpectedly enabled");
        }
    }
}
