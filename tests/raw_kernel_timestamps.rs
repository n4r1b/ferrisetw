use ferrisetw::provider::kernel_providers;
use ferrisetw::raw::RawTimestamp;
use ferrisetw::trace::{KernelStackEvent, KernelTrace};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Seen {
    samples: HashSet<(RawTimestamp, u32)>,
    stack_times: Vec<(RawTimestamp, u32)>,
}

#[test]
#[ignore = "requires enabled SeSystemProfilePrivilege and sampled profiling support"]
fn raw_sampled_profile_stacks_correlate_by_timestamp() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let samples = seen.clone();
    let stacks = seen.clone();
    let pid = std::process::id();
    let trace = KernelTrace::new_raw()
        .named(format!("ferrisetw-raw-correlation-{}", pid))
        .stop_if_exist(false)
        .enable_kernel(&kernel_providers::PROFILE_PROVIDER, move |record| {
            if record.opcode() == 46 {
                if let Ok(Ok(tid)) =
                    record.with_parser(|parser| parser.try_parse::<u32>("ThreadId"))
                {
                    samples
                        .lock()
                        .unwrap()
                        .samples
                        .insert((record.timestamp(), tid));
                }
            }
        })
        .enable_guid(0xdef2fe46_7bd6_4b80_bd94_f57fe20d0ce3, move |record| {
            let data = record.user_data();
            if record.opcode() == 32 && data.len() >= 16 + record.pointer_size() {
                let process = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                if process == pid {
                    let time = i64::from_le_bytes([
                        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                    ]);
                    let tid = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
                    stacks
                        .lock()
                        .unwrap()
                        .stack_times
                        .push((RawTimestamp::from_ticks(time), tid));
                }
            }
        })
        .stack_tracing(vec![KernelStackEvent::new(
            kernel_providers::PROFILE_PROVIDER.guid,
            46,
        )])
        .start_and_process()
        .expect("start owned kernel trace");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut value = 1_u64;
    while Instant::now() < deadline {
        value = std::hint::black_box(value.wrapping_mul(1664525).wrapping_add(1013904223));
    }
    std::hint::black_box(value);
    std::thread::sleep(Duration::from_secs(1));
    trace.stop().expect("stop owned kernel trace");
    let seen = seen.lock().unwrap();
    assert!(!seen.samples.is_empty(), "no sampled profile events");
    assert!(
        !seen.stack_times.is_empty(),
        "no stack events for this process"
    );
    let matched = seen
        .stack_times
        .iter()
        .filter(|time| seen.samples.contains(time))
        .count();
    println!(
        "samples={} own_stacks={} matched_by_timestamp_and_thread={}",
        seen.samples.len(),
        seen.stack_times.len(),
        matched
    );
    assert!(
        matched > 0,
        "raw stack and sample timestamps did not correlate"
    );
}

#[test]
#[ignore = "requires permission to create a kernel ETW session"]
fn raw_mode_preserves_extended_kernel_group_mask_events() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let pid = std::process::id();
    let trace = KernelTrace::new_raw()
        .named(format!("ferrisetw-raw-group-{}", pid))
        .stop_if_exist(false)
        .enable_group_mask(&kernel_providers::OBJECT_MANAGER_PROVIDER, move |record| {
            if record.process_id() == pid {
                seen.fetch_add(1, Ordering::Relaxed);
            }
        })
        .start_and_process()
        .expect("start owned kernel trace");
    std::thread::sleep(Duration::from_secs(1));
    for _ in 0..10 {
        drop(std::fs::File::open(std::env::current_exe().unwrap()).unwrap());
    }
    std::thread::sleep(Duration::from_secs(1));
    trace.stop().expect("stop owned kernel trace");
    assert!(
        count.load(Ordering::Relaxed) > 0,
        "extended group events missing in raw mode"
    );
}
