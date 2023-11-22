//! Test that traces are started and stopped as expected

use std::process::Command;

use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::RealTimeTraceTrait;
use ferrisetw::trace::TraceTrait;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;

#[derive(Clone, Copy, Debug)]
enum HowToProcess {
    StartOnly,
    ProcessFromHandle,
    StartAndProcess,
}

#[test]
fn trace_lifetime() {
    // List of (names to request, ASCII part to look for)
    const NAME_EXAMPLES: [(&str, &str); 4] = [
        ("simple-trace-name", "simple-trace-name"),
        ("998877",            "998877"),
        ("My Ütf-8 tråce",    "tf-8 tr"),
        ("My Ütf-8 tråce name, that has quite a løøøøøøøøøøøøøøøøøøøøøng name, 😎 a very λονɣ name indeed (which is even longer than TRACE_NAME_MAX_CHARS). My Ütf-8 tråce name, that has quite a løøøøøøøøøøøøøøøøøøøøøng name, 😎 a very λονɣ name indeed (which is even longer than TRACE_NAME_MAX_CHARS).", "that has quite a"),
    ];

    const HOW_TO_PROCESS: [HowToProcess; 3] = [
        HowToProcess::StartOnly,
        HowToProcess::ProcessFromHandle,
        HowToProcess::StartAndProcess,
    ];

    // Setup: make sure no trace is still running from an older interrupted test
    for (requested_trace_name, _ascii_part_to_look_for) in NAME_EXAMPLES {
        let _output = Command::new("logman")
            .arg("stop")
            .arg("-ets")
            .arg(requested_trace_name)
            .output()
            .unwrap();
    }

    for provider_count in 0..2 {
        for (requested_trace_name, ascii_part_to_look_for) in NAME_EXAMPLES {
            for explicit_stop in [true, false] {
                for how_to_process in HOW_TO_PROCESS {
                    test_wordpad_trace(
                        provider_count,
                        requested_trace_name,
                        ascii_part_to_look_for,
                        explicit_stop,
                        how_to_process,
                    );

                    // Regardless of whether we explicitly stopped it, trace has been dropped and must no longer run
                    assert_trace_exists(ascii_part_to_look_for, false);
                }
            }
        }
    }
}

fn test_wordpad_trace(
    provider_count: usize,
    requested_trace_name: &str,
    ascii_part_of_the_trace_name: &str,
    explicit_stop: bool,
    how_to_process: HowToProcess,
) {
    println!(
        "Testing a trace with {} providers, processed as {:?}, stopped:{}, name contains {}...",
        provider_count, how_to_process, explicit_stop, ascii_part_of_the_trace_name
    );

    // Create a provider
    let mut provider_builder = Provider::by_guid("54FFD262-99FE-4576-96E7-1ADB500370DC"); // Microsoft-Windows-Wordpad
    for _i in 0..provider_count {
        provider_builder =
            provider_builder.add_callback(|_record: &EventRecord, _locator: &SchemaLocator| {})
    }
    let wordpad_provider = provider_builder.build();
    assert_trace_exists(requested_trace_name, false);

    // Create a trace
    let trace_builder = UserTrace::new()
        .named(String::from(requested_trace_name))
        .enable(wordpad_provider);

    let trace = match how_to_process {
        HowToProcess::StartOnly => {
            let (trace, _handle) = trace_builder.start().unwrap();
            trace // the trace is running, but not processing anything
        }
        HowToProcess::ProcessFromHandle => {
            let (trace, handle) = trace_builder.start().unwrap();
            std::thread::spawn(move || UserTrace::process_from_handle(handle));
            trace
        }
        HowToProcess::StartAndProcess => trace_builder.start_and_process().unwrap(),
    };

    let actual_trace_name = trace.trace_name().to_string_lossy().to_string();
    assert!(actual_trace_name.contains(ascii_part_of_the_trace_name));
    assert_trace_exists(ascii_part_of_the_trace_name, true);

    if explicit_stop {
        trace.stop().unwrap();
        assert_trace_exists(ascii_part_of_the_trace_name, false);
    }
}

/// Call `logman` and check if the expected trace is part of the output
///
/// This is limited to the ASCII part of the trace name, because Windows really sucks when it comes to encodings from sub processes (codepage issues, etc.)
#[track_caller]
fn assert_trace_exists(ascii_part_of_the_trace_name: &str, expected: bool) {
    for _attempt in 0..3 {
        let output = Command::new("logman")
            .arg("query")
            .arg("-ets")
            .output()
            .unwrap();

        let stdout_u8 = output.stdout;
        let stdout = String::from_utf8_lossy(&stdout_u8);
        let status = output.status;

        let res = stdout
            .split('\n')
            .any(|line| line.contains(ascii_part_of_the_trace_name));

        if status.success() {
            if res != expected {
                println!("logman output (returned {}): {}", status, stdout);
                unreachable!();
            }
        } else {
            // Not sure why, but logman sometimes fails to list current traces (with "The GUID passed was not recognized as valid by a WMI data provider.")
            println!("logman hit an error (returned {}).", status);
            println!("logman output: {}", stdout);
            println!("Let's try again");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}
