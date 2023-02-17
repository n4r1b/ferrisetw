use std::time::Duration;
use std::path::PathBuf;

use ferrisetw::EventRecord;
use ferrisetw::{UserTrace, FileTrace};
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::DumpFileParams;
use ferrisetw::trace::TraceTrait;

#[test]
fn etl_file() {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

    let dump_file = DumpFileParams{
        file_path: PathBuf::from("etw-dump-file.etl"),
        ..Default::default()
    };
    let events_processes = save_a_trace(dump_file.clone());
    let events_read = process_from_file(dump_file.file_path);

    assert!(events_processes > 0); // otherwise this test will not test much
    assert!(events_read > events_processes); // The ETW framework can insert synthetic events, e.g. to give info about the current trace status. So, there may not be a perfec equality here
}

fn empty_callback(_record: &EventRecord, _schema_locator: &SchemaLocator) {}

fn save_a_trace(dump_file: DumpFileParams) -> usize {
    let process_provider = Provider
        ::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Microsoft-Windows-Kernel-Process
        .add_callback(empty_callback)
        .build();

    let trace = UserTrace::new()
        .named(String::from("MyTrace"))
        .enable(process_provider)
        .set_etl_dump_file(dump_file)
        .start_and_process()
        .unwrap();

    std::thread::sleep(Duration::from_secs(10));

    let n_events = trace.events_handled();
    println!("Processed {} events", n_events);
    n_events
}

fn process_from_file(input_file: PathBuf) -> usize {
    let (trace, handle) = FileTrace::new(input_file, empty_callback)
        .start()
        .unwrap();

    FileTrace::process_from_handle(handle).unwrap();

    let n_events = trace.events_handled();
    println!("Read {} events from file", n_events);
    n_events
}
