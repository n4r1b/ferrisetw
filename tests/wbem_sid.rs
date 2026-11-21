use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ferrisetw::parser::Parser;
use ferrisetw::provider::{kernel_providers, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::KernelTrace;
use ferrisetw::EventRecord;

#[test]
#[ignore = "requires an elevated Windows session and a kernel ETW session"]
fn process_start_user_sid_matches_process_token() {
    let expected = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .expect("read current token SID");
    assert!(expected.status.success());
    let expected = String::from_utf8(expected.stdout).unwrap();
    let expected = expected.trim().split(',').last().unwrap().trim_matches('"');

    let (tx, rx) = mpsc::channel();
    let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if record.opcode() != 1 {
                return;
            }
            if let Ok(schema) = locator.event_schema(record) {
                let parser = Parser::create(record, &schema);
                if let (Ok(pid), Ok(sid)) = (
                    parser.try_parse::<u32>("ProcessId"),
                    parser.try_parse::<String>("UserSID"),
                ) {
                    let _ = tx.send((pid, sid));
                }
            }
        })
        .build();
    let trace = KernelTrace::new()
        .stop_if_exist(false)
        .enable(provider)
        .start_and_process()
        .unwrap();
    let mut child = Command::new("whoami.exe").spawn().unwrap();
    let pid = child.id();
    assert!(child.wait().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(10);
    let result = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok((event_pid, sid)) if event_pid == pid => break Some(sid),
            Ok(_) => continue,
            Err(_) => break None,
        }
    };
    trace.stop().unwrap();
    assert_eq!(result.as_deref(), Some(expected));
}
