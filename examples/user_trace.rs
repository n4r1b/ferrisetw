use ferrisetw::native::etw_types::EventRecord;
use ferrisetw::parser::{Parser, TryParse};
use ferrisetw::provider::*;
use ferrisetw::schema::SchemaLocator;
use ferrisetw::trace::*;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let process_callback =
        |record: EventRecord, schema_locator: &mut SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let event_id = schema.event_id();
                if event_id == 2 {
                    let name = schema.provider_name();
                    println!("Name: {}", name);
                    let mut parser = Parser::create(&schema);
                    let process_id: u32 = parser.try_parse("ProcessID").unwrap();
                    let exit_code: u32 = parser.try_parse("ExitCode").unwrap();
                    let image_name: String = parser.try_parse("ImageName").unwrap();
                    println!(
                        "PID: {}, ExitCode: {}, ImageName: {}",
                        process_id, exit_code, image_name
                    );
                }
            }
            Err(err) => println!("Error {:?}", err),
        };

    let process_provider = Provider::new()
        .by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Microsoft-Windows-Kernel-Process
        .add_callback(process_callback)
        .build()
        .unwrap();

    let trace = Arc::new(
        UserTraceBuilder::new()
            .named(String::from("MyProvider"))
            .enable(process_provider)
            .open()
            .unwrap(),
    );

    let hnd = trace.clone();
    let thrd = std::thread::spawn(move || hnd.process());

    std::thread::sleep(Duration::from_secs(20));

    println!("stopping trace...");

    trace.stop().unwrap();
    thrd.join().unwrap().unwrap();
}
