use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::*;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use std::time::Duration;

fn main() {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

    let process_callback =
        |record: &EventRecord, schema_locator: &SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let event_id = record.event_id();
                if event_id == 2 {
                    let name = schema.provider_name();
                    println!("Name: {}", name);
                    let parser = Parser::create(record, &schema);
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

    let process_provider = Provider
        ::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Microsoft-Windows-Kernel-Process
        .add_callback(process_callback)
        .build();

    let (_user_trace, handle) = UserTrace::new()
        .named(String::from("MyProvider"))
        .enable(process_provider)
        .start()
        .unwrap();

    // This example uses `process_from_handle` rather than the more convient `start_and_process`, because why not.
    std::thread::spawn(move || {
        let status = UserTrace::process_from_handle(handle);
        // This code will be executed when the trace stops. Examples:
        // * when it is dropped
        // * when it is manually stopped (either by user_trace.stop, or by the `logman stop -ets MyProvider` command)
        println!("Trace ended with status {:?}", status);
    });

    std::thread::sleep(Duration::new(20, 0));

    // user_trace will be dropped (and stopped) here
}
