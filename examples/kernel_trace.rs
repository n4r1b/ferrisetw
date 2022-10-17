use ferrisetw::native::etw_types::EventRecord;
use ferrisetw::parser::{Parser, TryParse};
use ferrisetw::provider::*;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use std::time::Duration;

fn main() {
    let image_load_callback =
        |record: &EventRecord, schema_locator: &SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let opcode = record.opcode();
                if opcode == 10 {
                    let name = schema.provider_name();
                    println!("ProviderName: {}", name);
                    let parser = Parser::create(record, &schema);
                    // Fully Qualified Syntax for Disambiguation
                    match TryParse::<String>::try_parse(&parser, "FileName") {
                        Ok(filename) => println!("FileName: {}", filename),
                        Err(err) => println!("Error: {:?} getting Filename", err),
                    };
                }
            }
            Err(err) => println!("Error {:?}", err),
        };

    let provider = Provider
        ::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
        .add_callback(image_load_callback)
        .build();

    let kernel_trace = KernelTrace::new()
        .named(String::from("MyKernelProvider"))
        .enable(provider)
        .start_and_process()
        .unwrap();

    std::thread::sleep(Duration::new(20, 0));
    kernel_trace.stop().unwrap(); // This is not required, as it will automatically be stopped on Drop
}
