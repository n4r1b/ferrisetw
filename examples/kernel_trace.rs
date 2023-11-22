use ferrisetw::parser::Parser;
use ferrisetw::provider::*;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use ferrisetw::EventRecord;
use std::time::Duration;

fn main() {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

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
                    match parser.try_parse::<String>("FileName") {
                        Ok(filename) => println!("FileName: {}", filename),
                        Err(err) => println!("Error: {:?} getting Filename", err),
                    };
                }
            }
            Err(err) => println!("Error {:?}", err),
        };

    let provider = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
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
