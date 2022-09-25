use ferrisetw::native::etw_types::EventRecord;
use ferrisetw::parser::{Parser, TryParse};
use ferrisetw::provider::*;
use ferrisetw::schema::SchemaLocator;
use ferrisetw::trace::*;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let image_load_callback =
        |record: &mut EventRecord, schema_locator: &mut SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let opcode = schema.opcode();
                if opcode == 10 {
                    let name = schema.provider_name();
                    println!("ProviderName: {}", name);
                    let mut parser = Parser::create(&schema);
                    // Fully Qualified Syntax for Disambiguation
                    match TryParse::<String>::try_parse(&mut parser, "FileName") {
                        Ok(filename) => println!("FileName: {}", filename),
                        Err(err) => println!("Error: {:?} getting Filename", err),
                    };
                }
            }
            Err(err) => println!("Error {:?}", err),
        };

    let provider = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
        .add_callback(image_load_callback)
        .build()
        .unwrap();

    let trace = Arc::new(
        KernelTraceBuilder::new()
            .named(String::from("MyKernelProvider"))
            .enable(provider)
            .open()
            .unwrap(),
    );

    let hnd = trace.clone();
    let thrd = std::thread::spawn(move || hnd.process());

    std::thread::sleep(Duration::new(20, 0));

    println!("stopping trace...");

    trace.stop().unwrap();
    thrd.join().unwrap().unwrap();
}
