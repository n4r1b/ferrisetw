use ferrisetw::native::etw_types::EventRecord;
use ferrisetw::parser::{Parser, Pointer, TryParse};
use ferrisetw::provider::*;
use ferrisetw::schema::SchemaLocator;
use ferrisetw::trace::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

fn registry_callback(record: &mut EventRecord, schema_locator: &mut SchemaLocator) {
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            if schema.event_id() == 7 {
                let mut parser = Parser::create(&schema);
                let pid = schema.process_id();
                let key_obj: Pointer = parser.try_parse("KeyObject").unwrap_or(Pointer::default());
                let status: u32 = parser.try_parse("Status").unwrap_or(0);
                let value_name: String = parser.try_parse("ValueName").unwrap_or(String::from(""));
                println!(
                    "QueryValueKey (PID: {}) -> KeyObj: {:#08x}, ValueName: {}, Status: {:#04X}",
                    pid, key_obj, value_name, status,
                );
            }
        }
        Err(err) => println!("Error {:?}", err),
    };
}

fn tcpip_callback(record: &mut EventRecord, schema_locator: &mut SchemaLocator) {
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            if schema.event_id() == 11 {
                let mut parser = Parser::create(&schema);
                let size: u32 = parser.try_parse("size").unwrap_or(0);
                let daddr: IpAddr = parser
                    .try_parse("daddr")
                    .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
                let dport: u16 = parser.try_parse("dport").unwrap_or(0);
                let saddr: IpAddr = parser
                    .try_parse("saddr")
                    .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
                let sport: u16 = parser.try_parse("sport").unwrap_or(0);
                println!(
                    "{} bytes received from {}:{} to {}:{}",
                    size, saddr, sport, daddr, dport
                );
            }
        }
        Err(err) => println!("Error {:?}", err),
    };
}

fn main() {
    let tcpip_provider = Provider::new()
        .by_guid("7dd42a49-5329-4832-8dfd-43d979153a88") // Microsoft-Windows-Kernel-Network
        .add_callback(tcpip_callback)
        .build()
        .unwrap();

    let process_provider = Provider::new()
        .by_guid("70eb4f03-c1de-4f73-a051-33d13d5413bd") // Microsoft-Windows-Kernel-Registry
        .add_callback(registry_callback)
        .build()
        .unwrap();

    let trace = Arc::new(
        UserTraceBuilder::new()
            .enable(process_provider)
            .enable(tcpip_provider)
            .open()
            .unwrap(),
    );

    let hnd = trace.clone();
    let thrd = std::thread::spawn(move || hnd.process());

    std::thread::sleep(Duration::new(10, 0));

    println!("stopping trace...");

    trace.stop().unwrap();
    thrd.join().unwrap().unwrap();
}
