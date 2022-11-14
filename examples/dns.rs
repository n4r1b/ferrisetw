use std::time::Duration;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use ferrisetw::provider::Provider;
use ferrisetw::provider::TraceFlags;
use ferrisetw::parser::Parser;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::native::etw_types::EventRecord;
use ferrisetw::trace::UserTrace;
use ferrisetw::parser::TryParse;
use ferrisetw::schema::Schema;


static N_EVENTS: AtomicU32 = AtomicU32::new(0);

fn dns_etw_callback(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!(
                "Unable to get the ETW schema for a DNS event: {:?}",
                err
            );
            return;
        },

        Ok(schema) => {
            parse_etw_event(&schema, record);
        },
    }
}

fn parse_etw_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    // let event_timestamp = filetime_to_datetime(schema.timestamp());

    let requested_fqdn: Option<String> = parser
        .try_parse("QueryName")
        .ok();
    let query_type: Option<u32> = parser
        .try_parse("QueryType")
        .ok();
    let query_options: Option<u64> = parser
        .try_parse("QueryOptions")
        .ok();
    let query_status: Option<u32> = parser
        .try_parse("QueryStatus")
        .or_else(|_err| parser.try_parse("Status"))
        .ok();
    let query_results: Option<String> = parser
        .try_parse("QueryResults")
        .ok();

    println!("{:4} {:4}  {:16} {:2} {:10} {}",
        record.event_id(),
        query_status.map(|u| u.to_string()).unwrap_or_default(),
        query_options.map(|u| format!("{:16x}", u)).unwrap_or_default(),
        query_type.map(|u| format!("{:2}", u)).unwrap_or_default(),
        requested_fqdn.map(|s| truncate(&s, 10).to_owned()).unwrap_or_default(),
        query_results.map(|s| truncate(&s, 30).to_owned()).unwrap_or_default(),
    );
}

fn main() {
    let dns_provider = Provider
        ::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_callback(dns_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let trace = UserTrace::new()
        .enable(dns_provider)
        .start_and_process()
        .unwrap();

    println!("ID   Status Options         Ty Name       Results");

    std::thread::sleep(Duration::new(20, 0));

    trace.stop().unwrap(); // This is not required, as it will automatically be stopped on Drop
    println!("Done: {:?} events", N_EVENTS);
}

fn truncate(s: &str, n: usize) -> &str {
    match s.get(..n) {
        Some(x) => x,
        None => s
    }
}
