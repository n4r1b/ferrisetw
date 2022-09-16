//! Use the DNS provider to test a few things regarding user traces

use std::time::Duration;
use std::process::Command;

use ferrisetw::provider::{Provider, EventFilter};
use ferrisetw::native::etw_types::EventRecord;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, TraceBaseTrait};
use ferrisetw::parser::{Parser, TryParse};

mod utils;
use utils::{Status, TestKind};

const TEST_DOMAIN_NAME: &str = "www.github.com";

const EVENT_ID_DNS_QUERY_INITIATED: u16 = 3006;
const EVENT_ID_DNS_QUERY_COMPLETED: u16 = 3008;



#[test]
fn dns_tests() {
    // These tests must be consecutive, as they share the same DNS provider
    simple_user_dns_trace();
    test_event_id_filter();
    // TODO: test with separate start/process
}

fn simple_user_dns_trace() {
    let passed = Status::new(TestKind::ExpectSuccess);
    let notifier = passed.notifier();

    let dns_provider = Provider::new()
        .by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
            let schema = schema_locator.event_schema(record).unwrap();
            let parser = Parser::create(record, &schema);

            // While we're at it, let's check a few more-or-less unrelated things on an actual ETW event
            check_a_few_cases(record, &parser);

            if has_seen_resolution_to_test_domain(record, &parser) {
                notifier.notify_success();
            }
        })
        .build()
        .unwrap();

    let mut _dns_trace = UserTrace::new()
        .enable(dns_provider)
        .start()
        .unwrap();

    generate_dns_events();

    passed.assert_passed();
    println!("simple_user_dns_trace passed");
}

fn test_event_id_filter() {
    let passed1 = Status::new(TestKind::ExpectSuccess);
    let passed2 = Status::new(TestKind::ExpectNoFailure);
    let notifier1 = passed1.notifier();
    let notifier2 = passed2.notifier();

    let filter = EventFilter::ByEventIds(vec![EVENT_ID_DNS_QUERY_COMPLETED]);

    let dns_provider = Provider::new()
        .by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_filter(filter)
        .add_callback(move |record: &EventRecord, _schema_locator: &SchemaLocator| {
            // We want at least one event, but only for the filtered kind
            if record.event_id() == EVENT_ID_DNS_QUERY_COMPLETED {
                notifier1.notify_success();
            } else {
                notifier2.notify_failure();
            }
        })
        .build()
        .unwrap();

    let mut _dns_trace = UserTrace::new()
        .enable(dns_provider)
        .start()
        .unwrap();

    generate_dns_events();

    passed1.assert_passed();
    passed2.assert_passed();
    println!("Test passed");
}


fn generate_dns_events() {
    std::thread::sleep(Duration::from_secs(1));
    // Unfortunately, `&str::to_socket_addrs()` does not use Microsoft APIs, and hence does not trigger a DNS ETW event
    // Let's use ping.exe instead
    println!("Resolving {}...", TEST_DOMAIN_NAME);
    let _output = Command::new("ping.exe")
       .arg("-n")
       .arg("1")
       .arg(TEST_DOMAIN_NAME)
       .output()
       .unwrap();
    println!("Resolution done.");
}

fn check_a_few_cases(record: &EventRecord, parser: &Parser) {
    // Parsing with a wrong type should properly error out
    if record.event_id() == EVENT_ID_DNS_QUERY_INITIATED {
        let _right_type: String = parser.try_parse("QueryName").unwrap();
        let wrong_type: Result<u32, _> = parser.try_parse("QueryName");
        assert!(wrong_type.is_err());
    }

    // Giving an unknown property should properly error out
    let wrong_name: Result<u32, _> = parser.try_parse("NoSuchProperty");
    assert!(wrong_name.is_err());
}

fn has_seen_resolution_to_test_domain(record: &EventRecord, parser: &Parser) -> bool {
    if record.event_id() == EVENT_ID_DNS_QUERY_INITIATED {
        let query_name: String = parser.try_parse("QueryName").unwrap();
        #[allow(unused_parens)]
        return (&query_name == TEST_DOMAIN_NAME);
    }
    false
}
