use tracelogging as tlg;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::TraceTrait;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;

mod utils;
use utils::{Status, TestKind};

const EVENT1_COUNT: u32 = 1;
const EVENT2_COUNT: u32 = 5;
const TEST_STRING_VALUE: &'static str = "TestString";
const PROVIDER_NAME: &'static str = "ferrisETW.TraceLoggingTest";

tlg::define_provider!(FERRIS_PROVIDER, "ferrisETW.TraceLoggingTest");

#[ignore]
#[test]
fn tlg_tests() {
    unsafe {
        FERRIS_PROVIDER.register();
    }

    let binding = tlg::Guid::from_name(PROVIDER_NAME).to_utf8_bytes();
    let guid = std::str::from_utf8(&binding).unwrap();

    tlg_multiple_events(guid);

    FERRIS_PROVIDER.unregister();
}

fn generate_tlg_events() {
    for _i in 0..EVENT1_COUNT {
        tlg::write_event!(
            FERRIS_PROVIDER,
            "Event1",
            level(Warning),
            keyword(0x13),
            str8("String", TEST_STRING_VALUE),
        );
    }

    for i in 0..EVENT2_COUNT {
        tlg::write_event!(
            FERRIS_PROVIDER,
            "Event2",
            level(Informational),
            keyword(0x6),
            u32("Integer", &i),
        );
    }
}

fn tlg_multiple_events(provider_guid: &str) {
    let passed = Status::new(TestKind::ExpectSuccess);
    let notifier = passed.notifier();

    let mut event1_count = 0;
    let mut event2_count = 0;

    let tlg_provider = Provider::by_guid(provider_guid)
        .add_callback(
            move |record: &EventRecord, schema_locator: &SchemaLocator| {
                let schema = schema_locator.event_schema(record).unwrap();
                let parser = Parser::create(record, &schema);

                // Test event_name function is working as expected & we can handle multiple
                // different events.
                if record.event_name() == "Event1" {
                    println!(
                        "Received Event1({}) from ferrisETW.TraceLoggingTest",
                        event1_count
                    );

                    assert_eq!(record.level(), tlg::Level::Warning.as_int());
                    assert_eq!(record.keyword(), 0x13);

                    // Tracelogging crate sets OutTypeUtf8 for str8 which we don't handle at the
                    // moment.
                    let _data = parser.try_parse::<String>("String");
                    // assert!(data.is_ok());
                    // assert_eq!(data, TEST_STRING_VALUE);

                    event1_count = event1_count + 1;
                } else if record.event_name() == "Event2" {
                    println!(
                        "Received Event2({}) from ferrisETW.TraceLoggingTest",
                        event2_count
                    );

                    assert_eq!(record.level(), tlg::Level::Informational.as_int());
                    assert_eq!(record.keyword(), 0x6);

                    let data = parser.try_parse::<u32>("Integer");

                    assert!(data.is_ok());
                    assert_eq!(data.unwrap(), event2_count);

                    event2_count = event2_count + 1;
                }

                if event1_count == EVENT1_COUNT && event2_count == EVENT2_COUNT {
                    notifier.notify_success();
                }
            },
        )
        .build();

    let tlg_trace = UserTrace::new()
        .enable(tlg_provider)
        .start_and_process()
        .unwrap();

    generate_tlg_events();

    passed.assert_passed();
    assert!(tlg_trace.events_handled() > 0);
    tlg_trace.stop().unwrap();
    println!("tlg_multiple_events passed");
}
