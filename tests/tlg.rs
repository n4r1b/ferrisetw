use tracelogging as tlg;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::TraceTrait;
use ferrisetw::trace::UserTrace;
use ferrisetw::{EventRecord, GUID};
use std::time::{Duration, Instant};

mod utils;
use utils::{Status, TestKind};

const EVENT1_COUNT: u32 = 1;
const EVENT2_COUNT: u32 = 5;
const EVENT3_COUNT: u32 = 1;
const EVENT4_COUNT: u32 = 1;
const TEST_STRING_VALUE: &'static str = "TestString";
const TEST_UTF16_VALUE: &'static str = "Ferris \u{1f980} TDH";
const TEST_TRAILING_VALUE: u32 = 0xdead_beef;
const PROVIDER_NAME: &'static str = "ferrisETW.TraceLoggingTest";
const TEST_GUID: tlg::Guid = tlg::Guid::from_fields(
    0x6b29_fc40,
    0xca47,
    0x1067,
    [0xb3, 0x1d, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda],
);

tlg::define_provider!(FERRIS_PROVIDER, "ferrisETW.TraceLoggingTest");

#[ignore]
#[test]
fn tlg_tests() {
    use std::convert::TryInto;
    unsafe {
        FERRIS_PROVIDER.register();
    }

    let binding = tlg::Guid::from_name(PROVIDER_NAME).to_utf8_bytes();
    let guid = std::str::from_utf8(&binding).unwrap();

    tlg_multiple_events(guid.try_into().unwrap());

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

    for _i in 0..EVENT3_COUNT {
        tlg::write_event!(
            FERRIS_PROVIDER,
            "Event3",
            level(Informational),
            keyword(0x6),
            guid("Guid", &TEST_GUID),
        );
    }

    let utf16: Vec<u16> = TEST_UTF16_VALUE.encode_utf16().collect();
    for _i in 0..EVENT4_COUNT {
        tlg::write_event!(
            FERRIS_PROVIDER,
            "Event4",
            level(Informational),
            keyword(0x6),
            str16("Utf16", &utf16),
            u32("Trailing", &TEST_TRAILING_VALUE),
        );
    }
}

fn tlg_multiple_events(provider_guid: GUID) {
    let passed = Status::new(TestKind::ExpectSuccess);
    let notifier = passed.notifier();

    let mut event1_count = 0;
    let mut event2_count = 0;
    let mut event3_count = 0;
    let mut event4_count = 0;

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
                } else if record.event_name() == "Event3" {
                    let data = parser.try_parse::<GUID>("Guid");

                    assert!(data.is_ok());
                    assert_eq!(
                        data.unwrap(),
                        GUID::from_u128(0x6b29_fc40_ca47_1067_b31d_00dd010662da),
                    );

                    event3_count = event3_count + 1;
                } else if record.event_name() == "Event4" {
                    // The trailing field is only found if the counted string's size was right.
                    assert_eq!(
                        parser.try_parse::<String>("Utf16").unwrap(),
                        TEST_UTF16_VALUE
                    );
                    assert_eq!(
                        parser.try_parse::<u32>("Trailing").unwrap(),
                        TEST_TRAILING_VALUE
                    );

                    #[cfg(feature = "serde")]
                    {
                        let options = ferrisetw::EventSerializerOptions {
                            fail_unimplemented: true,
                            ..Default::default()
                        };
                        let event = ferrisetw::EventSerializer::new(record, &schema, options);
                        let json = serde_json::to_value(event).unwrap();
                        assert_eq!(json["Event"]["Utf16"], TEST_UTF16_VALUE);
                        assert_eq!(json["Event"]["Trailing"], TEST_TRAILING_VALUE);
                    }

                    event4_count = event4_count + 1;
                }

                if event1_count == EVENT1_COUNT
                    && event2_count == EVENT2_COUNT
                    && event3_count == EVENT3_COUNT
                    && event4_count == EVENT4_COUNT
                {
                    notifier.notify_success();
                }
            },
        )
        .build();

    let tlg_trace = UserTrace::new()
        .enable(tlg_provider)
        .start_and_process()
        .unwrap();

    // Enabling the provider completes asynchronously; events written before then are dropped.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !FERRIS_PROVIDER.enabled(tlg::Level::LogAlways, 0) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    generate_tlg_events();

    passed.assert_passed();
    assert!(tlg_trace.events_handled() > 0);
    tlg_trace.stop().unwrap();
    println!("tlg_multiple_events passed");
}
