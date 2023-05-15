#![cfg(feature = "serde")]

use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{stop_trace_by_name, TraceBuilder, TraceTrait, UserTrace};
use ferrisetw::{EventRecord, EventSerializer, EventSerializerOptions};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static BENCHMARK_PROVIDERS: &[&str] = &[
    "C514638F-7723-485B-BCFC-96565D735D4A",
    "16A1ADC1-9B7F-4CD9-94B3-D8296AB1B130",
    "E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23",
    "15CA44FF-4D7A-4BAA-BBA5-0998955E531E",
    "96AC7637-5950-4A30-B8F7-E07E8E5734C1",
    "A2D34BF1-70AB-5B21-C819-5A0DD42748FD",
    "7F54CA8A-6C72-5CBC-B96F-D0EF905B8BCE",
    "C7BDE69A-E1E0-4177-B6EF-283AD1525271",
    "17D2A329-4539-5F4D-3435-F510634CE3B9",
    "B675EC37-BDB6-4648-BC92-F3FDC74D3CA2",
    "EDD08927-9CC4-4E65-B970-C2560FB5C289",
    "A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D",
    "951B41EA-C830-44DC-A671-E2C9958809B8",
    "ABF1F586-2E50-4BA8-928D-49044E6F0DB7",
    "A103CABD-8242-4A93-8DF5-1CDF3B3F26A6",
    "A0AF438F-4431-41CB-A675-A265050EE947",
    "BEF2AA8E-81CD-11E2-A7BB-5EAC6188709B",
    "D1D93EF7-E1F2-4F45-9943-03D245FE6C00",
    "7DD42A49-5329-4832-8DFD-43D979153A88",
    "5412704E-B2E1-4624-8FFD-55777B8F7373",
    "9C205A39-1250-487D-ABD7-E831C6290539",
    "B3A0C2C8-83BB-4DDF-9F8D-4B22D3C38AD7",
    "331C3B3A-2005-44C2-AC5E-77220C37D6B4",
    "AA1F73E8-15FD-45D2-ABFD-E7F64F78EB11",
    "5322D61A-9EFA-4BC3-A3F9-14BE95C144F8",
    "B931ED29-66F4-576E-0579-0B8818A5DC6B",
    "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716",
    "0F67E49F-FE51-4E9F-B490-6F2948CC6027",
    "70EB4F03-C1DE-4F73-A051-33D13D5413BD",
    "0BF2FB94-7B60-4B4D-9766-E82F658DF540",
    "A6AD76E3-867A-4635-91B3-4904BA6374D7",
    "548C4417-CE45-41FF-99DD-528F01CE0FE1",
    "4CEC9C95-A65F-4591-B5C4-30100E51D870",
    "2FF3E6B7-CB90-4700-9621-443F389734ED",
    "7B563579-53C8-44E7-8236-0F87B9FE6594",
    "F029AC39-38F0-4A40-B7DE-404D244004CB",
    "84DE80EB-86E8-4FF6-85A6-9319ABD578A4",
    "8939299F-2315-4C5C-9B91-ABB86AA0627D",
    "85FE7609-FF4A-48E9-9D50-12918E43E1DA",
    "CB070027-1534-4CF3-98EA-B9751F508376",
    "7237FFF9-A08A-4804-9C79-4A8704B70B87",
    "4FCC72A9-D7CA-5DD2-8D34-6F41A0CDB7E0",
    "099614A5-5DD7-4788-8BC9-E29F43DB28FC",
    "73AA0094-FACB-4AEB-BD1D-A7B98DD5C799",
    "DCBFB8F0-CD19-4F1C-A27D-23AC706DED72",
    "05F02597-FE85-4E67-8542-69567AB8FD4F",
    "CCC64809-6B5F-4C1B-AB39-336904DA9B3B",
    "0741C7BE-DAAC-4A5B-B00A-4BD9A2D89D0E",
    "E159FC63-02FE-42F3-A234-028B9B8561CB",
    "93C05D69-51A3-485E-877F-1806A8731346",
    "C882FF1D-7585-4B33-B135-95C577179137",
    "A329CF81-57EC-46ED-AB7C-261A52B0754A",
];

struct BenchmarkStatistics {
    success_count: AtomicU64,
    error_count: AtomicU64,
    byte_count: AtomicU64,
}

impl BenchmarkStatistics {
    fn new() -> Self {
        Self {
            success_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            byte_count: AtomicU64::new(0),
        }
    }

    fn snap(&self) -> (u64, u64, u64) {
        (
            self.success_count.load(Ordering::Acquire),
            self.error_count.load(Ordering::Acquire),
            self.byte_count.load(Ordering::Acquire),
        )
    }

    fn json_callback(
        &self,
        record: &EventRecord,
        schema_locator: &SchemaLocator,
        options: EventSerializerOptions,
    ) {
        let res = schema_locator.event_schema(record);
        if res.is_err() {
            self.error_count.fetch_add(1, Ordering::AcqRel);
            return;
        }
        let schema = res.unwrap();

        let event = EventSerializer::new(record, &schema, options);
        let res = serde_json::to_value(event);
        if res.is_err() {
            println!("{:?}", res);
            self.error_count.fetch_add(1, Ordering::AcqRel);
            return;
        }

        let json_string = res.unwrap().to_string();
        //println!("{}", json_string);
        self.success_count.fetch_add(1, Ordering::AcqRel);
        self.byte_count
            .fetch_add(json_string.len() as u64, Ordering::AcqRel);
    }

    fn flexbuffer_callback(
        &self,
        record: &EventRecord,
        schema_locator: &SchemaLocator,
        options: EventSerializerOptions,
    ) {
        let res = schema_locator.event_schema(record);
        if res.is_err() {
            self.error_count.fetch_add(1, Ordering::AcqRel);
            return;
        }
        let schema = res.unwrap();

        let event = EventSerializer::new(record, &schema, options);
        let mut ser = flexbuffers::FlexbufferSerializer::new();
        let res = event.serialize(&mut ser);
        if res.is_err() {
            println!("{:?}", res);
            self.error_count.fetch_add(1, Ordering::AcqRel);
            return;
        }

        self.success_count.fetch_add(1, Ordering::AcqRel);
        self.byte_count
            .fetch_add(ser.view().len() as u64, Ordering::AcqRel);
    }
}

fn do_benchmark(
    name: &str,
    stats: Arc<BenchmarkStatistics>,
    trace_builder: TraceBuilder<UserTrace>,
    seconds_to_run: u64,
) {
    let (trace, trace_handle) = trace_builder.start().expect("unable to start trace");

    let thread = std::thread::spawn(move || UserTrace::process_from_handle(trace_handle));

    let clock = Instant::now();
    let mut now: Option<Instant> = None;
    let (mut last_s, mut last_e, mut last_b) = stats.snap();
    loop {
        let (s, e, b) = stats.snap();

        if let Some(now) = now {
            let micros = now.elapsed().as_micros();
            println!(
                "{:<32}: {} b/s {} s/s {} e/s",
                name,
                (((b - last_b) * 1_000_000) as u128) / micros,
                (((s - last_s) * 1_000_000) as u128) / micros,
                (((e - last_e) * 1_000_000) as u128) / micros,
            );
        }

        (last_s, last_e, last_b) = (s, e, b);
        now = Some(Instant::now());

        if clock.elapsed().as_secs() > seconds_to_run {
            break;
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    trace.stop().expect("unable to stop trace");
    thread
        .join()
        .expect("thread panic")
        .expect("trace processing error");

    println!(
        "{:<32}: {} b {} s {} e",
        name, last_b, last_s, last_e
    );
    assert_eq!(last_e, 0, "encountered errors when benchmarking");
}

fn ser_json_test(name: &'static str, options: EventSerializerOptions, seconds_to_run: u64) {
    if stop_trace_by_name(name).is_ok() {
        println!("Trace was running, it has been stopped before starting it again.");
    }

    let stats = Arc::new(BenchmarkStatistics::new());

    let mut trace_builder = UserTrace::new().named(name.to_string());
    for guid in BENCHMARK_PROVIDERS {
        let s = stats.clone();
        let opts = options;
        trace_builder = trace_builder.enable(
            Provider::by_guid(*guid)
                .add_callback(move |record, schema_locator| {
                    s.json_callback(record, schema_locator, opts)
                })
                .build(),
        );
    }

    do_benchmark(name, stats, trace_builder, seconds_to_run)
}

fn ser_flexbuffer_test(name: &'static str, options: EventSerializerOptions, seconds_to_run: u64) {
    if stop_trace_by_name(name).is_ok() {
        println!("Trace was running, it has been stopped before starting it again.");
    }

    let stats = Arc::new(BenchmarkStatistics::new());

    let mut trace_builder = UserTrace::new().named(name.to_string());
    for guid in BENCHMARK_PROVIDERS {
        let s = stats.clone();
        let opts = options;
        trace_builder = trace_builder.enable(
            Provider::by_guid(*guid)
                .add_callback(move |record, schema_locator| {
                    s.flexbuffer_callback(record, schema_locator, opts)
                })
                .build(),
        );
    }

    do_benchmark(name, stats, trace_builder, seconds_to_run)
}

const SECONDS_TO_RUN: u64 = 5;

#[test]
fn serialize_json() {
    ser_json_test(
        "ferrisetw-json",
        EventSerializerOptions {
            //include_schema: false,
            //include_header: false,
            //include_extended_data: false,
            //fail_unimplemented: true,
            ..Default::default()
        },
        SECONDS_TO_RUN,
    );
}

#[test]
fn serialize_flexbuffer() {
    ser_flexbuffer_test(
        "ferrisetw-flex",
        EventSerializerOptions {
            //include_schema: false,
            //include_header: false,
            //include_extended_data: false,
            //fail_unimplemented: true,
            ..Default::default()
        },
        SECONDS_TO_RUN,
    );
}
