//! Use the DNS provider to test a few things regarding user traces

use std::time::Duration;

use ferrisetw::provider::{Provider, EventFilter};
use ferrisetw::native::etw_types::EventRecord;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::parser::{Parser, TryParse};
use ferrisetw::trace::KernelTrace;
use ferrisetw::provider::kernel_providers;

use windows::Win32::Foundation::HANDLE;
use windows::core::HSTRING;
use windows::Win32::System::LibraryLoader::{LOAD_LIBRARY_FLAGS, LoadLibraryExW};


mod utils;
use utils::{Status, TestKind};

const TEST_LIBRARY_NAME: &str = "crypt32.dll"; // this DLL is available on all Windows versions (so that the test can run everywhere)



#[test]
fn kernel_trace_tests() {
    simple_kernel_trace_trace();
}

fn simple_kernel_trace_trace() {
    let passed1 = Status::new(TestKind::ExpectSuccess);
    let notifier1 = passed1.notifier();

    println!("We are process {}", std::process::id());
    let our_process_only = EventFilter::ByPids(vec![std::process::id() as _]);

    let kernel_provider = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
        .add_filter(our_process_only)
        .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
            let schema = schema_locator.event_schema(record).unwrap();
            let parser = Parser::create(record, &schema);

            // By-PID filters are not working (yet?)
            // See See https://github.com/n4r1b/ferrisetw/issues/51
            // if has_seen_other_pid(record) {
            //     notifier2.notify_failure();
            // }
            if has_seen_dll_load(record, &parser) {
                notifier1.notify_success();
            }

        })
        .build();

    let mut _kernel_trace = KernelTrace::new()
        .enable(kernel_provider)
        .start_and_process()
        .unwrap();

    generate_image_load_events();

    passed1.assert_passed();
    println!("Test passed");
}

fn load_library(libname: &str) {
    let widename = HSTRING::from(libname);

    // Safety: LoadLibraryExW expects a valid string in lpLibFileName.
    let res = unsafe {
            LoadLibraryExW(
            &widename,
            HANDLE::default(),
            LOAD_LIBRARY_FLAGS::default(),
        )
    };

    res.unwrap();
}

fn generate_image_load_events() {
    std::thread::sleep(Duration::from_secs(1));
    println!("Will load a specific DLL...");
    load_library(TEST_LIBRARY_NAME);
    println!("Loading done.");
}



fn has_seen_dll_load(record: &EventRecord, parser: &Parser) -> bool {
    if record.process_id() == std::process::id() {
        let filename: Result<String, _> = parser.try_parse("FileName");
        println!("   this one's for us: {:?}", filename);
        if let Ok(filename) = filename {
            if filename.ends_with(TEST_LIBRARY_NAME) {
                return true;
            }
        }
    }

    false
}

