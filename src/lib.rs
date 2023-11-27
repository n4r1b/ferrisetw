//! # Event Windows Tracing FTW!
//! This crate provides safe Rust abstractions over the ETW consumer APIs.
//!
//! It started as a [KrabsETW](https://github.com/microsoft/krabsetw/) rip-off written in Rust (hence the name [`Ferris`](https://rustacean.net/) 🦀).
//! All credits go to the team at Microsoft who develop KrabsEtw, without it, this project probably wouldn't be a thing.<br/>
//! Since version 1.0, the API and internal architecture of this crate is slightly diverging from `krabsetw`, so that it is more Rust-idiomatic.
//!
//! # What's ETW
//! Event Tracing for Windows (ETW) is an efficient kernel-level tracing facility that lets you log
//! kernel or application-defined events to a log file. You can consume the events in real time or
//! from a log file and use them to debug an application or to determine where performance issues
//! are occurring in the application. [Source]
//!
//! ETW is made out of three components:
//! * Controllers
//! * Providers
//! * Consumers
//!
//! This crate provides the means to start and stop a controller, enable/disable providers and
//! finally to consume the events within our own defined callback.<br/>
//! It is also able to process events from a file instead of a real-time trace session.
//!
//! # Motivation
//! Even though ETW is a extremely powerful tracing mechanism, interacting with it is not easy by any
//! means. There's a lot of details and caveats that have to be taken into consideration in order
//! to make it work. On the other hand, once we manage to start consuming a trace session in real-time
//! we have to deal with the process of finding the Schema and parsing the properties. All this process
//! can be tedious and cumbersome, therefore tools like KrabsETW come in very handy to simplify the
//! interaction with ETW.
//!
//! Since lately I've been working very closely with ETW and Rust, I thought that having a tool that
//! would simplify ETW management written in Rust and available as a crate for other to consume would
//! be pretty neat and that's where this crate comes into play 🔥
//!
//! # Getting started
//! If you are familiar with KrabsEtw you'll see using the crate is very similar, in case you are not
//! familiar with it the following example shows the basics on how to build a provider, start a trace
//! and handle the Event in the callback
//!
//! ```
//! use ferrisetw::EventRecord;
//! use ferrisetw::schema_locator::SchemaLocator;
//! use ferrisetw::parser::Parser;
//! use ferrisetw::provider::Provider;
//! use ferrisetw::trace::{UserTrace, TraceTrait};
//!
//! fn process_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
//!     // Basic event scrutinizing can be done directly from the `EventRecord`
//!     if record.event_id() == 2 {
//!         // More advanced info can be retrieved from the event schema
//!         // (the SchemaLocator caches the schema for a given kind of event, so this call is cheap in case you've already encountered the same event kind previously)
//!         match schema_locator.event_schema(record) {
//!             Err(err) => println!("Error {:?}", err),
//!             Ok(schema) => {
//!                 println!("Received an event from provider {}", schema.provider_name());
//!
//!                 // Finally, properties for a given event can be retrieved using a Parser
//!                 let parser = Parser::create(record, &schema);
//!
//!                 // You'll need type inference to tell ferrisetw what type you want to parse into
//!                 // In actual code, be sure to correctly handle Err values!
//!                 let process_id: u32 = parser.try_parse("ProcessID").unwrap();
//!                 let image_name: String = parser.try_parse("ImageName").unwrap();
//!                 println!("PID: {} ImageName: {}", process_id, image_name);
//!             }
//!         }
//!     }
//! }
//!
//! fn main() {
//!     // First we build a Provider
//!     let process_provider = Provider
//!         ::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Microsoft-Windows-Kernel-Process
//!         .add_callback(process_callback)
//!         // .add_callback(process_callback) // it is possible to add multiple callbacks for a given provider
//!         // .add_filter(event_filters)      // it is possible to filter by event ID, process ID, etc.
//!         .build();
//!
//!     // We start a real-time trace session for the previously registered provider
//!     // Callbacks will be run in a separate thread.
//!     let mut trace = UserTrace::new()
//!         .named(String::from("MyTrace"))
//!         .enable(process_provider)
//!         // .enable(other_provider) // It is possible to enable multiple providers on the same trace.
//!         // .set_etl_dump_file(...) // It is possible to dump the events that the callbacks are processing into a file
//!         .start_and_process()       // This call will spawn the thread for you.
//!                                    // See the doc for alternative ways of processing the trace,
//!                                    // with more or less flexibility regarding this spawned thread.
//!         .unwrap();
//!
//!     std::thread::sleep(std::time::Duration::from_secs(3));
//!
//!     // We stop the trace
//!     trace.stop();
//! }
//! ```
//!
//! [KrabsETW]: https://github.com/microsoft/krabsetw/
//! [Source]: https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing
//!
//! # Log messages
//! ferrisetw may (very) occasionally write error log messages using the [`log`](https://docs.rs/log/latest/log/) crate.<br/>
//! In case you want them to be printed to the console, your binary should use one of the various logger implementations. [`env_logger`](https://docs.rs/env_logger/latest/env_logger/) is one of them.<br/>
//! You can have a look at how to use it in the `examples/` folder in the GitHub repository.

#[macro_use]
extern crate memoffset;

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate num_derive;
extern crate num_traits;

pub mod native;
pub mod parser;
mod property;
pub mod provider;
pub mod query;
pub mod schema;
pub mod schema_locator;
pub mod ser;
pub mod trace;
mod traits;
mod utils;

pub(crate) type EtwCallback = Box<dyn FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static>;

// Convenience re-exports.
pub use crate::native::etw_types::event_record::EventRecord;
pub use crate::schema_locator::SchemaLocator;
#[cfg(feature = "serde")]
pub use crate::ser::{EventSerializer, EventSerializerOptions};
pub use crate::trace::FileTrace;
pub use crate::trace::KernelTrace;
pub use crate::trace::UserTrace;

// These types are returned by some public APIs of this crate.
// They must be re-exported, so that users of the crate have a way to avoid version conflicts
// (see https://github.com/n4r1b/ferrisetw/issues/46)
/// Re-exported `GUID` from `windows-rs`, which is used in return values for some functions of this crate
pub use windows::core::GUID;
/// Re-exported `SID` from `windows-rs`, which is used in return values for some functions of this crate
pub use windows::Win32::Security::SID;
