//! # Event Windows Tracing FTW!
//! **Basically a [KrabsETW] rip-off written in Rust**, hence the name `Ferris` 🦀
//!
//! All **credits** go to the team at Microsoft who develop KrabsEtw, without it, this project
//! probably wouldn't be a thing.
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
//! finally to consume the events within our own defined callback.
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
//! # Disclaimer
//! This project is still WIP. There's still plenty of things to evaluate/investigate and things to
//! fix and do better. Any help would be greatly appreciated, also any issues you may have!
//!
//! Although I encourage everyone to use Rust, I do believe that, at the moment, if you plan on interacting
//! with ETW in a production level and the programming language is not a constraint you should definitely
//! consider [KrabsETW] as a more robust and tested option. Hopefully in next iterations I'll be able
//! to remove this disclaimer 😃
//!
//! # Getting started
//! If you are familiar with KrabsEtw you'll see using the crate is very similar, in case you are not
//! familiar with it the following example shows the basics on how to build a provider, start a trace
//! and handle the Event in the callback
//!
//! ```
//! use ferrisetw::native::etw_types::EventRecord;
//! use ferrisetw::schema_locator::SchemaLocator;
//! use ferrisetw::parser::Parser;
//! use ferrisetw::parser::TryParse;
//! use ferrisetw::provider::Provider;
//! use ferrisetw::trace::{UserTrace, TraceTrait, TraceBaseTrait};
//!
//! fn process_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
//!     // Within the callback we first locate the proper Schema for the event
//!     match schema_locator.event_schema(record) {
//!         Ok(schema) => {
//!             // At the moment we can only filter by checking the event_id
//!             if record.event_id() == 2 {
//!
//!                 // We build the Parser based on the Schema
//!                 let mut parser = Parser::create(record, &schema);
//!
//!                 // Finally, Parse data from the Event, proper error handling should be done
//!                 // Type annotations or Fully Qualified Syntax are needed when calling TryParse
//!                 // Supported types implement the trait TryParse for Parser
//!
//!                 let process_id: u32 = parser.try_parse("ProcessID").unwrap();
//!                 let image_name: String = parser.try_parse("ImageName").unwrap();
//!                 println!("PID: {} ImageName: {}", process_id, image_name);
//!             }
//!         }
//!         Err(err) => println!("Error {:?}", err),
//!     };
//! }
//!
//! fn main() {
//!     // First we build a Provider
//!     let process_provider = Provider::new()
//!         .by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Microsoft-Windows-Kernel-Process
//!         .add_callback(process_callback)
//!         // .add_filter(event_filters) // it is possible to filter by event ID, process ID, etc.
//!         .build()
//!         .unwrap();
//!
//!     // We start a trace session for the previously registered provider
//!     // This call will spawn a new thread which listens to the events
//!     let mut trace = UserTrace::new()
//!         .named(String::from("MyProvider"))
//!         .enable(process_provider)
//!         // .enable(other_provider) // it is possible to enable multiple providers on the same trace
//!         .start()
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

#[macro_use]
extern crate memoffset;

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate num_derive;
extern crate num_traits;

pub mod native;
pub mod parser;
pub mod property;
pub mod provider;
pub mod schema;
pub mod schema_locator;
pub mod trace;
mod traits;
mod utils;
