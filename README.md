# FerrisETW 🦀
**Basically a [KrabsETW](https://github.com/microsoft/krabsetw/) rip-off written in Rust**, 
hence the name [`Ferris`](https://rustacean.net/) 🦀

All **credits** go to the team at Microsoft who develop KrabsEtw, without it, this project 
probably wouldn't be a thing.

## Motivation
Since lately I've been working very closely with ETW and Rust, I thought that having a tool that
would simplify ETW management written in Rust and available as a crate for other to consume would
be pretty neat and that's where this crate comes into play 🔥

## Examples
You can find a few examples within the [examples](./examples) or the [tests](./tests) folders. If you are familiar with KrabsETW you'll see that is very similar
In case you've never used KrabsETW before, the examples are very straight forward and should be easy to follow. If you have
any issues don't hesitate in asking.

The following snippet shows the basic usage of the library
```rust
fn wmi_callback(record: EventRecord, schema_locator: &mut SchemaLocator) {
    // We locate the Schema for the Event
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            // We filter the event by EventId
            if schema.event_id() == 12 {
                // We obtain the Parser for the Schema
                let mut parser = Parser::create(&schema);
                // We parse the data from the Event based on the names of the fields of the Event
                // Type annotations or Fully Qualified Syntax are needed when calling TryParse
                let op: String = parser
                    .try_parse("Operation")
                    .unwrap_or(String::from("Operation missing"));
                let provider_name: String = parser
                    .try_parse("ProviderName")
                    .unwrap_or(String::from("ProviderName missing"));
                // Could also use String as type
                let provider_guid: GUID =
                    parser.try_parse("ProviderGuid").unwrap_or(GUID::zeroed());
                println!(
                    "WMI-Activity -> ProviderName {}, ProviderGuid: {:?}, Operation: {}",
                    provider_name, provider_guid, op
                );
            }
        }
        Err(err) => println!("Error {:?}", err),
    };
}

fn main() {
    // We first build a Provider
    let wmi_provider = Provider::new()
        .by_guid("1418ef04-b0b4-4623-bf7e-d74ab47bbdaa") // Microsoft-Windows-WMI-Activity
        .add_callback(wmi_callback)
        .build()
        .unwrap();
  
    // We enable the Provider in a new Trace and start the trace
    // This internally will launch a new thread
    let mut trace = UserTrace::new().enable(wmi_provider).start().unwrap();

    std::thread::sleep(Duration::new(20, 0));
  
    // We stop the trace
    trace.stop();
}
```
## Documentation
I'm having some trouble to get docs.rs to build the documentation for the crate so at the moment is being hosted on my domain.
[FerrisETW Doc](https://www.n4r1b.com/doc/ferrisetw/index.html)

## Notes
- The project is still WIP, there's still plenty of things to evaluate/investigate and things to fix and do better.
  Any help would be greatly appreciated, also any issues you may have!

  
- The types available for parsing are those that implement the trait TryParse for Parser, basic types are already
  implemented. In the near future I'll add more :)
  

- I tried to keep dependencies as minimal as possible, also you'll see I went with the new [windows-rs](https://github.com/microsoft/windows-rs) instead of 
  using the [winapi](https://docs.rs/winapi/0.3.9/winapi/). This is a personal decision mainly because I believe the
  Windows bindings is going to be the "standard" to interact with the Windows API in the near future.


- Although I encourage everyone to use Rust, I do believe that, at the moment, if you plan on interacting
  with ETW in a production level and the programming language is not a constraint you should definitely
  go with **KrabsETW** as a more robust and tested option. Hopefully in next iterations I'll be able
  to remove this disclaimer 😃
  
### Acknowledgments
- First of all, the team at MS who develop KrabsETW!! 
- [Shaddy](https://github.com/Shaddy) for, pretty much, teaching me all the Rust I know 😃
