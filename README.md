# FerrisETW 🦀

This crate provides safe Rust abstractions over the ETW consumer APIs.

It started as a [KrabsETW](https://github.com/microsoft/krabsetw/) rip-off written in Rust (hence the name [`Ferris`](https://rustacean.net/) 🦀).
All credits go to the team at Microsoft who develop KrabsEtw, without it, this project probably wouldn't be a thing.<br/>
Since version 1.0, the API and internal architecture of this crate is slightly diverging from `krabsetw`, so that it is more Rust-idiomatic.

## Examples
You can find a examples within the
  [crate documentation on doc.rs](https://docs.rs/ferrisetw),
  as well as the [examples](./examples) and the [tests](./tests) folders.

If you are familiar with KrabsETW you'll see that is very similar.
In case you've never used KrabsETW before, the examples are very straight forward and should be easy to follow. If you have any issues don't hesitate in asking.

## Documentation
This crate is documented at [docs.rs](https://docs.rs/crate/ferrisetw/latest).

## Notes
- The project is still WIP.
  Feel free to report bugs, issues, feature requests, etc.
  Of course, contributing will be happily accepted!


- The types available for parsing are those that implement the trait TryParse for Parser, basic types are already
  implemented. In the near future I'll add more :)


- I tried to keep dependencies as minimal as possible, also you'll see I went with the new [windows-rs](https://github.com/microsoft/windows-rs) instead of
  using the [winapi](https://docs.rs/winapi/0.3.9/winapi/). This is a personal decision mainly because I believe the
  Windows bindings is going to be the "standard" to interact with the Windows API in the near future.


### Acknowledgments
- First of all, the team at MS who develop KrabsETW!!
- [Shaddy](https://github.com/Shaddy) for, pretty much, teaching me all the Rust I know 😃
- [n4r1b](https://github.com/n4r1b) for creating this great crate
- [daladim](https://github.com/daladim) for adding even more features
