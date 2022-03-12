# framehop

This is a library for stack frame unwinding. It is intended to be used in sampling profilers.

It is very much a work in progress. At the moment, it can unwind on aarch64 and x86_64 on macOS / Linux / Android, using __unwind_info and DWARF CFI (from the eh_frame section).

It would be nice if this library could be used inside the Gecko profiler at some point. For that we'll also want to add x86 support (for 32 bit Linux), EHABI / EXIDX support (for 32 bit Android), and Windows support.

## License

Licensed under either of

  * Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
