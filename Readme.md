# framehop

This is a library for stack frame unwinding. It is intended to be used in sampling profilers.

It is very much a work in progress. At the moment, it can only unwind on macOS arm64, using __unwind_info and __eh_frame.
I also intend to add support for macOS x86_64 and ELF x86 / x86_64 soon.

It would be nice if this library could be used inside the Gecko profiler at some point. For that we'll also want to add EHABI / EXIDX support (for Android 32 bit) and Windows support.

## License

Licensed under either of

  * Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
