# Weaklink

Weaklink provides weak dynamic linking for Linux, macOS, and Windows. It allows a program to use a dynamic library
without requiring that library to be installed at startup, and it can accommodate libraries whose exported symbols vary
between versions.

# When is this useful?

Use Weaklink when your program has an optional dependency on a dynamic library or must support multiple versions of that
library. Weaklink handles loading and symbol resolution at runtime, so you do not need to resolve every symbol manually
with `dlopen` and `dlsym` or their platform-specific equivalents.

This allows the host application to degrade gracefully when the library is unavailable or does not export every expected
function symbol, for example by disabling only the features that depend on the missing library or symbols.

# How does it work?

At build time, Weaklink generates a Rust crate containing function stubs for selected symbols in the target dynamic
library. The generated crate is compiled as a static library and linked into your program. When your program calls a stub,
Weaklink loads the target library at runtime, resolves the corresponding symbol, and transfers control to the resolved
function.

This mechanism is similar to the ELF
[Procedure Linkage Table](https://en.wikipedia.org/wiki/Position-independent_code#Dynamic_shared_objects) on Linux and
[Delay-loaded DLLs](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls) on
Windows.

The generated crate also provides a management API for:
- overriding the dynamic library's file name,
- supplying an existing dynamic library handle,
- controlling resolution of symbol groups defined at build time,
- checking whether every symbol in a group was resolved successfully before calling functions that may be unavailable in
  the installed library.

# Limitations

Weaklink supports function symbols only. It cannot transparently link data symbols, such as global variables, because
doing so requires explicit linker support.

To use a data symbol, expose a function that returns the symbol's address and dereference that address in your code.

# Supported platforms:

* Linux: x86_64, arm, aarch64
* MacOS: x86_64, arm64
* Windows: x86_64
