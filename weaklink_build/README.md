# weaklink_build

Build-time code generation for [`weaklink`](https://docs.rs/weaklink). This crate generates Rust source containing
weak-link stubs and the static values used to load a dynamic library and resolve its symbols at runtime.

Add `weaklink_build` as a build dependency and use it from your package's `build.rs` script.

# Workflow

1. Describe each symbol with [`SymbolStub`]. You can list symbols manually or discover them with
   [`exports::dylib_exports`].
2. Create a [`Config`] and organize the symbols into groups with [`Config::add_symbol_group`]. Symbols in a group are
   resolved together at runtime.
3. Call [`Config::generate_source`] to write the generated source into Cargo's `OUT_DIR`.
4. Use `include!` to add that source to your crate.

The generated module exposes one [`weaklink::Library`](https://docs.rs/weaklink/latest/weaklink/struct.Library.html) static,
named by [`Config::name`], and one [`weaklink::Group`](https://docs.rs/weaklink/latest/weaklink/struct.Group.html) static for
each configured symbol group.

## Example

Generate the stubs in `build.rs`:

```rust,no_run
use std::{env, fs::File, path::PathBuf};
use weaklink_build::{Config, SymbolStub};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut config = Config::new("plugin_library");
	config.dylib_names.push("libplugin.so".to_owned());
	config.add_symbol_group("required", [SymbolStub::new("plugin_init")])?;
	config.add_symbol_group("optional", [SymbolStub::new("plugin_extra")])?;

	let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("plugin_stubs.rs");
	config.generate_source(&mut File::create(output)?);
	Ok(())
}
```

Include the generated source in your crate:

```rust,ignore
mod plugin_stubs {
	include!(concat!(env!("OUT_DIR"), "/plugin_stubs.rs"));
}
```

# Discovering symbols

[`exports::dylib_exports`] reads the symbols exported by an ELF, Mach-O, or PE dynamic library. If you only need stubs
for symbols referenced by a static library, use [`imports::archive_imports`] to read its imports and intersect the two
sets by symbol name. Both helpers use the platform-independent [Goblin](https://crates.io/crates/goblin) object parser.
