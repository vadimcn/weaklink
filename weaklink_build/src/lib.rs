#![allow(unused)]
#![doc = include_str!("../README.md")]

macro_rules! write_lines {
    ($dest:expr, $($line:literal)+ $(, $name:ident=$value:expr)*) => (write!($dest, concat!($($line,"\n"),+) $(, $name=$value)*))
}

pub mod exports;
pub mod imports;
mod stub_gen;
mod util;

use std::borrow::{Cow, ToOwned};
use std::collections::{hash_map::Entry, HashMap};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::{env, fmt};

use util::iter_fmt;

use crate::stub_gen::TargetOs;

type Error = Box<dyn std::error::Error>;

/// Describes one symbol stub to generate.
///
/// A stub exports [`SymbolStub::export_name`] to the consuming program and resolves [`SymbolStub::import_name`] in the
/// target dynamic library.
#[derive(Clone, Default, Debug)]
pub struct SymbolStub {
    /// The symbol name to resolve in the target dynamic library.
    pub import_name: String,
    /// The symbol name exported by the generated stub.
    pub export_name: String,
    /// Whether to generate an accessor that returns the resolved address instead of a function jump stub.
    pub is_data: bool,
}

impl SymbolStub {
    /// Creates a function stub that exports and resolves `name`.
    pub fn new(name: &str) -> SymbolStub {
        SymbolStub {
            import_name: name.to_string(),
            export_name: name.to_string(),
            is_data: false,
        }
    }

    /// Creates an accessor stub named `exp_name` for the data symbol `imp_name`.
    ///
    /// Calling the generated accessor returns the address of `imp_name` in the target dynamic library.
    pub fn new_data(exp_name: &str, imp_name: &str) -> SymbolStub {
        SymbolStub {
            export_name: exp_name.to_string(),
            import_name: imp_name.to_string(),
            is_data: true,
        }
    }
}

/// Configures source generation for one weakly linked dynamic library.
pub struct Config {
    /// Name of the generated [`weaklink::Library`] static.
    pub name: String,
    /// Rust target triple for which stubs are generated.
    pub target: String,
    /// Candidate dynamic-library names tried by [`weaklink::Library::load`], in order.
    pub dylib_names: Vec<String>,
    /// Whether to adjust generated symbol names for platform ABI conventions.
    ///
    /// Currently this includes adapting Mach-O symbol names for Apple's
    /// [`dlsym`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlsym.3.html#//apple_ref/doc/man/3/dlsym),
    /// which expects names without the ABI's leading underscore.
    pub adjust_symbol_names: bool,

    // The list of symbol stubs created so far.
    stubs: Vec<SymbolStub>,
    // Look up index in `stubs` by the export name.
    stub_by_exp: HashMap<String, usize>,
    // Group name => stub indices in `stubs`.
    groups: HashMap<String, Vec<usize>>,
}

impl Config {
    /// Creates a build configuration with the following defaults:
    ///
    /// - [`name`](`Config::name`): The `name` parameter.
    /// - [`target`](`Config::target`): Cargo's `TARGET`, or the host target outside a Cargo build script.
    /// - [`dylib_names`](`Config::dylib_names`): An empty list.
    /// - [`adjust_symbol_names`](`Config::adjust_symbol_names`): `true`.
    pub fn new(name: &str) -> Self {
        let target = match env::var("TARGET") {
            Ok(target) => target,
            Err(_) => env!("TARGET").to_string(), // Fall back to host target
        };

        Config {
            name: name.into(),
            target: target,
            dylib_names: vec![],
            adjust_symbol_names: true,
            stubs: Vec::new(),
            stub_by_exp: HashMap::new(),
            groups: HashMap::new(),
        }
    }

    /// Adds a named group of symbols that will be resolved together at runtime.
    ///
    /// A symbol may belong to more than one group. If it does, its [`SymbolStub::import_name`] and
    /// [`SymbolStub::is_data`] values must be identical in every group.
    ///
    /// Returns an error if `group_name` already exists or a symbol conflicts with an earlier definition.
    pub fn add_symbol_group<'a>(
        &mut self,
        group_name: &str,
        symbols: impl IntoIterator<Item = SymbolStub>,
    ) -> Result<(), Error> {
        if let Some(_) = self.groups.get(group_name) {
            Err(format!("Group \"{group_name}\" already exists"))?;
        }
        let mut group_syms = Vec::new();
        for symbol in symbols {
            let sym_idx = match self.stub_by_exp.entry(symbol.export_name.clone()) {
                Entry::Occupied(o) => {
                    let idx = *o.get();
                    let existing = &self.stubs[idx];
                    if existing.is_data != symbol.is_data {
                        return Err(format!(
                            "Stub for symbol '{}' already exists, but with a different `is_data` value: {}",
                            existing.export_name, existing.is_data
                        )
                        .into());
                    }
                    if self.stubs[idx].import_name != symbol.import_name {
                        return Err(format!(
                            "Stub for symbol '{}' already exists, but with a different `import_name` value: {}",
                            existing.export_name, existing.import_name
                        )
                        .into());
                    }
                    idx
                }
                Entry::Vacant(v) => {
                    let idx = self.stubs.len();
                    self.stubs.push(symbol);
                    v.insert(idx);
                    idx
                }
            };
            group_syms.push(sym_idx);
        }
        self.groups.insert(group_name.to_string(), group_syms);
        Ok(())
    }

    /// Writes the generated Rust source and assembly stubs to `text`.
    ///
    /// The output is intended to be included in the consuming crate with `include!`.
    ///
    /// # Panics
    ///
    /// Panics if [`Config::target`] specifies an unsupported operating system or architecture.
    pub fn generate_source(&self, text: &mut dyn Write) {
        // Adjust names for MacOS ABI
        let mut stubs = Cow::from(&self.stubs);
        if self.adjust_symbol_names && self.target.contains("-apple-") {
            let new_stubs = self
                .stubs
                .iter()
                .map(|stub| {
                    let mut stub = stub.clone();
                    if !stub.is_data && stub.export_name == stub.import_name {
                        if stub.export_name.starts_with('_') {
                            stub.import_name.remove(0);
                        } else {
                            stub.export_name.insert(0, '_');
                        }
                    }
                    stub
                })
                .collect::<Vec<_>>();
            stubs = Cow::from(new_stubs);
        }

        // Header
        write_lines!(text,
            "#[allow(unused_imports)]"
            "use weaklink::{{Library, Group, Address}};"
            "use core::arch::global_asm;"
            "use std::ffi::CStr;"
        );

        // Declare symbol table (will be defined by StubGenerator)
        let sym_table = format!("symbol_table_{:08x}", rand::random::<u64>());
        write_lines!(text,
            "extern \"C\" {{"
            "    static {sym_table}: [Address; {size}];"
            "}}",
            sym_table=sym_table,
            size=stubs.len()
        );

        // Emit library object
        write_lines!(text,
            "#[no_mangle]"
            "#[allow(non_upper_case_globals)]"
            "pub static {name}: Library = Library::new("
            "    &[{dylib_names}],"
            "    unsafe {{ &[\n{symbol_names}] }},"
            "    unsafe {{ &{sym_table} }},"
            ");",
            name = self.name,
            dylib_names = iter_fmt(&self.dylib_names, |f, name| write!(f, "\"{name}\",")),
            symbol_names = iter_fmt(stubs.as_ref().iter().enumerate(), |f, (i, sym)|
                writeln!(f, "      CStr::from_bytes_with_nul_unchecked(b\"{}\\0\"), // {i}", sym.import_name)),
            sym_table=sym_table
        );

        // Emit group objects
        for (grp_name, indices) in &self.groups {
            let mut indices = indices.clone();
            indices.sort();
            write_lines!(text,
                "#[no_mangle]"
                "#[allow(non_upper_case_globals)]"
                "pub static {grp_name}: Group = Group::new("
                "    \"{grp_name}\","
                "    &{name},"
                "    &[{indices}],"
                ");",
                name = self.name,
                grp_name = grp_name,
                indices = iter_fmt(indices, |f, idx| write!(f, "{idx},"))
            );
        }

        let target_os = if self.target.contains("linux") {
            TargetOs::Linux
        } else if self.target.contains("apple") {
            TargetOs::MacOS
        } else if self.target.contains("windows") {
            TargetOs::Windows
        } else {
            panic!("Unsupported OS");
        };

        // Emit symbol table and PLT
        let stub_gen: Box<dyn stub_gen::StubGenerator> = if self.target.starts_with("x86_64-") {
            Box::new(stub_gen::x64::X64StubGenerator { target_os })
        } else if self.target.starts_with("aarch64-") {
            Box::new(stub_gen::aarch64::Aarch64StubGenerator { target_os })
        } else if self.target.starts_with("arm") {
            Box::new(stub_gen::arm::ArmStubGenerator {})
        } else {
            panic!("Unsupported arch");
        };

        stub_gen.generate(text, stubs.as_ref(), &sym_table);
    }
}
