use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::path::Path;

use goblin::*;

use crate::{Error, SymbolStub};

/// A symbol exported by a dynamic library.
#[derive(Clone, Debug)]
pub struct Export {
    /// Name of the exported symbol.
    ///
    /// Nameless symbols, including ordinal-only exports on Windows, are omitted by [`dylib_exports`].
    pub name: String,

    /// Name of the image section containing the symbol, if it could be determined.
    ///
    /// On macOS, this combines the segment and section names, for example `__TEXT.__text`.
    pub section: Option<String>,
}

/// Reads the symbols exported by the ELF, Mach-O, or PE dynamic library at `path`.
///
/// For a universal Mach-O binary, only the first architecture is inspected.
pub fn dylib_exports(path: &Path) -> Result<Vec<Export>, Error> {
    let mut fd = File::open(path)?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;
    let object = Object::parse(&buffer)?;
    match object {
        Object::Elf(elf) => {
            let mut result = Vec::new();
            for sym in elf.dynsyms.iter().filter(|sym| !sym.is_import()) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        let sec_name = elf.shdr_strtab.get_at(elf.section_headers[sym.st_shndx].sh_name);
                        result.push(Export {
                            name: name.into(),
                            section: sec_name.map(|s| s.into()),
                        });
                    }
                }
            }
            Ok(result)
        }
        Object::Mach(mach) => {
            fn macho_exports(macho: &mach::MachO) -> Result<Vec<Export>, Error> {
                let mut ranges = SectionRanges::new();
                for sec in macho.segments.sections().flatten() {
                    if let Ok((sec, _)) = sec {
                        let seg_name = sec.segname()?;
                        let sec_name = sec.name()?;
                        ranges.insert(sec.offset as u64, sec.size, format!("{}.{}", seg_name, sec_name));
                    }
                }

                match macho.exports() {
                    Ok(exports) => {
                        let mut result = Vec::new();
                        for export in exports {
                            result.push(Export {
                                name: export.name,
                                section: ranges.lookup(export.offset).map(|name| name.into()),
                            });
                        }
                        Ok(result)
                    }
                    Err(err) => Err(err.to_string().into()),
                }
            }

            match mach {
                mach::Mach::Binary(macho) => macho_exports(&macho),
                mach::Mach::Fat(multi) => match multi.get(0) {
                    Ok(mach::SingleArch::MachO(macho)) => macho_exports(&macho),
                    Ok(mach::SingleArch::Archive(_)) => {
                        Err(format!("The first object in a multiarch binary is not MachO").into())
                    }
                    Err(err) => Err(err.to_string().into()),
                },
            }
        }
        Object::PE(pe) => {
            let mut ranges = SectionRanges::new();
            for sec in pe.sections {
                ranges.insert(sec.virtual_address as u64, sec.virtual_size as u64, sec.name()?.into());
            }

            let mut result = Vec::new();
            for export in &pe.exports {
                if let Some(name) = export.name {
                    result.push(Export {
                        name: name.into(),
                        section: ranges.lookup(export.rva as u64).map(|name| name.into()),
                    })
                }
            }
            Ok(result)
        }
        _ => Err(format!("Unsupported object type: {object:?}").into()),
    }
}

struct SectionRanges {
    ranges: Vec<(Range<u64>, String)>,
}

impl SectionRanges {
    fn new() -> SectionRanges {
        SectionRanges { ranges: Vec::new() }
    }

    fn insert(&mut self, offset: u64, size: u64, name: String) {
        let idx = self.ranges.partition_point(|s| s.0.start < offset);
        self.ranges.insert(idx, (offset..offset + size, name));
    }

    fn lookup(&self, offset: u64) -> Option<&str> {
        let idx = self.ranges.partition_point(|s| s.0.start < offset);
        if idx > 0 && self.ranges[idx - 1].0.contains(&offset) {
            Some(&self.ranges[idx - 1].1)
        } else {
            None
        }
    }
}
