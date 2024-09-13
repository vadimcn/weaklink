use std::fmt::format;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use goblin::*;
use superslice::Ext;

use crate::{Error, SymbolStub};

pub struct Export {
    /// Name of the exported symbol.
    ///
    /// Name-less symbols (including ordinal exports on Windows) will be skipped.
    pub name: String,

    /// Image section name, or `None` if the export could not be mapped to any image section (unusual).
    ///
    /// On MacOS this will contain a combination of segment and section names, e.g. "__TEXT.__text".
    pub section: Option<String>,
}

/// Returns the list of symbols exported from a dynamic library.
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
    ranges: Vec<(u64, u64, String)>,
}

impl SectionRanges {
    fn new() -> SectionRanges {
        SectionRanges { ranges: Vec::new() }
    }

    fn insert(&mut self, offset: u64, size: u64, name: String) {
        let idx = self.ranges.lower_bound_by_key(&offset, |s| s.0);
        self.ranges.insert(idx, (offset, size, name));
    }

    fn lookup(&self, offset: u64) -> Option<&str> {
        let idx = self.ranges.upper_bound_by_key(&offset, |s| s.0);
        if idx > 0 && self.ranges[idx - 1].0 + self.ranges[idx - 1].1 > offset {
            Some(&self.ranges[idx - 1].2)
        } else {
            None
        }
    }
}
