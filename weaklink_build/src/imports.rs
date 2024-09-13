use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use goblin::*;

use crate::{Error, SymbolStub};

pub struct Import {
    pub name: String,
}

/// Returns the list of symbols imported by a static library.
pub fn archive_imports(path: &Path) -> Result<Vec<Import>, Error> {
    let mut fd = File::open(path)?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;

    let mut imports = HashSet::new();
    get_unique_imports(&buffer, &mut imports)?;
    Ok(imports.into_iter().map(|s| Import { name: s }).collect())
}

fn get_unique_imports(buffer: &[u8], imports: &mut HashSet<String>) -> Result<(), Error> {
    let object = Object::parse(&buffer)?;
    match object {
        Object::Archive(archive) => {
            for mbr_name in archive.members() {
                if let Ok(slice) = archive.extract(mbr_name, &buffer) {
                    get_unique_imports(slice, imports)?;
                }
            }
            Ok(())
        }
        Object::Elf(elf) => {
            for (_, rsection) in &elf.shdr_relocs {
                for reloc in rsection {
                    if let Some(sym) = elf.syms.get(reloc.r_sym) {
                        if sym.is_import() {
                            if let Some(sym_name) = elf.strtab.get_at(sym.st_name) {
                                imports.insert(sym_name.into());
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        Object::Mach(mach) => {
            fn macho_imports(macho: &mach::MachO, imports: &mut HashSet<String>) -> Result<(), Error> {
                match macho.symbols.as_ref() {
                    Some(symbols) => match macho.relocations() {
                        Ok(relocations) => {
                            for (_, reloc_iter, _) in relocations {
                                for reloc in reloc_iter {
                                    let reloc = reloc?;
                                    if reloc.is_extern() {
                                        let (name, _) = symbols.get(reloc.r_symbolnum())?;
                                        imports.insert(name.into());
                                    }
                                }
                            }
                            Ok(())
                        }
                        Err(err) => Err(err.to_string().into()),
                    },
                    None => Ok(()),
                }
            }

            match mach {
                mach::Mach::Binary(macho) => macho_imports(&macho, imports),
                mach::Mach::Fat(multi) => match multi.get(0) {
                    Ok(mach::SingleArch::MachO(macho)) => macho_imports(&macho, imports),
                    Ok(mach::SingleArch::Archive(_)) => {
                        Err(format!("The first object in a multiarch binary is not MachO").into())
                    }
                    Err(err) => Err(err.to_string().into()),
                },
            }
        }
        Object::COFF(coff) => {
            if let Ok(Some(strtab)) = coff.header.strings(buffer) {
                if let Ok(Some(symtab)) = coff.header.symbols(buffer) {
                    for (index, _, sym) in symtab.iter() {
                        if sym.section_number == pe::symbol::IMAGE_SYM_UNDEFINED {
                            let sym_name = sym.name(&strtab)?;
                            imports.insert(sym_name.into());
                        }
                    }
                }
            }
            Ok(())
        }
        _ => Err(format!("Unsupported object type: {object:?}").into()),
    }
}
