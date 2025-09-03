use crate::{Error, Library};
use std::{
    mem,
    sync::atomic::{AtomicU8, Ordering},
};

/// A build-time-defined set of symbols that are resolved together.
#[repr(C)]
pub struct Group {
    name: &'static str,
    library: &'static Library,
    sym_indices: &'static [u32],
    status: AtomicU8,
}

/// Not yet attempted to resolve
const GROUP_STATUS_UNKNOWN: u8 = 0;
/// All symbols have been resolved successfuly
const GROUP_STATUS_RESOLVED: u8 = 1;
/// At least one symbol could not be resolved
const GROUP_STATUS_FAILED: u8 = 2;

impl Group {
    #[doc(hidden)]
    pub const fn new(name: &'static str, library: &'static Library, sym_indices: &'static [u32]) -> Group {
        Group {
            name,
            library,
            sym_indices,
            status: AtomicU8::new(GROUP_STATUS_UNKNOWN),
        }
    }

    /// Resolves every symbol in the group.
    ///
    /// On success, returns a [`GroupResolved`] token. In [checked mode](index.html#checked-mode), the group's symbols
    /// remain callable while at least one token covering them is alive. Without checked mode, successful resolution is
    /// cached permanently. Failed resolution is cached in both modes.
    pub fn resolve(&self) -> Result<GroupResolved, Error> {
        let is_resolved = match self.status.load(Ordering::Acquire) {
            GROUP_STATUS_UNKNOWN => {
                for sym_index in self.sym_indices {
                    if let Err(err) = self.library.resolve_symbol(*sym_index) {
                        // Cache failed status
                        self.status.store(GROUP_STATUS_FAILED, Ordering::Release);
                        return Err(err);
                    }
                }
                // In checked mode we can't cache the "resolved" state, as the symbol table entries
                // will be reset to null upon dropping the token.
                #[cfg(not(feature = "checked"))]
                self.status.store(GROUP_STATUS_RESOLVED, Ordering::Release);
                true
            }
            GROUP_STATUS_RESOLVED => true,
            GROUP_STATUS_FAILED | _ => false,
        };
        if is_resolved {
            self.library.assert_resolved(self.sym_indices);
            Ok(GroupResolved(self))
        } else {
            Err(format!("Group {} could not be resolved", self.name).into())
        }
    }

    /// Forces the group into the failed state without attempting symbol resolution.
    ///
    /// This is intended for testing fallback paths in [checked mode](index.html#checked-mode). Future calls to
    /// [`Group::resolve`] return an error.
    pub fn mark_failed(&self) {
        self.status.store(GROUP_STATUS_FAILED, Ordering::Release);
    }
}

/// A token proving that a [`Group`] was resolved successfully.
///
/// In [checked mode](index.html#checked-mode), keep this token alive while calling functions whose symbols belong to the
/// group. Dropping the last token that covers a symbol clears its stub pointer.
pub struct GroupResolved<'a>(&'a Group);

impl<'a> GroupResolved<'a> {
    /// Keeps the group's symbols resolved permanently.
    ///
    /// This consumes the token without releasing its resolution assertion. It is intended for required symbol groups
    /// that remain in use for the lifetime of the process.
    pub fn mark_permanent(self) {
        mem::forget(self);
    }
}

impl<'a> Drop for GroupResolved<'a> {
    fn drop(&mut self) {
        self.0.library.deassert_resolved(self.0.sym_indices);
    }
}
