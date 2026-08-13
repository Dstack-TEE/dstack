// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! CPU hotplug scaffolding: the `PRES` register window and the `CPUS`
//! container with one processor object per possible CPU.
//!
//! This is QEMU's `build_cpus_aml()` (`hw/acpi/cpu.c`). The two devices are
//! emitted bare here; the caller wraps them in `Scope (_SB)`.
//!
//! ```asl
//! Device (\_SB.PCI0.PRES) {
//!     Name (_HID, EisaId ("PNP0A06"))
//!     Name (_UID, "CPU Hotplug resources")
//!     Mutex (CPLK, 0x00)
//!     Name (_CRS, ResourceTemplate () {
//!         IO (Decode16, 0x0CD8, 0x0CD8, 0x01, 0x0C)
//!     })
//!     OperationRegion (PRST, SystemIO, 0x0CD8, 0x0C)
//!     Field (PRST, ByteAcc, NoLock, WriteAsZeros) {
//!         Offset (0x04), CPEN, 1, CINS, 1, CRMV, 1, CEJ0, 1, CEJF, 1,
//!         Offset (0x05), CCMD, 8
//!     }
//!     Field (PRST, DWordAcc, NoLock, Preserve) {
//!         CSEL, 32, Offset (0x08), CDAT, 32
//!     }
//! }
//! Device (\_SB.CPUS) {
//!     Name (_HID, "ACPI0010")
//!     Name (_CID, EisaId ("PNP0A05"))
//!     Method (CTFY, 2, NotSerialized) {
//!         If ((Arg0 == Zero)) { Notify (C000, Arg1) }
//!     }
//!     Method (CSTA, 1, Serialized) {
//!         Acquire (\_SB.PCI0.PRES.CPLK, 0xFFFF)
//!         \_SB.PCI0.PRES.CSEL = Arg0
//!         Local0 = Zero
//!         If ((\_SB.PCI0.PRES.CPEN == One)) { Local0 = 0x0F }
//!         Release (\_SB.PCI0.PRES.CPLK)
//!         Return (Local0)
//!     }
//!     Method (CEJ0, 1, Serialized) {
//!         Acquire (\_SB.PCI0.PRES.CPLK, 0xFFFF)
//!         \_SB.PCI0.PRES.CSEL = Arg0
//!         \_SB.PCI0.PRES.CEJ0 = One
//!         Release (\_SB.PCI0.PRES.CPLK)
//!     }
//!     Method (CSCN, 0, Serialized) {
//!         Acquire (\_SB.PCI0.PRES.CPLK, 0xFFFF)
//!         Name (CNEW, Package (0xFF) {})
//!         Name (CEJL, Package (0xFF) {})
//!         Local3 = Zero
//!         Local4 = One
//!         While ((Local4 == One)) {
//!             Local4 = Zero
//!             Local0 = One
//!             Local1 = Zero
//!             Local5 = Zero
//!             While (((Local0 == One) && (Local3 < One))) {
//!                 Local0 = Zero
//!                 \_SB.PCI0.PRES.CSEL = Local3
//!                 \_SB.PCI0.PRES.CCMD = Zero
//!                 If ((\_SB.PCI0.PRES.CDAT < Local3)) { Break }
//!                 If (((Local1 == 0xFF) || (Local5 == 0xFF))) {
//!                     Local4 = One
//!                     Break
//!                 }
//!                 Local3 = \_SB.PCI0.PRES.CDAT
//!                 If ((\_SB.PCI0.PRES.CINS == One)) {
//!                     CNEW [Local1] = Local3
//!                     Local1++
//!                     Local0 = One
//!                 }
//!                 If ((\_SB.PCI0.PRES.CRMV == One)) {
//!                     CEJL [Local5] = Local3
//!                     Local5++
//!                     Local0 = One
//!                 }
//!                 Local3++
//!             }
//!             Local2 = Zero
//!             While ((Local2 < Local1)) {
//!                 Local3 = DerefOf (CNEW [Local2])
//!                 CTFY (Local3, One)
//!                 Debug = Local3
//!                 \_SB.PCI0.PRES.CSEL = Local3
//!                 \_SB.PCI0.PRES.CINS = One
//!                 Local2++
//!             }
//!             Local2 = Zero
//!             While ((Local2 < Local5)) {
//!                 Local3 = DerefOf (CEJL [Local2])
//!                 CTFY (Local3, 0x03)
//!                 \_SB.PCI0.PRES.CSEL = Local3
//!                 \_SB.PCI0.PRES.CRMV = One
//!                 Local2++
//!             }
//!         }
//!         Release (\_SB.PCI0.PRES.CPLK)
//!     }
//!     Method (COST, 4, Serialized) {
//!         Acquire (\_SB.PCI0.PRES.CPLK, 0xFFFF)
//!         \_SB.PCI0.PRES.CSEL = Arg0
//!         \_SB.PCI0.PRES.CCMD = One
//!         \_SB.PCI0.PRES.CDAT = Arg1
//!         \_SB.PCI0.PRES.CCMD = 0x02
//!         \_SB.PCI0.PRES.CDAT = Arg2
//!         Release (\_SB.PCI0.PRES.CPLK)
//!     }
//!     Processor (C000, 0x00, 0x00000000, 0x00) {
//!         Method (_STA, 0, Serialized) { Return (CSTA (Zero)) }
//!         Name (_MAT, Buffer (0x08) { 0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 })
//!         Method (_OST, 3, Serialized) { COST (Zero, Arg0, Arg1, Arg2) }
//!     }
//! }
//! ```

use acpi_tables::aml::{
    Acquire, Arg, DeRefOf, Device, EISAName, Else, Equal, Field, FieldAccessType, FieldEntry,
    FieldLockRule, FieldUpdateRule, If, Index, LessThan, Local, Method, MethodCall, Mutex, Name,
    Notify, One, OpRegion, OpRegionSpace, Path, Release, ResourceTemplate, Return, Store, While,
    Zero, IO,
};
use acpi_tables::{Aml, AmlSink};

use super::ops::{emit, pkg_length, Increment, Raw};
use crate::Error;

/// Base of the CPU hotplug register block (`ACPI_CPU_HOTPLUG_BASE`) and its
/// length (`ACPI_CPU_HOTPLUG_REG_LEN`).
const HOTPLUG_BASE: u16 = 0x0cd8;
const HOTPLUG_LEN: u8 = 12;

/// Largest number of CPUs one scan pass can collect: the ACPI 1.0 `Package`
/// the scan method uses to cache them holds at most 255 elements.
const MAX_CPUS_PER_PASS: u8 = 255;

/// `CPHP_GET_NEXT_CPU_WITH_EVENT_CMD`, `CPHP_OST_EVENT_CMD`,
/// `CPHP_OST_STATUS_CMD`: the values written to the command register.
const CMD_GET_NEXT_CPU: u8 = 0;
const CMD_OST_EVENT: u8 = 1;
const CMD_OST_STATUS: u8 = 2;

/// `Notify()` reason codes: device check (a CPU appeared) and eject request.
const DEVICE_CHECK: u8 = 1;
const EJECT_REQUEST: u8 = 3;

/// Device holding the hotplug registers. Every field below is addressed
/// through its full path, because the methods that use them live in a
/// sibling device.
const RES: &str = "\\_SB_.PCI0.PRES";

/// Path of one register field inside the hotplug resource device.
fn res(field: &str) -> Path {
    Path::new(&format!("{RES}.{field}"))
}

pub(crate) fn build(
    cpu_count: u32,
    numa: bool,
    initialize_selector: bool,
    queued_eject: bool,
) -> Result<Vec<u8>, Error> {
    let mut out = resource_device(initialize_selector);
    out.extend(cpus_device(cpu_count, numa, queued_eject)?);
    Ok(out)
}

/// `Device (\_SB.PCI0.PRES)`: the I/O window plus the fields overlaid on it.
fn resource_device(initialize_selector: bool) -> Vec<u8> {
    let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0A06"));
    let uid = Name::new(Path::new("_UID"), &"CPU Hotplug resources");
    let lock = Mutex::new(Path::new("CPLK"), 0);

    let io = IO::new(HOTPLUG_BASE, HOTPLUG_BASE, 1, HOTPLUG_LEN);
    let crs = Name::new(Path::new("_CRS"), &ResourceTemplate::new(vec![&io]));

    let region = OpRegion::new(
        Path::new("PRST"),
        OpRegionSpace::SystemIO,
        &HOTPLUG_BASE,
        &HOTPLUG_LEN,
    );

    // Flag bits, byte-accessed: one bit each for enabled, insert event,
    // remove event, eject request and firmware-eject request, then the
    // command register.
    let flags = Field::new(
        Path::new("PRST"),
        FieldAccessType::Byte,
        FieldLockRule::NoLock,
        FieldUpdateRule::WriteAsZeroes,
        vec![
            FieldEntry::Reserved(4 * 8),
            FieldEntry::Named(*b"CPEN", 1),
            FieldEntry::Named(*b"CINS", 1),
            FieldEntry::Named(*b"CRMV", 1),
            FieldEntry::Named(*b"CEJ0", 1),
            FieldEntry::Named(*b"CEJF", 1),
            FieldEntry::Reserved(3),
            FieldEntry::Named(*b"CCMD", 8),
        ],
    );

    // The same window seen as two dwords: the CPU selector and the data
    // register, with the flag/command bytes skipped.
    let words = Field::new(
        Path::new("PRST"),
        FieldAccessType::DWord,
        FieldLockRule::NoLock,
        FieldUpdateRule::Preserve,
        vec![
            FieldEntry::Named(*b"CSEL", 32),
            FieldEntry::Reserved(4 * 8),
            FieldEntry::Named(*b"CDAT", 32),
        ],
    );

    let selector = Path::new("CSEL");
    let initialize = Store::new(&selector, &Zero {});
    let initialize = Method::new(Path::new("_INI"), 0, true, vec![&initialize]);
    let initialize = initialize_selector.then(|| emit(&initialize));
    let initialize = Raw(match initialize.as_deref() {
        Some(bytes) => bytes,
        None => &[],
    });

    emit(&Device::new(
        Path::new(RES),
        vec![
            &hid as &dyn Aml,
            &uid,
            &lock,
            &crs,
            &region,
            &flags,
            &words,
            &initialize,
        ],
    ))
}

/// `Device (\_SB.CPUS)`: the control methods plus one object per CPU.
fn cpus_device(cpu_count: u32, numa: bool, queued_eject: bool) -> Result<Vec<u8>, Error> {
    let hid = Name::new(Path::new("_HID"), &"ACPI0010");
    let cid = Name::new(Path::new("_CID"), &EISAName::new("PNP0A05"));

    let notify = notify_method(cpu_count);
    let status = status_method();
    let eject = eject_method();
    let scan = scan_method(cpu_count, queued_eject);
    let ost = ost_method();

    let mut processors = Vec::new();
    for index in 0..cpu_count {
        processors.extend(crate::cpu::object(index, numa)?);
    }

    let methods = [notify, status, eject, scan, ost].concat();
    let (methods, processors) = (Raw(&methods), Raw(&processors));
    Ok(emit(&Device::new(
        Path::new("\\_SB_.CPUS"),
        vec![&hid as &dyn Aml, &cid, &methods, &processors],
    )))
}

/// `Method (CTFY, 2)`: dispatch a notification to the named CPU object,
/// since `Notify` needs a literal name rather than a computed one.
fn notify_method(cpu_count: u32) -> Vec<u8> {
    let mut cases = Vec::new();
    for index in 0..cpu_count {
        let selected = Equal::new(&Arg(0), &index);
        let cpu = Path::new(&cpu_name(index));
        let notify = Notify::new(&cpu, &Arg(1));
        cases.extend(emit(&If::new(&selected, vec![&notify])));
    }
    let cases = Raw(&cases);
    emit(&Method::new(Path::new("CTFY"), 2, false, vec![&cases]))
}

/// `Method (CSTA, 1)`: report whether the selected CPU is enabled.
fn status_method() -> Vec<u8> {
    let status = Local(0);
    let csel = res("CSEL");
    let cpen = res("CPEN");
    let acquire = Acquire::new(res("CPLK"), 0xffff);
    let select = Store::new(&csel, &Arg(0));
    let clear = Store::new(&status, &Zero {});
    let enabled = Equal::new(&cpen, &One {});
    let present = Store::new(&status, &0x0fu8);
    let check = If::new(&enabled, vec![&present]);
    let release = Release::new(res("CPLK"));
    let result = Return::new(&status);
    emit(&Method::new(
        Path::new("CSTA"),
        1,
        true,
        vec![&acquire, &select, &clear, &check, &release, &result],
    ))
}

/// `Method (CEJ0, 1)`: ask the hotplug controller to eject the selected CPU.
fn eject_method() -> Vec<u8> {
    let csel = res("CSEL");
    let cej0 = res("CEJ0");
    let acquire = Acquire::new(res("CPLK"), 0xffff);
    let select = Store::new(&csel, &Arg(0));
    let eject = Store::new(&cej0, &One {});
    let release = Release::new(res("CPLK"));
    emit(&Method::new(
        Path::new("CEJ0"),
        1,
        true,
        vec![&acquire, &select, &eject, &release],
    ))
}

/// `Method (CSCN)`: walk the CPUs with pending events, in batches of at most
/// `MAX_CPUS_PER_PASS`, notifying OSPM about each insert and each eject.
fn scan_method(cpu_count: u32, queued_eject: bool) -> Vec<u8> {
    let (csel, ccmd, cdat) = (res("CSEL"), res("CCMD"), res("CDAT"));
    let (cins, crmv) = (res("CINS"), res("CRMV"));
    let (added_list, eject_list) = (Path::new("CNEW"), Path::new("CEJL"));

    let has_event = Local(0);
    let num_added = Local(1);
    let cpu_idx = Local(2);
    let uid = Local(3);
    let has_job = Local(4);
    let num_eject = Local(5);

    let acquire = Acquire::new(res("CPLK"), 0xffff);
    // Named packages, not locals: old Windows cannot hold a package in a
    // local, and its packages are capped at 255 elements.
    let declare_added = Name::new(Path::new("CNEW"), &FixedPackage(MAX_CPUS_PER_PASS));
    let declare_eject_term = Name::new(Path::new("CEJL"), &FixedPackage(MAX_CPUS_PER_PASS));
    let declare_eject_bytes = queued_eject.then(|| emit(&declare_eject_term));
    let declare_eject = Raw(match declare_eject_bytes.as_deref() {
        Some(bytes) => bytes,
        None => &[],
    });
    let first_uid = Store::new(&uid, &Zero {});
    let arm_job = Store::new(&has_job, &One {});

    // Inner loop: collect CPUs with events until the batch is full, the scan
    // wraps around, or every CPU has been looked at.
    let clear_event = Store::new(&has_event, &Zero {});
    let select = Store::new(&csel, &uid);
    let next_cpu = Store::new(&ccmd, &CMD_GET_NEXT_CPU);
    let wrapped = LessThan::new(&cdat, &uid);
    let wrap_exit = If::new(&wrapped, vec![&Break]);
    let added_full = Equal::new(&num_added, &MAX_CPUS_PER_PASS);
    let eject_full = Equal::new(&num_eject, &MAX_CPUS_PER_PASS);
    let both_full = LOr::new(&added_full, &eject_full);
    let batch_full_bytes = if queued_eject {
        emit(&both_full)
    } else {
        emit(&added_full)
    };
    let batch_full = Raw(&batch_full_bytes);
    let resume_later = Store::new(&has_job, &One {});
    let batch_exit = If::new(&batch_full, vec![&resume_later, &Break]);
    let load_uid = Store::new(&uid, &cdat);

    let mark_event = Store::new(&has_event, &One {});
    let added_slot = Index::new(&Zero {}, &added_list, &num_added);
    let cache_added = Store::new(&added_slot, &uid);
    let count_added = Increment::new(&num_added);
    let inserted = Equal::new(&cins, &One {});
    let on_insert = If::new(&inserted, vec![&cache_added, &count_added, &mark_event]);

    let eject_slot = Index::new(&Zero {}, &eject_list, &num_eject);
    let cache_eject = Store::new(&eject_slot, &uid);
    let count_eject = Increment::new(&num_eject);
    let removed = Equal::new(&crmv, &One {});
    let queued_remove = If::new(&removed, vec![&cache_eject, &count_eject, &mark_event]);
    let notify_removed = MethodCall::new(Path::new("CTFY"), vec![&uid, &EJECT_REQUEST]);
    let clear_removed = Store::new(&crmv, &One {});
    let immediate_remove = If::new(&removed, vec![&notify_removed, &clear_removed, &mark_event]);
    let immediate_remove = Else::new(vec![&immediate_remove]);
    let on_remove_bytes = if queued_eject {
        emit(&queued_remove)
    } else {
        emit(&immediate_remove)
    };
    let on_remove = Raw(&on_remove_bytes);

    let next_uid = Increment::new(&uid);
    let pending = Equal::new(&has_event, &One {});
    let in_range = LessThan::new(&uid, &cpu_count);
    let scanning = LAnd::new(&pending, &in_range);
    let scan_loop = While::new(
        &scanning,
        vec![
            &clear_event,
            &select,
            &next_cpu,
            &wrap_exit,
            &batch_exit,
            &load_uid,
            &on_insert,
            &on_remove,
            &next_uid,
        ],
    );

    // Notify OSPM about the collected CPUs and clear the events that got
    // them onto the lists.
    let first_idx = Store::new(&cpu_idx, &Zero {});
    let next_idx = Increment::new(&cpu_idx);

    let zero = Zero {};
    let added_slot_by_idx = Index::new(&zero, &added_list, &cpu_idx);
    let added_elem = DeRefOf::new(&added_slot_by_idx);
    let take_added = Store::new(&uid, &added_elem);
    let notify_added = MethodCall::new(Path::new("CTFY"), vec![&uid, &DEVICE_CHECK]);
    let trace = Store::new(&Debug, &uid);
    let select_added = Store::new(&csel, &uid);
    let clear_insert = Store::new(&cins, &One {});
    let more_added = LessThan::new(&cpu_idx, &num_added);
    let added_loop = While::new(
        &more_added,
        vec![
            &take_added,
            &notify_added,
            &trace,
            &select_added,
            &clear_insert,
            &next_idx,
        ],
    );

    let eject_slot_by_idx = Index::new(&zero, &eject_list, &cpu_idx);
    let eject_elem = DeRefOf::new(&eject_slot_by_idx);
    let take_eject = Store::new(&uid, &eject_elem);
    let notify_eject = MethodCall::new(Path::new("CTFY"), vec![&uid, &EJECT_REQUEST]);
    let select_eject = Store::new(&csel, &uid);
    let clear_remove = Store::new(&crmv, &One {});
    let more_eject = LessThan::new(&cpu_idx, &num_eject);
    let eject_loop_term = While::new(
        &more_eject,
        vec![
            &take_eject,
            &notify_eject,
            &select_eject,
            &clear_remove,
            &next_idx,
        ],
    );
    let eject_loop_bytes = queued_eject.then(|| emit(&eject_loop_term));
    let eject_loop = Raw(match eject_loop_bytes.as_deref() {
        Some(bytes) => bytes,
        None => &[],
    });
    let reset_eject_index_bytes = queued_eject.then(|| emit(&first_idx));
    let reset_eject_index = Raw(match reset_eject_index_bytes.as_deref() {
        Some(bytes) => bytes,
        None => &[],
    });

    let clear_job = Store::new(&has_job, &Zero {});
    let arm_event = Store::new(&has_event, &One {});
    let reset_added = Store::new(&num_added, &Zero {});
    let reset_eject_term = Store::new(&num_eject, &Zero {});
    let reset_eject_bytes = queued_eject.then(|| emit(&reset_eject_term));
    let reset_eject = Raw(match reset_eject_bytes.as_deref() {
        Some(bytes) => bytes,
        None => &[],
    });
    let batching = Equal::new(&has_job, &One {});
    let batch_loop = While::new(
        &batching,
        vec![
            &clear_job,
            &arm_event,
            &reset_added,
            &reset_eject,
            &scan_loop,
            &first_idx,
            &added_loop,
            &reset_eject_index,
            &eject_loop,
        ],
    );

    let release = Release::new(res("CPLK"));
    emit(&Method::new(
        Path::new("CSCN"),
        0,
        true,
        vec![
            &acquire,
            &declare_added,
            &declare_eject,
            &first_uid,
            &arm_job,
            &batch_loop,
            &release,
        ],
    ))
}

/// `Method (COST, 4)`: hand an `_OST` status report to the controller.
fn ost_method() -> Vec<u8> {
    let (csel, ccmd, cdat) = (res("CSEL"), res("CCMD"), res("CDAT"));
    let acquire = Acquire::new(res("CPLK"), 0xffff);
    let select = Store::new(&csel, &Arg(0));
    let event_cmd = Store::new(&ccmd, &CMD_OST_EVENT);
    let event = Store::new(&cdat, &Arg(1));
    let status_cmd = Store::new(&ccmd, &CMD_OST_STATUS);
    let status = Store::new(&cdat, &Arg(2));
    let release = Release::new(res("CPLK"));
    emit(&Method::new(
        Path::new("COST"),
        4,
        true,
        vec![
            &acquire,
            &select,
            &event_cmd,
            &event,
            &status_cmd,
            &status,
            &release,
        ],
    ))
}

/// `CPU_NAME_FMT`: the AML name of a CPU object.
fn cpu_name(index: u32) -> String {
    format!("C{index:03X}")
}

/// `Package (count) {}`: a package that reserves room for `count` elements
/// but declares none. `PackageBuilder` always derives the count from the
/// elements added to it, so it cannot express this.
struct FixedPackage(u8);

impl Aml for FixedPackage {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.byte(0x12);
        sink.vec(&pkg_length(1));
        sink.byte(self.0);
    }
}

/// `Break`
struct Break;

impl Aml for Break {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.byte(0xa5);
    }
}

/// `Debug`, the store target that forwards to the debug object.
struct Debug;

impl Aml for Debug {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.byte(0x5b);
        sink.byte(0x31);
    }
}

macro_rules! logical_op {
    ($(#[$doc:meta])* $name:ident, $opcode:expr) => {
        $(#[$doc])*
        struct $name<'a> {
            left: &'a dyn Aml,
            right: &'a dyn Aml,
        }

        impl<'a> $name<'a> {
            fn new(left: &'a dyn Aml, right: &'a dyn Aml) -> Self {
                Self { left, right }
            }
        }

        impl Aml for $name<'_> {
            fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
                sink.byte($opcode);
                self.left.to_aml_bytes(sink);
                self.right.to_aml_bytes(sink);
            }
        }
    };
}

logical_op!(
    /// `(left && right)`
    LAnd,
    0x90
);
logical_op!(
    /// `(left || right)`
    LOr,
    0x91
);

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        let generated =
            super::build(1, false, false, true).unwrap_or_else(|error| panic!("{error}"));
        super::super::fixture::assert_region(&generated, 6299, 7354);
    }
}
