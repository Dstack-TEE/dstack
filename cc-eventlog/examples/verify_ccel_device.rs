// End-to-end verification: runs on a real TDX CVM, reads the actual
// /sys/firmware/acpi/tables/data/CCEL + /run/log/dstack/runtime_events.log,
// builds the merged CCEL binary, decodes it back, and verifies invariants.

use anyhow::{Context, Result};
use cc_eventlog::{
    tcg::TcgEventLog,
    tdx::{build_ccel_event_log, read_event_log, TdxEvent},
    DSTACK_RUNTIME_EVENT_TYPE,
};
use dcap_qvl::quote::Quote;
use ez_hash::{Hasher, Sha384};

fn main() -> Result<()> {
    let events = read_event_log().context("read event log")?;
    let orig_runtime = events.iter().filter(|e| e.is_runtime_event()).count();
    eprintln!("runtime events: {orig_runtime}");
    eprintln!("total events:   {}", events.len());

    let merged = build_ccel_event_log(&events).context("build merged CCEL")?;
    eprintln!("merged CCEL size: {} bytes", merged.len());

    let parsed = TcgEventLog::decode(&mut merged.as_slice()).context("decode merged CCEL")?;
    let decoded: Vec<TdxEvent> = parsed.to_cc_event_log().context("to_cc_event_log")?;
    eprintln!("decoded events:   {}", decoded.len());

    // Every runtime event in the output must satisfy sha384(event_data) == digest
    let mut checked = 0usize;
    for e in &decoded {
        if e.event_type != DSTACK_RUNTIME_EVENT_TYPE {
            continue;
        }
        let h = Sha384::hash([e.event_payload.as_slice()]);
        anyhow::ensure!(
            h.as_slice() == e.digest.as_slice(),
            "digest mismatch for runtime event at imr={}",
            e.imr,
        );
        checked += 1;
    }
    eprintln!("runtime events verified: {checked}");
    anyhow::ensure!(
        checked == orig_runtime,
        "expected {orig_runtime} runtime events in merged CCEL, got {checked}"
    );

    // RTMR3 replay check: replay the runtime digests in order and compare with
    // what the TD10 report says. We can't easily read the quote here without
    // TDX attest, so just print the replayed RTMR3 for manual comparison.
    let mut rtmr3 = [0u8; 48];
    for e in decoded.iter().filter(|e| e.imr == 3) {
        let mut data = [0u8; 96];
        data[..48].copy_from_slice(&rtmr3);
        data[48..].copy_from_slice(&e.digest);
        rtmr3 = Sha384::hash([data.as_slice()]);
    }
    eprintln!("replayed RTMR3:   {}", hex::encode(rtmr3));

    // Compare against the real RTMR3 from a fresh TDX quote.
    let report_data = [0u8; 64];
    let quote_bytes = tdx_attest::get_quote(&report_data).context("tdx_attest::get_quote")?;
    let quote = Quote::parse(&quote_bytes).context("parse quote")?;
    let td10 = quote.report.as_td10().context("missing td10 report")?;
    eprintln!("td10 RTMR3:       {}", hex::encode(td10.rt_mr3));
    anyhow::ensure!(
        rtmr3 == td10.rt_mr3,
        "replayed RTMR3 does not match td10 RTMR3"
    );

    println!("OK");
    Ok(())
}
