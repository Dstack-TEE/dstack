// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Ratatui drawing. A function of [`State`] and the frame size; no I/O.
//!
//! Visual language: no boxed panels on the main screen, dim labels beside
//! bright values, color reserved for status glyphs, meters and the accent. The
//! selected row carries a `▌` marker on a slightly lifted background. Every
//! line is clipped to the terminal width; nothing wraps.

use super::model::{
    display_node, totals, Detail, DetailTab, EntryKind, Input, JournalEntry, NodeEntry, Row,
    RowKey, State, Tab, Totals,
};
use crate::fmt;
use crate::snapshot::{Phase, Vm};
use crate::source::LogChannel;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;

// ── palette ────────────────────────────────────────────────────────────────

const ACCENT: Color = Color::Rgb(130, 170, 255);
const OK: Color = Color::Rgb(134, 200, 120);
const ERR: Color = Color::Rgb(240, 110, 120);
const WARN: Color = Color::Rgb(230, 180, 90);
const TEXT: Color = Color::Rgb(222, 225, 232);
const MUTED: Color = Color::Rgb(150, 156, 172);
const DIM: Color = Color::Rgb(100, 106, 124);
const RULE: Color = Color::Rgb(62, 66, 80);
const SEL_BG: Color = Color::Rgb(38, 42, 56);

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn fg(c: Color) -> Style {
    Style::default().fg(c)
}

fn sp(style: Style, text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), style)
}

fn dim(text: impl Into<String>) -> Span<'static> {
    sp(fg(DIM), text)
}

fn val(text: impl Into<String>) -> Span<'static> {
    let t: String = text.into();
    if t == "-" {
        dim(t)
    } else {
        sp(fg(TEXT), t)
    }
}

fn spans_width(spans: &[Span]) -> usize {
    spans.iter().map(|s| fmt::width(&s.content)).sum()
}

/// Clip spans to `width` columns, ending with "…" when cut.
fn fit(spans: Vec<Span<'static>>, width: usize) -> Vec<Span<'static>> {
    if spans_width(&spans) <= width {
        return spans;
    }
    let mut out = Vec::new();
    let mut used = 0;
    for s in spans {
        let w = fmt::width(&s.content);
        if used + w < width {
            used += w;
            out.push(s);
            continue;
        }
        let room = width - used;
        if room > 0 {
            out.push(Span::styled(fmt::truncate(&s.content, room), s.style));
        }
        break;
    }
    out
}

/// Exactly `width` columns: clipped, then padded on the right or left.
fn cell(spans: Vec<Span<'static>>, width: usize, right: bool) -> Vec<Span<'static>> {
    let mut spans = fit(spans, width);
    let pad = width.saturating_sub(spans_width(&spans));
    if pad > 0 {
        if right {
            spans.insert(0, Span::raw(" ".repeat(pad)));
        } else {
            spans.push(Span::raw(" ".repeat(pad)));
        }
    }
    spans
}

/// `left`, then `right` flush to the right edge; `right` is dropped when the
/// two would touch.
fn split_line(
    mut left: Vec<Span<'static>>,
    right: Vec<Span<'static>>,
    width: usize,
) -> Vec<Span<'static>> {
    let (lw, rw) = (spans_width(&left), spans_width(&right));
    if rw == 0 || lw + rw + 2 > width {
        return fit(left, width);
    }
    left.push(Span::raw(" ".repeat(width - lw - rw)));
    left.extend(right);
    left
}

/// `key label` pairs: key bright, label dim.
fn hints(pairs: &[(&str, &str)]) -> Vec<Span<'static>> {
    let mut out = vec![Span::raw(" ")];
    for (i, (k, l)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push(Span::raw("  "));
        }
        out.push(sp(fg(MUTED).add_modifier(Modifier::BOLD), *k));
        out.push(dim(format!(" {l}")));
    }
    out
}

/// Only the pairs that fit, so a narrow footer never ends mid-word.
fn hints_fit(pairs: &[(&str, &str)], width: usize) -> Vec<Span<'static>> {
    let mut n = pairs.len();
    while n > 0 && spans_width(&hints(&pairs[..n])) > width {
        n -= 1;
    }
    hints(&pairs[..n])
}

/// `▰▰▰▱▱▱` meter, colored by how full it is.
fn meter(used: u64, total: u64, cells: usize) -> Vec<Span<'static>> {
    if total == 0 {
        return vec![sp(fg(RULE), "▱".repeat(cells))];
    }
    let ratio = used as f64 / total as f64;
    let fill = ((ratio * cells as f64).ceil() as usize).min(cells);
    let fill = if used > 0 { fill.max(1) } else { 0 };
    let color = if ratio >= 0.9 {
        ERR
    } else if ratio >= 0.7 {
        WARN
    } else {
        ACCENT
    };
    vec![
        sp(fg(color), "▰".repeat(fill)),
        sp(fg(RULE), "▱".repeat(cells - fill)),
    ]
}

fn pct(used: u64, total: u64) -> String {
    if total == 0 {
        "-".into()
    } else {
        format!("{}%", used * 100 / total)
    }
}

fn spinner(state: &State) -> &'static str {
    SPINNER[(state.frame as usize) % SPINNER.len()]
}

fn phase_color(p: Phase) -> Color {
    match p {
        Phase::Running => OK,
        Phase::Failed | Phase::Exited => ERR,
        Phase::Booting => ACCENT,
        Phase::ShuttingDown | Phase::Stopping | Phase::Removing => WARN,
        Phase::Stopped | Phase::Unknown => DIM,
    }
}

fn phase_glyph(state: &State, p: Phase) -> Span<'static> {
    let g = match p {
        p if p.is_transient() => spinner(state),
        Phase::Running => "●",
        Phase::Failed => "✕",
        Phase::Exited => "◆",
        Phase::Stopped => "○",
        _ => "?",
    };
    sp(fg(phase_color(p)), g)
}

fn node_glyph(state: &State, n: &NodeEntry) -> Span<'static> {
    if n.snap.error.is_some() {
        sp(fg(ERR), "✕")
    } else if n.snap.ok_at_ms.is_none() {
        sp(fg(ACCENT), spinner(state))
    } else {
        sp(fg(OK), "●")
    }
}

fn interval_text(ms: u64) -> String {
    if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

/// Refresh state plus the time of the last applied poll, so every refresh
/// is visible even when no number changed.
fn live_pill(state: &State) -> Vec<Span<'static>> {
    let at = if state.updated_ms > 0 {
        format!(" · {}", fmt::clock(state.updated_ms))
    } else {
        String::new()
    };
    if state.paused {
        vec![sp(fg(WARN), "‖ paused"), dim(format!("{at} "))]
    } else {
        vec![
            sp(fg(OK), "● "),
            sp(
                fg(MUTED),
                format!("live {}", interval_text(state.interval_ms)),
            ),
            dim(format!("{at} ")),
        ]
    }
}

// ── screen ─────────────────────────────────────────────────────────────────

pub fn draw(frame: &mut Frame, state: &mut State) {
    let area = frame.area();
    if state.detail.is_some() {
        draw_detail(frame, area, state);
        if state.help {
            draw_help(frame, area);
        }
        return;
    }
    state.hits.detail_tabs.clear();
    let short = area.height < 20;
    let head_h = if short { 2 } else { 7 };
    let preview_on = state.preview && !short;
    let preview_h = if preview_on {
        let rest = area.height.saturating_sub(head_h + 3);
        (rest * if area.height >= 32 { 40 } else { 35 } / 100).max(4)
    } else {
        0
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(head_h),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(preview_h),
            Constraint::Length(1),
        ])
        .split(area);
    let t = totals(&state.nodes);
    draw_header(frame, chunks[0], state, &t, short);
    draw_tabs(frame, chunks[1], state);
    let rows = state.rows();
    draw_list(frame, chunks[2], chunks[3], state, &rows);
    if preview_h > 0 {
        draw_preview(frame, chunks[4], state);
    }
    draw_footer(frame, chunks[5], state);
    if state.help {
        draw_help(frame, area);
    }
}

fn brand_line(state: &State, t: &Totals, width: usize) -> Line<'static> {
    let mut left = vec![
        sp(fg(ACCENT).add_modifier(Modifier::BOLD), " ◆ "),
        sp(fg(TEXT).add_modifier(Modifier::BOLD), "dstack"),
        sp(fg(MUTED), " vmm"),
        dim(format!(
            "   {} node{}",
            t.nodes,
            if t.nodes == 1 { "" } else { "s" }
        )),
    ];
    if state.sources.len() != t.nodes {
        left.push(dim(format!(" · {} sources", state.sources.len())));
    }
    if state.read_only {
        left.push(dim(" · read-only"));
    }
    Line::from(split_line(left, live_pill(state), width))
}

fn draw_header(frame: &mut Frame, area: Rect, state: &State, t: &Totals, short: bool) {
    let width = area.width as usize;
    if short {
        let mut l = vec![dim("   nodes ")];
        l.push(nodes_value(t));
        l.push(dim("   vms "));
        l.extend(phase_summary(state, t, true));
        l.push(dim("   vcpu "));
        l.push(val(pct(t.vcpu_used, t.vcpu_max)));
        l.push(dim("   mem "));
        l.push(val(pct(t.mem_used_mb, t.mem_max_mb)));
        frame.render_widget(
            Paragraph::new(vec![brand_line(state, t, width), Line::from(fit(l, width))]),
            area,
        );
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(area);
    frame.render_widget(Paragraph::new(brand_line(state, t, width)), rows[0]);
    let split = if width >= 110 { 50 } else { 100 };
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(split),
            Constraint::Percentage(100 - split),
        ])
        .split(rows[1]);

    let stat = |label: &str, value: Vec<Span<'static>>| {
        let mut out = vec![dim(format!("   {label:<8}"))];
        out.extend(value);
        out
    };
    let lw = cols[0].width as usize;
    let mut left = Vec::new();
    let mut nodes = vec![nodes_value(t)];
    if t.nodes > t.nodes_up + t.nodes_connecting {
        nodes.push(dim(" · "));
        nodes.push(sp(
            fg(ERR),
            format!("{} down", t.nodes - t.nodes_up - t.nodes_connecting),
        ));
    }
    if t.nodes_connecting > 0 {
        nodes.push(dim(format!(" · {} connecting", t.nodes_connecting)));
    }
    left.push(stat("nodes", nodes));
    left.push(stat("vms", phase_summary(state, t, false)));
    let mut vcpu = meter(t.vcpu_used, t.vcpu_max, 12);
    vcpu.extend([
        val(format!(" {}", t.vcpu_used)),
        dim(format!("/{} allocated", t.vcpu_max)),
    ]);
    left.push(stat("vcpu", vcpu));
    let mut mem = meter(t.mem_used_mb, t.mem_max_mb, 12);
    mem.extend([
        val(format!(" {}", fmt::mem_mb(t.mem_used_mb))),
        dim(format!("/{}", fmt::mem_mb(t.mem_max_mb))),
        dim(format!(" · disk {}", fmt::disk_gb(t.disk_gb))),
    ]);
    left.push(stat("memory", mem));
    if t.gpus > 0 {
        let mut gpu = meter(t.gpus_used as u64, t.gpus as u64, 12);
        gpu.extend([
            val(format!(" {}", t.gpus_used)),
            dim(format!("/{} attached", t.gpus)),
        ]);
        left.push(stat("gpu", gpu));
    } else {
        left.push(stat("gpu", vec![dim("none on these nodes")]));
    }
    let left: Vec<Line> = left.into_iter().map(|l| Line::from(fit(l, lw))).collect();
    frame.render_widget(Paragraph::new(left), cols[0]);
    if split < 100 {
        draw_node_board(frame, cols[1], state);
    }
}

fn nodes_value(t: &Totals) -> Span<'static> {
    let color = if t.nodes_up == t.nodes { OK } else { WARN };
    sp(fg(color), format!("{}/{} up", t.nodes_up, t.nodes))
}

/// `12 running · 1 booting · 2 failed` with the count of each phase present.
fn phase_summary(state: &State, t: &Totals, compact: bool) -> Vec<Span<'static>> {
    if t.vms == 0 {
        return vec![dim("none")];
    }
    let mut out = Vec::new();
    for (i, (p, n)) in t.by_phase.iter().enumerate() {
        if i > 0 {
            out.push(dim(if compact { " " } else { " · " }));
        }
        if compact {
            out.push(phase_glyph(state, *p));
            out.push(val(n.to_string()));
        } else {
            out.push(sp(
                fg(phase_color(*p)).add_modifier(Modifier::BOLD),
                n.to_string(),
            ));
            out.push(dim(format!(" {}", p.label())));
        }
    }
    out
}

/// Right half of the header: one line per node, like a status board.
fn draw_node_board(frame: &mut Frame, area: Rect, state: &State) {
    let w = area.width as usize;
    let mut lines = vec![Line::from(fit(
        vec![dim(format!(
            " {:<16} {:>5} {:>6} {:>6} {:>5}  {}",
            "node", "vms", "vcpu", "mem", "gpu", "rtt"
        ))],
        w,
    ))];
    let room = (area.height as usize).saturating_sub(1);
    let shown = if state.nodes.len() > room {
        room.saturating_sub(1)
    } else {
        state.nodes.len()
    };
    for n in state.nodes.iter().take(shown) {
        let s = &n.snap;
        let mut row = vec![
            Span::raw(" "),
            node_glyph(state, n),
            sp(fg(TEXT), format!(" {}", fmt::pad(&display_node(s), 14))),
        ];
        if s.ok_at_ms.is_none() {
            row.push(dim(format!(
                " {:>5} {:>6} {:>6} {:>5}  ",
                "-", "-", "-", "-"
            )));
        } else {
            let (vu, vm) = (
                s.vcpu_used() as u64,
                s.resources.as_ref().map_or(0, |r| r.max_vcpu as u64),
            );
            let (mu, mm) = (
                s.memory_used_mb(),
                s.resources.as_ref().map_or(0, |r| r.max_memory_mb as u64),
            );
            let running = s.vms.iter().filter(|v| v.phase().is_live()).count();
            let level = |used: u64, max: u64| {
                let p = pct(used, max);
                let c = if max > 0 && used * 10 >= max * 9 {
                    ERR
                } else if max > 0 && used * 10 >= max * 7 {
                    WARN
                } else {
                    TEXT
                };
                (p, c)
            };
            let (vp, vc) = level(vu, vm);
            let (mp, mc) = level(mu, mm);
            row.extend([
                val(format!(" {:>5}", format!("{running}/{}", s.vms.len()))),
                sp(fg(vc), format!(" {vp:>6}")),
                sp(fg(mc), format!(" {mp:>6}")),
                val(format!(
                    " {:>5}",
                    if s.gpus.is_empty() {
                        "-".to_string()
                    } else {
                        format!("{}/{}", s.gpus_used(), s.gpus.len())
                    }
                )),
                Span::raw("  "),
            ]);
        }
        row.push(match (&s.error, s.latency_ms) {
            (Some(_), _) => sp(fg(ERR), "down"),
            (None, Some(ms)) => dim(format!("{ms}ms")),
            (None, None) => dim("…"),
        });
        lines.push(Line::from(fit(row, w)));
    }
    if shown < state.nodes.len() {
        lines.push(Line::from(dim(format!(
            " +{} more · Fleet tab lists all",
            state.nodes.len() - shown
        ))));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_tabs(frame: &mut Frame, area: Rect, state: &mut State) {
    let width = area.width as usize;
    let mut spans = vec![Span::raw(" ")];
    let mut x = 1usize;
    state.hits.tabs.clear();
    for (i, tab) in Tab::ALL.into_iter().enumerate() {
        let active = state.tab == tab;
        let start = x;
        let key = format!("{}", i + 1);
        spans.push(dim(format!("{key} ")));
        x += key.len() + 1;
        let name_style = if active {
            fg(ACCENT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            fg(MUTED)
        };
        spans.push(sp(name_style, tab.label()));
        x += tab.label().len();
        let c = format!(" {}", state.count(tab));
        x += c.len();
        spans.push(sp(if active { fg(ACCENT) } else { fg(DIM) }, c));
        state.hits.tabs.push((start as u16, x as u16, area.y, tab));
        spans.push(Span::raw("    "));
        x += 4;
    }
    let mut right = Vec::new();
    if !state.filter.is_empty() && !matches!(state.input, Some(Input::Filter(_))) {
        right.extend([
            dim("filter "),
            sp(fg(WARN), state.filter.clone()),
            dim("   "),
        ]);
    }
    right.extend([
        dim("scope "),
        sp(fg(MUTED), state.scope.label()),
        dim("   sort "),
        sp(
            fg(MUTED),
            format!(
                "{} {}",
                state.sort.label(),
                if state.sort_rev { "↑" } else { "↓" }
            ),
        ),
        Span::raw(" "),
    ]);
    frame.render_widget(
        Paragraph::new(Line::from(split_line(spans, right, width))),
        area,
    );
}

// ── main list ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Col {
    Name,
    Node,
    Status,
    Uptime,
    Vcpu,
    Mem,
    Disk,
    Gpu,
    Id,
    Image,
    App,
    Ports,
}

impl Col {
    fn title(self) -> &'static str {
        match self {
            Col::Name => "NAME",
            Col::Node => "NODE",
            Col::Status => "STATUS",
            Col::Uptime => "UPTIME",
            Col::Vcpu => "VCPU",
            Col::Mem => "MEM",
            Col::Disk => "DISK",
            Col::Gpu => "GPU",
            Col::Id => "ID",
            Col::Image => "IMAGE",
            Col::App => "APP ID",
            Col::Ports => "PORTS",
        }
    }

    fn width(self) -> usize {
        match self {
            Col::Name => 0,
            Col::Node => 14,
            Col::Status => 14,
            Col::Uptime => 7,
            Col::Vcpu => 7,
            Col::Mem => 10,
            Col::Disk => 6,
            Col::Gpu => 5,
            Col::Id => 8,
            Col::Image => 16,
            Col::App => 10,
            Col::Ports => 16,
        }
    }

    fn right(self) -> bool {
        matches!(
            self,
            Col::Uptime | Col::Vcpu | Col::Mem | Col::Disk | Col::Gpu
        )
    }
}

const GUTTER: usize = 2;
const SEP: usize = 2;
const NAME_MIN: usize = 20;

/// The columns that fit `width`, and the width left for the name.
/// Compact under 100 columns, standard to 139, wide from 140.
fn columns(tab: Tab, width: usize) -> (Vec<Col>, usize) {
    let mut cols = vec![Col::Name];
    if tab == Tab::Vms {
        cols.push(Col::Node);
    }
    cols.extend([Col::Status, Col::Uptime, Col::Vcpu, Col::Mem]);
    if width >= 100 {
        cols.extend([Col::Disk, Col::Gpu, Col::Id, Col::Image]);
    }
    if width >= 140 {
        cols.extend([Col::App, Col::Ports]);
    }
    loop {
        let fixed: usize = cols.iter().map(|c| c.width() + SEP).sum::<usize>() - SEP;
        let name = width.saturating_sub(GUTTER + fixed);
        if name >= NAME_MIN || cols.len() <= 2 {
            return (cols, name.max(8));
        }
        cols.pop();
    }
}

fn header_line(cols: &[Col], name_w: usize, width: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ".repeat(GUTTER))];
    for (i, c) in cols.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" ".repeat(SEP)));
        }
        let w = if *c == Col::Name { name_w } else { c.width() };
        spans.extend(cell(vec![dim(c.title())], w, c.right()));
    }
    Line::from(fit(spans, width))
}

fn draw_list(frame: &mut Frame, head: Rect, area: Rect, state: &mut State, rows: &[Row]) {
    let width = area.width as usize;
    state.list_height = area.height as usize;
    state.hits.list_y = area.y;
    state.hits.list_h = area.height;
    state.clamp_selection();
    if state.tab == Tab::Events {
        draw_events(frame, head, area, state, rows);
        return;
    }
    let (cols, name_w) = columns(state.tab, width);
    frame.render_widget(Paragraph::new(header_line(&cols, name_w, width)), head);
    if rows.is_empty() {
        frame.render_widget(Paragraph::new(empty_hint(state)), area);
        return;
    }
    let sel = state.selected_index();
    let lines: Vec<Line> = rows
        .iter()
        .enumerate()
        .skip(state.offset)
        .take(area.height as usize)
        .map(|(i, r)| {
            let n = &state.nodes[r.node];
            let mut spans = vec![Span::raw(" ".repeat(GUTTER))];
            for (ci, c) in cols.iter().enumerate() {
                if ci > 0 {
                    spans.push(Span::raw(" ".repeat(SEP)));
                }
                let w = if *c == Col::Name { name_w } else { c.width() };
                let content = match r.vm {
                    None => node_cell(state, n, *c),
                    Some(vi) => vm_cell(state, n, &n.snap.vms[vi], r, *c),
                };
                spans.extend(cell(content, w, c.right()));
            }
            row_line(fit(spans, width), i == sel, width)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

/// A row with the selection marker and background when selected.
fn row_line(mut spans: Vec<Span<'static>>, selected: bool, width: usize) -> Line<'static> {
    if !selected {
        return Line::from(spans);
    }
    let w = spans_width(&spans);
    if w < width {
        spans.push(Span::raw(" ".repeat(width - w)));
    }
    if let Some(first) = spans.first_mut() {
        if first.content.starts_with(' ') {
            let rest: String = first.content.chars().skip(1).collect();
            *first = Span::raw(rest);
            spans.insert(0, sp(fg(ACCENT), "▌"));
        }
    }
    Line::from(spans).style(Style::default().bg(SEL_BG))
}

fn empty_hint(state: &State) -> Vec<Line<'static>> {
    let msg = if state.nodes.is_empty() {
        "connecting…".to_string()
    } else if !state.filter.is_empty() {
        format!(
            "nothing matches \"{}\" · esc clears the filter",
            state.filter
        )
    } else {
        format!(
            "nothing in scope \"{}\" · a cycles scope",
            state.scope.label()
        )
    };
    vec![Line::from(""), Line::from(dim(format!("   {msg}")))]
}

fn node_cell(state: &State, n: &NodeEntry, col: Col) -> Vec<Span<'static>> {
    let s = &n.snap;
    let up = s.ok_at_ms.is_some();
    let res = s.resources.as_ref();
    match col {
        Col::Name => {
            let fold = if state.folded.contains(&n.key) {
                "▸ "
            } else {
                "▾ "
            };
            let mut v = vec![
                dim(fold),
                node_glyph(state, n),
                sp(
                    fg(TEXT).add_modifier(Modifier::BOLD),
                    format!(" {}", s.name),
                ),
            ];
            if let Some(hub) = &s.via {
                v.push(dim(format!(" via {hub}")));
            }
            if up {
                v.push(dim(format!(
                    "  {} vm{}",
                    s.vms.len(),
                    if s.vms.len() == 1 { "" } else { "s" }
                )));
            }
            v
        }
        Col::Status => match (&s.error, s.ok_at_ms) {
            (Some(_), Some(ok)) => vec![
                sp(fg(ERR), "down"),
                dim(format!(" {}", fmt::ago(state.now_ms, ok))),
            ],
            (Some(_), None) => vec![sp(fg(ERR), "unreachable")],
            (None, None) => vec![dim("connecting")],
            (None, Some(_)) => vec![
                sp(fg(MUTED), "online"),
                dim(s.latency_ms.map(|l| format!(" {l}ms")).unwrap_or_default()),
            ],
        },
        Col::Vcpu if up => frac(
            s.vcpu_used().to_string(),
            res.map(|r| r.max_vcpu.to_string()),
        ),
        Col::Mem if up => frac(
            fmt::mem_mb(s.memory_used_mb()),
            res.map(|r| fmt::mem_mb(r.max_memory_mb as u64)),
        ),
        Col::Disk if up => vec![val(fmt::disk_gb(s.disk_gb()))],
        Col::Gpu if up && !s.gpus.is_empty() => {
            frac(s.gpus_used().to_string(), Some(s.gpus.len().to_string()))
        }
        Col::Image => match &s.version {
            Some(v) => vec![dim(format!("vmm {v}"))],
            None => vec![],
        },
        Col::App | Col::Ports if col == Col::Ports => vec![dim(s.endpoint.clone())],
        _ => vec![],
    }
}

fn frac(used: String, max: Option<String>) -> Vec<Span<'static>> {
    match max {
        Some(m) => vec![val(used), dim(format!("/{m}"))],
        None => vec![val(used)],
    }
}

fn vm_cell(state: &State, n: &NodeEntry, vm: &Vm, r: &Row, col: Col) -> Vec<Span<'static>> {
    let phase = vm.phase();
    let quiet = matches!(phase, Phase::Stopped | Phase::Unknown);
    let stale = n.snap.error.is_some();
    let text = if quiet || stale { fg(MUTED) } else { fg(TEXT) };
    match col {
        Col::Name => {
            let mut v = Vec::new();
            if state.tab == Tab::Fleet {
                v.push(sp(fg(RULE), if r.last { "  └ " } else { "  ├ " }));
            }
            v.push(sp(text, vm.name.clone()));
            if let Some(a) = vm.activity().filter(|a| !a.is_empty()) {
                let c = if phase == Phase::Failed { ERR } else { DIM };
                v.push(sp(fg(c), format!("  {a}")));
            }
            v
        }
        Col::Node => vec![sp(fg(MUTED), display_node(&n.snap))],
        Col::Status => {
            let label_style = match phase {
                Phase::Failed | Phase::Exited => fg(ERR),
                _ if quiet => fg(DIM),
                _ => fg(MUTED),
            };
            let mut v = vec![
                phase_glyph(state, phase),
                sp(label_style, format!(" {}", phase.label())),
            ];
            if stale {
                v.push(dim(" ?"));
            }
            v
        }
        Col::Uptime => vec![val(vm
            .uptime_secs
            .map(fmt::duration)
            .unwrap_or_else(|| "-".into()))],
        Col::Vcpu => vec![sp(text, vm.vcpu.to_string())],
        Col::Mem => vec![sp(text, fmt::mem_mb(vm.memory_mb as u64))],
        Col::Disk => vec![sp(text, fmt::disk_gb(vm.disk_gb as u64))],
        Col::Gpu => vec![val(if vm.gpus.is_empty() {
            "-".to_string()
        } else {
            vm.gpus.len().to_string()
        })],
        Col::Id => vec![dim(vm.short_id().to_string())],
        Col::Image => vec![sp(fg(MUTED), vm.image.clone())],
        Col::App => vec![dim(crate::snapshot::short(&vm.app_id, 10).to_string())],
        Col::Ports => vec![dim(ports_text(vm))],
    }
}

fn ports_text(vm: &Vm) -> String {
    if vm.ports.is_empty() {
        return "-".into();
    }
    vm.ports
        .iter()
        .map(|p| format!("{}→{}", p.host_port, p.vm_port))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── events ─────────────────────────────────────────────────────────────────

fn draw_events(frame: &mut Frame, head: Rect, area: Rect, state: &State, rows: &[Row]) {
    let width = area.width as usize;
    let node_w = 14;
    let vm_w = 18;
    let ev_w = 20;
    frame.render_widget(
        Paragraph::new(Line::from(fit(
            vec![dim(format!(
                "{}{:<14}  {}  {}  {}  DETAIL",
                " ".repeat(GUTTER + 2),
                "TIME",
                fmt::pad("NODE", node_w),
                fmt::pad("VM", vm_w),
                fmt::pad("EVENT", ev_w),
            ))],
            width,
        ))),
        head,
    );
    if rows.is_empty() {
        let msg = if state.journal.is_empty() {
            "no events yet · state changes and guest events land here"
        } else {
            "nothing matches"
        };
        frame.render_widget(
            Paragraph::new(vec![Line::from(""), Line::from(dim(format!("   {msg}")))]),
            area,
        );
        return;
    }
    let sel = state.selected_index();
    let lines: Vec<Line> = rows
        .iter()
        .enumerate()
        .skip(state.offset)
        .take(area.height as usize)
        .filter_map(|(i, r)| {
            let e = &state.journal[r.event?];
            let spans = vec![
                Span::raw(" ".repeat(GUTTER)),
                event_glyph(e),
                Span::raw(" "),
                dim(format!("{:<14}", fmt::stamp(e.at_ms))),
                Span::raw("  "),
                sp(fg(MUTED), fmt::pad(&e.node, node_w)),
                Span::raw("  "),
                sp(
                    fg(TEXT),
                    fmt::pad(e.vm_name.as_deref().unwrap_or("-"), vm_w),
                ),
                Span::raw("  "),
                sp(
                    if e.bad { fg(ERR) } else { fg(MUTED) },
                    fmt::pad(&e.title, ev_w),
                ),
                Span::raw("  "),
                dim(e.body.replace('\n', " ")),
            ];
            Some(row_line(fit(spans, width), i == sel, width))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn event_glyph(e: &JournalEntry) -> Span<'static> {
    match e.kind {
        EntryKind::Guest if e.bad => sp(fg(ERR), "·"),
        EntryKind::Guest => sp(fg(DIM), "·"),
        EntryKind::Change if e.bad => sp(fg(ERR), "◆"),
        EntryKind::Change => sp(fg(ACCENT), "◆"),
        EntryKind::NodeDown => sp(fg(ERR), "✕"),
        EntryKind::NodeUp => sp(fg(OK), "●"),
        EntryKind::Action => sp(fg(WARN), "▸"),
    }
}

// ── info (preview + detail) ────────────────────────────────────────────────

fn kv(key: &str, value: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![dim(format!("  {key:<12}"))];
    spans.extend(value);
    Line::from(spans)
}

fn section(title: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        sp(fg(MUTED).add_modifier(Modifier::BOLD), title.to_string()),
    ])
}

fn info_lines(state: &State, key: &RowKey, events: usize) -> Vec<Line<'static>> {
    match key {
        RowKey::Node(k) => state
            .node(k)
            .map(|n| node_info(state, n))
            .unwrap_or_default(),
        RowKey::Vm(nk, id) => state
            .vm(nk, id)
            .map(|(n, vm)| vm_info(state, n, vm, events))
            .unwrap_or_else(|| vec![Line::from(dim("  this VM is gone"))]),
        RowKey::Event(seq) => match state.event(*seq) {
            Some(e) => {
                let mut l = vec![
                    kv("when", vec![val(fmt::stamp(e.at_ms))]),
                    kv("node", vec![val(e.node.clone())]),
                    kv(
                        "vm",
                        vec![val(e.vm_name.clone().unwrap_or_else(|| "-".into()))],
                    ),
                    kv(
                        "event",
                        vec![event_glyph(e), Span::raw(" "), val(e.title.clone())],
                    ),
                ];
                for (i, line) in e.body.lines().enumerate() {
                    l.push(kv(
                        if i == 0 { "detail" } else { "" },
                        vec![val(line.to_string())],
                    ));
                }
                l.push(Line::from(dim("  enter opens the VM")));
                l
            }
            None => vec![],
        },
    }
}

fn vm_info(state: &State, n: &NodeEntry, vm: &Vm, events: usize) -> Vec<Line<'static>> {
    let phase = vm.phase();
    let mut status = vec![
        phase_glyph(state, phase),
        val(format!(" {}", phase.label())),
    ];
    if let Some(up) = vm.uptime_secs {
        status.push(dim(format!(" · up {}", fmt::duration(up))));
    }
    if let Some(a) = vm.activity().filter(|a| !a.is_empty()) {
        let c = if phase == Phase::Failed { ERR } else { MUTED };
        status.push(sp(fg(c), format!(" · {a}")));
    }
    if let Some(err) = &n.snap.error {
        status.push(sp(
            fg(WARN),
            format!(
                " · as of {} (node: {err})",
                n.snap.ok_at_ms.map(fmt::clock).unwrap_or_default()
            ),
        ));
    }
    let mut l = vec![
        kv("status", status),
        kv("id", vec![val(vm.id.clone())]),
        kv("app id", vec![val(or_dash(&vm.app_id))]),
        kv(
            "instance",
            vec![val(vm.instance_id.clone().unwrap_or_else(|| "-".into()))],
        ),
        kv(
            "node",
            vec![
                val(display_node(&n.snap)),
                dim(format!("  {}", n.snap.endpoint)),
            ],
        ),
        kv(
            "image",
            vec![
                val(or_dash(&vm.image)),
                dim(if vm.image_version.is_empty() {
                    String::new()
                } else {
                    format!("  v{}", vm.image_version)
                }),
            ],
        ),
        kv(
            "resources",
            vec![
                val(vm.vcpu.to_string()),
                dim(" vcpu · "),
                val(fmt::mem_mb(vm.memory_mb as u64)),
                dim(" memory · "),
                val(fmt::disk_gb(vm.disk_gb as u64)),
                dim(" disk"),
            ],
        ),
        kv(
            "tee",
            vec![if vm.no_tee {
                sp(fg(WARN), "off · plain VM")
            } else {
                val("on")
            }],
        ),
    ];
    if !vm.gpus.is_empty() {
        l.push(kv("gpus", vec![val(vm.gpus.join(", "))]));
    }
    if !vm.networks.is_empty() {
        l.push(kv("network", vec![val(vm.networks.join(", "))]));
    }
    if !vm.ports.is_empty() {
        let ports = vm
            .ports
            .iter()
            .map(|p| {
                let addr = if p.host_address.is_empty() {
                    "127.0.0.1"
                } else {
                    &p.host_address
                };
                format!("{} {addr}:{}→{}", p.protocol, p.host_port, p.vm_port)
            })
            .collect::<Vec<_>>()
            .join(", ");
        l.push(kv("ports", vec![val(ports)]));
    }
    if let Some(url) = &vm.app_url {
        l.push(kv("app url", vec![sp(fg(ACCENT), url.clone())]));
    }
    if events > 0 && !vm.events.is_empty() {
        l.push(Line::from(""));
        l.push(section("recent guest events"));
        let mut evs: Vec<_> = vm.events.iter().collect();
        evs.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        for e in evs.into_iter().take(events) {
            l.push(Line::from(vec![
                dim(format!("  {}  ", fmt::clock(e.timestamp_ms))),
                sp(fg(MUTED), fmt::pad(&e.event, 18)),
                val(format!(" {}", e.body.replace('\n', " "))),
            ]));
        }
    }
    l
}

fn node_info(state: &State, n: &NodeEntry) -> Vec<Line<'static>> {
    let s = &n.snap;
    let mut status = vec![node_glyph(state, n)];
    match (&s.error, s.ok_at_ms) {
        (Some(e), ok) => {
            status.push(sp(fg(ERR), format!(" {e}")));
            if let Some(ok) = ok {
                status.push(dim(format!(" · last ok {}", fmt::ago(state.now_ms, ok))));
            }
        }
        (None, Some(_)) => {
            status.push(val(" online"));
            if let Some(l) = s.latency_ms {
                status.push(dim(format!(" · {l}ms")));
            }
        }
        (None, None) => status.push(dim(" connecting")),
    }
    let mut l = vec![
        kv("status", status),
        kv("endpoint", vec![val(s.endpoint.clone())]),
    ];
    if let Some(hub) = &s.via {
        l.push(kv("via hub", vec![val(hub.clone()), dim("  read-only")]));
    } else if !n.writable {
        l.push(kv("actions", vec![dim("read-only")]));
    }
    l.push(kv(
        "vmm",
        vec![
            val(s.version.clone().unwrap_or_else(|| "-".into())),
            dim(s
                .rev
                .as_ref()
                .map(|r| format!("  {}", crate::snapshot::short(r, 12)))
                .unwrap_or_default()),
        ],
    ));
    if let Some(r) = &s.resources {
        let live = s.live_vms().count() as u64;
        let mut cvms = meter(live, r.max_cvms as u64, 10);
        cvms.extend([
            val(format!(" {live}")),
            dim(format!("/{} slots", r.max_cvms)),
        ]);
        l.push(kv("cvms", cvms));
        let mut vcpu = meter(s.vcpu_used() as u64, r.max_vcpu as u64, 10);
        vcpu.extend([
            val(format!(" {}", s.vcpu_used())),
            dim(format!("/{}", r.max_vcpu)),
        ]);
        l.push(kv("vcpu", vcpu));
        let mut mem = meter(s.memory_used_mb(), r.max_memory_mb as u64, 10);
        mem.extend([
            val(format!(" {}", fmt::mem_mb(s.memory_used_mb()))),
            dim(format!("/{}", fmt::mem_mb(r.max_memory_mb as u64))),
        ]);
        l.push(kv("memory", mem));
    }
    l.push(kv(
        "disk",
        vec![val(fmt::disk_gb(s.disk_gb())), dim(" provisioned")],
    ));
    l.push(kv("kms", vec![val(join_or_dash(&s.kms_urls))]));
    l.push(kv("gateway", vec![val(join_or_dash(&s.gateway_urls))]));
    if let Some(d) = &s.base_domain {
        l.push(kv("base domain", vec![val(d.clone())]));
    }
    if !s.gpus.is_empty() {
        l.push(Line::from(""));
        l.push(section("gpus"));
        for g in &s.gpus {
            let owner = s
                .vms
                .iter()
                .find(|v| v.gpus.iter().any(|slot| slot == &g.slot))
                .map(|v| v.name.clone());
            l.push(Line::from(vec![
                Span::raw("  "),
                if g.is_free {
                    dim("○")
                } else {
                    sp(fg(ACCENT), "●")
                },
                sp(fg(TEXT), format!(" {:<14}", g.slot)),
                sp(fg(MUTED), fmt::pad(&g.description, 32)),
                dim(match owner {
                    Some(o) => format!("  {o}"),
                    None if g.is_free => "  free".into(),
                    None => "  in use".into(),
                }),
            ]));
        }
    }
    l
}

fn or_dash(s: &str) -> String {
    if s.is_empty() {
        "-".into()
    } else {
        s.to_string()
    }
}

fn join_or_dash(v: &[String]) -> String {
    if v.is_empty() {
        "-".into()
    } else {
        v.join(", ")
    }
}

fn draw_preview(frame: &mut Frame, area: Rect, state: &State) {
    let width = area.width as usize;
    let Some(key) = state.sel.clone() else {
        return;
    };
    let title = match &key {
        RowKey::Node(k) => state.node(k).map(|n| display_node(&n.snap)),
        RowKey::Vm(nk, id) => state
            .vm(nk, id)
            .map(|(n, v)| format!("{} · {} on {}", v.name, v.short_id(), n.snap.name)),
        RowKey::Event(seq) => state
            .event(*seq)
            .map(|e| format!("{} · {}", e.node, e.title)),
    }
    .unwrap_or_default();
    let head = format!("── {title} ");
    let rule = "─".repeat(width.saturating_sub(fmt::width(&head)));
    let mut lines = vec![Line::from(vec![
        sp(fg(RULE), "── "),
        sp(fg(MUTED), format!("{title} ")),
        sp(fg(RULE), rule),
    ])];
    lines.extend(
        info_lines(state, &key, 3)
            .into_iter()
            .map(|l| Line::from(fit(l.spans, width))),
    );
    lines.truncate(area.height as usize);
    frame.render_widget(Paragraph::new(lines), area);
}

// ── footer ─────────────────────────────────────────────────────────────────

fn draw_footer(frame: &mut Frame, area: Rect, state: &State) {
    let width = area.width as usize;
    let line = match &state.input {
        Some(Input::Filter(buf)) => {
            let left = vec![
                sp(fg(ACCENT).add_modifier(Modifier::BOLD), " / "),
                sp(fg(TEXT), buf.clone()),
                sp(fg(ACCENT), "▏"),
            ];
            split_line(left, hints(&[("enter", "keep"), ("esc", "clear")]), width)
        }
        Some(Input::Choose {
            vm_name, node_key, ..
        }) => {
            let node = state
                .node(node_key)
                .map(|n| n.snap.name.clone())
                .unwrap_or_default();
            let mut left = vec![
                sp(fg(WARN).add_modifier(Modifier::BOLD), " ▸ "),
                sp(fg(TEXT), vm_name.clone()),
                dim(format!(" on {node}   ")),
            ];
            left.extend(hints(&[
                ("u", "start"),
                ("d", "shutdown"),
                ("r", "restart"),
                ("k", "force stop"),
                ("esc", "cancel"),
            ]));
            fit(left, width)
        }
        Some(Input::Confirm {
            vm_name,
            node_key,
            action,
            ..
        }) => {
            let node = state
                .node(node_key)
                .map(|n| n.snap.name.clone())
                .unwrap_or_default();
            let c = if action.is_forceful() { ERR } else { WARN };
            let mut left = vec![
                sp(
                    fg(c).add_modifier(Modifier::BOLD),
                    format!(" {} ", action.label()),
                ),
                sp(fg(TEXT), vm_name.clone()),
                dim(format!(" on {node}?   ")),
            ];
            left.extend(hints(&[("y", "confirm"), ("n", "cancel")]));
            fit(left, width)
        }
        None => match &state.toast {
            Some(t) => fit(
                vec![sp(fg(if t.bad { ERR } else { OK }), format!(" {}", t.text))],
                width,
            ),
            None => hints_fit(
                &[
                    ("↑↓", "move"),
                    ("enter", "open"),
                    ("x", "act"),
                    ("/", "filter"),
                    ("a", "scope"),
                    ("s", "sort"),
                    ("v", "preview"),
                    ("←→", "fold"),
                    ("p", "pause"),
                    ("?", "help"),
                    ("q", "quit"),
                ],
                width,
            ),
        },
    };
    frame.render_widget(Paragraph::new(Line::from(line)), area);
}

// ── detail ─────────────────────────────────────────────────────────────────

fn draw_detail(frame: &mut Frame, area: Rect, state: &mut State) {
    frame.render_widget(Clear, area);
    let width = area.width as usize;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);
    let Some(d) = state.detail.clone() else {
        return;
    };

    // Title.
    let mut title = vec![sp(fg(ACCENT).add_modifier(Modifier::BOLD), " ◆ ")];
    match &d.target {
        RowKey::Vm(nk, id) => match state.vm(nk, id) {
            Some((n, vm)) => {
                let p = vm.phase();
                title.extend([
                    sp(fg(TEXT).add_modifier(Modifier::BOLD), vm.name.clone()),
                    Span::raw("  "),
                    phase_glyph(state, p),
                    sp(fg(MUTED), format!(" {}", p.label())),
                    dim(format!("  on {}", display_node(&n.snap))),
                ]);
            }
            None => title.push(dim("gone")),
        },
        RowKey::Node(k) => {
            if let Some(n) = state.node(k) {
                title.extend([
                    sp(fg(TEXT).add_modifier(Modifier::BOLD), display_node(&n.snap)),
                    Span::raw("  "),
                    node_glyph(state, n),
                    dim(format!("  {}", n.snap.endpoint)),
                ]);
            }
        }
        RowKey::Event(_) => {}
    }
    frame.render_widget(
        Paragraph::new(Line::from(split_line(title, live_pill(state), width))),
        chunks[0],
    );

    // Tabs.
    let mut tabs = vec![Span::raw(" ")];
    let mut x = 1usize;
    state.hits.detail_tabs.clear();
    for (i, t) in d.tabs().iter().enumerate() {
        let active = *t == d.tab;
        let start = x;
        let key = format!("{} ", i + 1);
        x += key.len() + t.label().len();
        tabs.push(dim(key));
        tabs.push(sp(
            if active {
                fg(ACCENT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                fg(MUTED)
            },
            t.label(),
        ));
        state
            .hits
            .detail_tabs
            .push((start as u16, x as u16, chunks[1].y, *t));
        tabs.push(Span::raw("    "));
        x += 4;
    }
    let body_h = chunks[3].height as usize;
    let right = detail_status(state, &d, body_h);
    frame.render_widget(
        Paragraph::new(Line::from(split_line(tabs, right, width))),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(Line::from(sp(fg(RULE), "─".repeat(width)))),
        chunks[2],
    );

    // Body.
    if let Some(dm) = state.detail.as_mut() {
        dm.body_height = body_h;
    }
    let body: Vec<Line> = match d.tab {
        DetailTab::Info => {
            let lines = info_lines(state, &d.target, 8);
            let max = lines.len().saturating_sub(body_h);
            let scroll = d.scroll.min(max);
            if let Some(dm) = state.detail.as_mut() {
                dm.scroll = scroll;
            }
            lines
                .into_iter()
                .skip(scroll)
                .take(body_h)
                .map(|l| Line::from(fit(l.spans, width)))
                .collect()
        }
        DetailTab::Events => {
            let lines = detail_events(state, &d.target);
            let max = lines.len().saturating_sub(body_h);
            let scroll = d.scroll.min(max);
            if let Some(dm) = state.detail.as_mut() {
                dm.scroll = scroll;
            }
            lines
                .into_iter()
                .skip(scroll)
                .take(body_h)
                .map(|l| Line::from(fit(l.spans, width)))
                .collect()
        }
        DetailTab::Log(ch) => log_body(&d, ch, body_h, width),
    };
    frame.render_widget(Paragraph::new(body), chunks[3]);

    let foot = match &state.input {
        Some(Input::Choose { .. }) | Some(Input::Confirm { .. }) => None,
        _ => state
            .toast
            .as_ref()
            .map(|t| vec![sp(fg(if t.bad { ERR } else { OK }), format!(" {}", t.text))]),
    };
    let foot = match foot {
        Some(f) => fit(f, width),
        None if state.input.is_some() => {
            // Reuse the main footer's prompt rendering.
            draw_footer(frame, chunks[4], state);
            return;
        }
        None => hints_fit(
            &[
                ("tab", "next"),
                ("1-5", "jump"),
                ("↑↓", "scroll"),
                ("←→", "pan"),
                ("f", "follow"),
                ("x", "act"),
                ("esc", "back"),
            ],
            width,
        ),
    };
    frame.render_widget(Paragraph::new(Line::from(foot)), chunks[4]);
}

fn detail_status(state: &State, d: &Detail, body_h: usize) -> Vec<Span<'static>> {
    let DetailTab::Log(ch) = d.tab else {
        return vec![];
    };
    let Some(buf) = d.logs.get(ch.as_str()) else {
        return vec![dim("loading… ")];
    };
    let mut out = Vec::new();
    if buf.error.is_some() {
        out.push(sp(fg(ERR), "fetch failed  "));
    }
    if d.follow {
        out.push(sp(fg(OK), "● "));
        out.push(sp(fg(MUTED), "following"));
    } else {
        let end = (d.scroll + body_h).min(buf.lines.len());
        out.push(dim(format!(
            "lines {}–{end} of {}",
            d.scroll + 1,
            buf.lines.len()
        )));
    }
    if let Some(t) = buf.fetched_at_ms {
        out.push(dim(format!(" · {}", fmt::clock(t))));
    }
    if buf.loading {
        out.push(sp(fg(ACCENT), format!(" {}", spinner(state))));
    }
    out.push(Span::raw(" "));
    out
}

fn log_body(d: &Detail, ch: LogChannel, body_h: usize, width: usize) -> Vec<Line<'static>> {
    let Some(buf) = d.logs.get(ch.as_str()) else {
        return vec![Line::from(dim("  loading…"))];
    };
    let mut out = Vec::new();
    if let Some(e) = &buf.error {
        out.push(Line::from(sp(fg(ERR), format!("  {e}"))));
    }
    if buf.lines.is_empty() && buf.error.is_none() {
        out.push(Line::from(dim(if buf.fetched_at_ms.is_some() {
            "  (empty)"
        } else {
            "  loading…"
        })));
    }
    let gutter = 6;
    let room = width.saturating_sub(gutter + 1);
    for (i, line) in buf
        .lines
        .iter()
        .enumerate()
        .skip(d.scroll)
        .take(body_h - out.len().min(body_h))
    {
        let text: String = skip_cols(line, d.pan);
        out.push(Line::from(vec![
            sp(fg(RULE), format!("{:>5} ", i + 1)),
            sp(fg(TEXT), fmt::truncate(&text, room)),
        ]));
    }
    out
}

/// `s` without its first `cols` display columns.
fn skip_cols(s: &str, cols: usize) -> String {
    if cols == 0 {
        return s.to_string();
    }
    let mut used = 0;
    let mut out = String::new();
    for c in s.chars() {
        if used >= cols {
            out.push(c);
        } else {
            used += fmt::width(c.encode_utf8(&mut [0; 4]));
        }
    }
    out
}

fn detail_events(state: &State, target: &RowKey) -> Vec<Line<'static>> {
    let entries: Vec<&JournalEntry> = state
        .journal
        .iter()
        .filter(|e| match target {
            RowKey::Vm(nk, id) => &e.node_key == nk && e.vm_id.as_ref() == Some(id),
            RowKey::Node(nk) => &e.node_key == nk,
            RowKey::Event(_) => false,
        })
        .collect();
    if entries.is_empty() {
        return vec![Line::from(dim("  no events seen yet"))];
    }
    entries
        .into_iter()
        .map(|e| {
            Line::from(vec![
                Span::raw("  "),
                event_glyph(e),
                dim(format!(" {}  ", fmt::stamp(e.at_ms))),
                sp(
                    if e.bad { fg(ERR) } else { fg(MUTED) },
                    fmt::pad(&e.title, 20),
                ),
                if matches!(target, RowKey::Node(_)) {
                    sp(
                        fg(TEXT),
                        format!("  {}", fmt::pad(e.vm_name.as_deref().unwrap_or("-"), 18)),
                    )
                } else {
                    Span::raw("")
                },
                dim(format!("  {}", e.body.replace('\n', " "))),
            ])
        })
        .collect()
}

// ── help ───────────────────────────────────────────────────────────────────

fn draw_help(frame: &mut Frame, area: Rect) {
    let keys: &[(&str, &str)] = &[
        ("1 2 3  tab", "fleet · vms · events"),
        ("↑↓  j k", "move"),
        ("pgup pgdn  g G", "page · top · bottom"),
        ("←→  h l", "fold · unfold a node"),
        ("z", "fold / unfold all"),
        ("enter", "open detail"),
        ("v", "preview pane"),
        ("x", "start · shutdown · restart · stop"),
        ("/", "filter by name, id, app, image, node"),
        ("a", "scope: all · live · attention"),
        ("s S  I", "sort key · invert"),
        ("r", "refresh now"),
        ("p  space", "pause"),
        ("+ -", "refresh interval"),
        ("in detail", "tab/1-5 switch · f follow · ←→ pan"),
        ("q  esc", "back · quit"),
    ];
    let w = 56u16.min(area.width.saturating_sub(4));
    let h = (keys.len() as u16 + 4).min(area.height.saturating_sub(2));
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(fg(RULE))
        .title(Span::styled(" keys ", fg(MUTED)));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let mut lines = vec![Line::from("")];
    lines.extend(keys.iter().map(|(k, v)| {
        Line::from(vec![
            sp(fg(TEXT).add_modifier(Modifier::BOLD), format!(" {k:<16}")),
            dim(v.to_string()),
        ])
    }));
    frame.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{NodeSnapshot, Resources};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn sample() -> State {
        let mut s = State::new(vec!["a".into(), "b".into()], 2000, false);
        s.now_ms = 1_700_000_000_000;
        let vm = |id: &str, name: &str, status: &str, boot: &str| Vm {
            id: id.into(),
            name: name.into(),
            status: status.into(),
            running: status == "running",
            uptime_secs: Some(93_000),
            boot_progress: boot.into(),
            vcpu: 8,
            memory_mb: 32768,
            disk_gb: 100,
            image: "dstack-0.5.3".into(),
            app_id: "1a2b3c4d5e6f".into(),
            ..Default::default()
        };
        s.apply_nodes(
            0,
            vec![NodeSnapshot {
                name: "tdx-01".into(),
                endpoint: "http://10.0.0.1:9080".into(),
                ok_at_ms: Some(1),
                latency_ms: Some(12),
                version: Some("0.6.1".into()),
                resources: Some(Resources {
                    max_cvms: 16,
                    max_vcpu: 64,
                    max_memory_mb: 262144,
                }),
                vms: vec![
                    vm(
                        "11111111-aaaa",
                        "web-frontend-with-a-long-name",
                        "running",
                        "done",
                    ),
                    vm("22222222-bbbb", "worker", "running", "requesting app keys"),
                    vm("33333333-cccc", "名字很长的应用", "exited", ""),
                ],
                ..Default::default()
            }],
            true,
        );
        s.apply_nodes(
            1,
            vec![NodeSnapshot {
                name: "tdx-02".into(),
                endpoint: "http://10.0.0.2:9080".into(),
                error: Some("connection refused".into()),
                ..Default::default()
            }],
            true,
        );
        s
    }

    fn render(state: &mut State, w: u16, h: u16) -> Vec<String> {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, state)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn renders_at_every_breakpoint_without_panicking() {
        for (w, h) in [(40, 10), (80, 24), (120, 30), (160, 40), (20, 5), (200, 60)] {
            let mut s = sample();
            for tab in Tab::ALL {
                s.set_tab(tab);
                s.preview = true;
                render(&mut s, w, h);
                s.help = true;
                render(&mut s, w, h);
                s.help = false;
            }
            s.set_tab(Tab::Fleet);
            s.move_to(1);
            s.open_detail();
            for t in DetailTab::VM {
                s.set_detail_tab(t);
                render(&mut s, w, h);
            }
        }
    }

    #[test]
    fn fleet_view_shows_tree_and_selection() {
        let mut s = sample();
        let screen = render(&mut s, 120, 30).join("\n");
        assert!(screen.contains("dstack"));
        assert!(screen.contains("tdx-01"));
        assert!(screen.contains("└ "));
        assert!(screen.contains("requesting app"));
        assert!(screen.contains("unreachable"));
        assert!(screen.contains("▌"));
        // Standard width carries IMAGE but not PORTS.
        assert!(screen.contains("IMAGE"));
        assert!(!screen.contains("PORTS"));
    }

    #[test]
    fn columns_by_width() {
        let (c, name) = columns(Tab::Fleet, 80);
        assert_eq!(
            c,
            [Col::Name, Col::Status, Col::Uptime, Col::Vcpu, Col::Mem]
        );
        assert!(name >= NAME_MIN);
        let (c, _) = columns(Tab::Vms, 160);
        assert!(c.contains(&Col::Ports) && c.contains(&Col::Node));
        let (c, _) = columns(Tab::Vms, 30);
        assert!(c.len() >= 2);
    }

    #[test]
    fn columns_fill_the_width_exactly() {
        for tab in [Tab::Fleet, Tab::Vms] {
            for w in 30..=220usize {
                let (cols, name) = columns(tab, w);
                let fixed: usize = cols.iter().map(|c| c.width() + SEP).sum::<usize>() - SEP;
                if name >= NAME_MIN {
                    assert_eq!(GUTTER + fixed + name, w, "{tab:?} {w}");
                }
            }
        }
        assert_eq!(
            fmt::width(&spans_text(&cell(vec![dim("名字很长的应用")], 7, false))),
            7
        );
        assert_eq!(fmt::width(&spans_text(&cell(vec![dim("7")], 5, true))), 5);
    }

    fn spans_text(spans: &[Span]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }
}
