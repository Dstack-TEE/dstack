// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TUI state and every decision about what is on screen: which rows, in what
//! order, which one is selected, what changed since the last poll. No I/O and
//! no drawing, so all of it is unit-tested.

use crate::fmt;
use crate::snapshot::{NodeSnapshot, Phase, Vm};
use crate::source::{Action, LogChannel};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

pub const INTERVAL_STEPS_MS: [u64; 5] = [1000, 2000, 5000, 10_000, 30_000];
const JOURNAL_CAP: usize = 2000;
pub const LOG_LINES: u32 = 2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Fleet,
    Vms,
    Events,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Fleet, Tab::Vms, Tab::Events];

    pub fn label(self) -> &'static str {
        match self {
            Tab::Fleet => "Fleet",
            Tab::Vms => "VMs",
            Tab::Events => "Events",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    All,
    Live,
    Attention,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Scope::All => "all",
            Scope::Live => "live",
            Scope::Attention => "attention",
        }
    }

    fn next(self) -> Self {
        match self {
            Scope::All => Scope::Live,
            Scope::Live => Scope::Attention,
            Scope::Attention => Scope::All,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    Status,
    Name,
    Node,
    Uptime,
    Vcpu,
    Memory,
}

impl SortKey {
    const ORDER: [SortKey; 6] = [
        SortKey::Status,
        SortKey::Name,
        SortKey::Node,
        SortKey::Uptime,
        SortKey::Vcpu,
        SortKey::Memory,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SortKey::Status => "status",
            SortKey::Name => "name",
            SortKey::Node => "node",
            SortKey::Uptime => "uptime",
            SortKey::Vcpu => "vcpu",
            SortKey::Memory => "memory",
        }
    }

    fn step(self, forward: bool) -> Self {
        let i = Self::ORDER.iter().position(|k| *k == self).unwrap_or(0);
        let n = Self::ORDER.len();
        Self::ORDER[if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        }]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RowKey {
    Node(String),
    Vm(String, String),
    Event(u64),
}

/// One line of the main list.
#[derive(Clone, Debug)]
pub struct Row {
    pub key: RowKey,
    pub node: usize,
    pub vm: Option<usize>,
    pub event: Option<usize>,
    /// Last child under its node, for the tree guide.
    pub last: bool,
}

#[derive(Clone, Debug)]
pub struct NodeEntry {
    /// `<source index>/<name>`; stable across polls.
    pub key: String,
    pub source: usize,
    pub writable: bool,
    pub snap: NodeSnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Guest,
    Change,
    NodeDown,
    NodeUp,
    Action,
}

#[derive(Clone, Debug)]
pub struct JournalEntry {
    pub seq: u64,
    pub at_ms: u64,
    pub kind: EntryKind,
    pub node_key: String,
    pub node: String,
    pub vm_id: Option<String>,
    pub vm_name: Option<String>,
    pub title: String,
    pub body: String,
    /// Bad news, drawn in the error color.
    pub bad: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetailTab {
    Info,
    Log(LogChannel),
    Events,
}

impl DetailTab {
    pub const VM: [DetailTab; 5] = [
        DetailTab::Info,
        DetailTab::Log(LogChannel::Serial),
        DetailTab::Log(LogChannel::Stdout),
        DetailTab::Log(LogChannel::Stderr),
        DetailTab::Events,
    ];
    pub const NODE: [DetailTab; 2] = [DetailTab::Info, DetailTab::Events];

    pub fn label(self) -> &'static str {
        match self {
            DetailTab::Info => "Info",
            DetailTab::Log(LogChannel::Serial) => "Serial",
            DetailTab::Log(LogChannel::Stdout) => "Stdout",
            DetailTab::Log(LogChannel::Stderr) => "Stderr",
            DetailTab::Events => "Events",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct LogBuf {
    pub lines: Vec<String>,
    pub fetched_at_ms: Option<u64>,
    pub error: Option<String>,
    pub loading: bool,
}

#[derive(Clone, Debug)]
pub struct Detail {
    pub target: RowKey,
    pub tab: DetailTab,
    /// First visible body line.
    pub scroll: usize,
    /// Columns panned right in log views.
    pub pan: usize,
    /// Stick to the bottom as logs grow.
    pub follow: bool,
    pub logs: HashMap<&'static str, LogBuf>,
    /// Body height at the last draw, for paging and follow.
    pub body_height: usize,
}

impl Detail {
    pub fn new(target: RowKey) -> Self {
        Self {
            target,
            tab: DetailTab::Info,
            scroll: 0,
            pan: 0,
            follow: true,
            logs: HashMap::new(),
            body_height: 0,
        }
    }

    pub fn tabs(&self) -> &'static [DetailTab] {
        match self.target {
            RowKey::Node(_) => &DetailTab::NODE,
            _ => &DetailTab::VM,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Filter(String),
    Choose {
        node_key: String,
        vm_id: String,
        vm_name: String,
    },
    Confirm {
        node_key: String,
        vm_id: String,
        vm_name: String,
        action: Action,
    },
}

#[derive(Clone, Debug)]
pub struct Toast {
    pub text: String,
    pub bad: bool,
    pub until_ms: u64,
}

/// Screen regions the last draw put where, for mouse hits.
#[derive(Clone, Debug, Default)]
pub struct Hits {
    pub tabs: Vec<(u16, u16, u16, Tab)>,
    pub list_y: u16,
    pub list_h: u16,
    pub detail_tabs: Vec<(u16, u16, u16, DetailTab)>,
}

/// What the UI asks the collector for after handling input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Refresh,
    Logs {
        source: usize,
        node: String,
        vm_id: String,
        channel: LogChannel,
    },
    Act {
        source: usize,
        vm_id: String,
        what: String,
        action: Action,
    },
    SetInterval(u64),
    Quit,
}

pub struct State {
    pub nodes: Vec<NodeEntry>,
    pub sources: Vec<String>,
    pub tab: Tab,
    pub scope: Scope,
    pub sort: SortKey,
    pub sort_rev: bool,
    pub filter: String,
    pub input: Option<Input>,
    pub folded: HashSet<String>,
    pub sel: Option<RowKey>,
    sel_idx: usize,
    /// The user picked the selection; until then it stays on the first row
    /// while nodes arrive in whatever order they answer.
    sel_pinned: bool,
    pub offset: usize,
    pub list_height: usize,
    pub preview: bool,
    pub help: bool,
    pub detail: Option<Detail>,
    pub journal: VecDeque<JournalEntry>,
    seen_guest: HashSet<(String, String, u64, String)>,
    seq: u64,
    pub toast: Option<Toast>,
    pub interval_ms: u64,
    pub paused: bool,
    pub now_ms: u64,
    pub updated_ms: u64,
    pub frame: u64,
    pub read_only: bool,
    pub hits: Hits,
    /// Polls received while paused, applied on resume.
    pending: Vec<(usize, Vec<NodeSnapshot>, bool)>,
}

impl State {
    pub fn new(sources: Vec<String>, interval_ms: u64, read_only: bool) -> Self {
        Self {
            nodes: Vec::new(),
            sources,
            tab: Tab::Fleet,
            scope: Scope::All,
            sort: SortKey::Status,
            sort_rev: false,
            filter: String::new(),
            input: None,
            folded: HashSet::new(),
            sel: None,
            sel_idx: 0,
            sel_pinned: false,
            offset: 0,
            list_height: 20,
            preview: false,
            help: false,
            detail: None,
            journal: VecDeque::new(),
            seen_guest: HashSet::new(),
            seq: 0,
            toast: None,
            interval_ms,
            paused: false,
            now_ms: 0,
            updated_ms: 0,
            frame: 0,
            read_only,
            hits: Hits::default(),
            pending: Vec::new(),
        }
    }

    // ── data in ───────────────────────────────────────────────────────────

    /// Replace the nodes of one source with a fresh poll, journaling what
    /// changed.
    pub fn apply_nodes(&mut self, source: usize, nodes: Vec<NodeSnapshot>, writable: bool) {
        if self.paused {
            self.pending.retain(|(s, _, _)| *s != source);
            self.pending.push((source, nodes, writable));
            return;
        }
        let now = self.now_ms;
        self.updated_ms = now;
        let old: HashMap<String, NodeEntry> = self
            .nodes
            .iter()
            .filter(|n| n.source == source)
            .map(|n| (n.key.clone(), n.clone()))
            .collect();
        let fresh: Vec<NodeEntry> = nodes
            .into_iter()
            .map(|snap| NodeEntry {
                key: format!("{source}/{}", snap.name),
                source,
                writable,
                snap,
            })
            .collect();
        for n in &fresh {
            self.journal_node(old.get(&n.key), n, now);
        }
        // Keep source order, then the order the source listed its nodes.
        let at = self
            .nodes
            .iter()
            .position(|n| n.source > source)
            .unwrap_or(self.nodes.len());
        self.nodes.retain(|n| n.source != source);
        let at = at.min(
            self.nodes
                .iter()
                .position(|n| n.source > source)
                .unwrap_or(self.nodes.len()),
        );
        self.nodes.splice(at..at, fresh);
        self.clamp_selection();
    }

    fn journal_node(&mut self, old: Option<&NodeEntry>, new: &NodeEntry, now: u64) {
        let snap = &new.snap;
        let name = display_node(snap);
        let entry = |kind, vm: Option<&Vm>, title: String, body: String, bad: bool| JournalEntry {
            seq: 0,
            at_ms: now,
            kind,
            node_key: new.key.clone(),
            node: name.clone(),
            vm_id: vm.map(|v| v.id.clone()),
            vm_name: vm.map(|v| v.name.clone()),
            title,
            body,
            bad,
        };
        let mut out = Vec::new();
        match (old.map(|o| o.snap.error.is_some()), snap.error.as_ref()) {
            (Some(false) | None, Some(err)) => out.push(entry(
                EntryKind::NodeDown,
                None,
                "unreachable".into(),
                err.clone(),
                true,
            )),
            (Some(true), None) => out.push(entry(
                EntryKind::NodeUp,
                None,
                "reachable".into(),
                String::new(),
                false,
            )),
            _ => {}
        }
        // Only a poll that succeeded says anything about the VMs.
        if snap.error.is_none() {
            if let Some(old) = old.filter(|o| o.snap.ok_at_ms.is_some()) {
                let before: HashMap<&str, &Vm> =
                    old.snap.vms.iter().map(|v| (v.id.as_str(), v)).collect();
                for vm in &snap.vms {
                    match before.get(vm.id.as_str()) {
                        None => out.push(entry(
                            EntryKind::Change,
                            Some(vm),
                            "created".into(),
                            vm.phase().label().into(),
                            false,
                        )),
                        Some(prev) if prev.phase() != vm.phase() => {
                            let to = vm.phase();
                            let body = vm.activity().map(str::to_string).unwrap_or_default();
                            out.push(entry(
                                EntryKind::Change,
                                Some(vm),
                                format!("{} → {}", prev.phase().label(), to.label()),
                                body,
                                matches!(to, Phase::Failed | Phase::Exited),
                            ));
                        }
                        _ => {}
                    }
                }
                let now_ids: HashSet<&str> = snap.vms.iter().map(|v| v.id.as_str()).collect();
                for vm in &old.snap.vms {
                    if !now_ids.contains(vm.id.as_str()) {
                        out.push(entry(
                            EntryKind::Change,
                            Some(vm),
                            "removed".into(),
                            String::new(),
                            false,
                        ));
                    }
                }
            }
            for vm in &snap.vms {
                for ev in &vm.events {
                    let key = (
                        new.key.clone(),
                        vm.id.clone(),
                        ev.timestamp_ms,
                        format!("{}\u{0}{}", ev.event, ev.body),
                    );
                    if self.seen_guest.insert(key) {
                        let mut e = entry(
                            EntryKind::Guest,
                            Some(vm),
                            ev.event.clone(),
                            ev.body.clone(),
                            ev.event.contains("error"),
                        );
                        e.at_ms = ev.timestamp_ms;
                        out.push(e);
                    }
                }
            }
        }
        for e in out {
            self.push_journal(e);
        }
    }

    pub fn push_journal(&mut self, mut e: JournalEntry) {
        self.seq += 1;
        e.seq = self.seq;
        // Newest first; guest events can arrive with older timestamps.
        let at = self
            .journal
            .iter()
            .position(|j| j.at_ms <= e.at_ms)
            .unwrap_or(self.journal.len());
        self.journal.insert(at, e);
        while self.journal.len() > JOURNAL_CAP {
            self.journal.pop_back();
        }
        if self.seen_guest.len() > JOURNAL_CAP * 4 {
            self.seen_guest.clear();
        }
    }

    pub fn apply_logs(
        &mut self,
        target: &RowKey,
        channel: LogChannel,
        result: Result<String, String>,
    ) {
        let now = self.now_ms;
        let Some(d) = self.detail.as_mut().filter(|d| &d.target == target) else {
            return;
        };
        let buf = d.logs.entry(channel.as_str()).or_default();
        buf.loading = false;
        match result {
            Ok(text) => {
                buf.lines = text
                    .lines()
                    .filter(|l| *l != "[vmm heartbeat]")
                    .map(fmt::sanitize)
                    .collect();
                buf.error = None;
                buf.fetched_at_ms = Some(now);
            }
            Err(err) => buf.error = Some(err),
        }
        if d.follow && d.tab == DetailTab::Log(channel) {
            d.scroll = buf.lines.len().saturating_sub(d.body_height.max(1));
        }
    }

    pub fn toast(&mut self, text: impl Into<String>, bad: bool) {
        self.toast = Some(Toast {
            text: text.into(),
            bad,
            until_ms: self.now_ms + 5000,
        });
    }

    pub fn acted(&mut self, what: &str, action: Action, result: Result<(), String>) {
        match result {
            Ok(()) => self.toast(format!("{} {what}: sent", action.label()), false),
            Err(err) => self.toast(format!("{} {what} failed: {err}", action.label()), true),
        }
    }

    // ── lookups ───────────────────────────────────────────────────────────

    pub fn node(&self, key: &str) -> Option<&NodeEntry> {
        self.nodes.iter().find(|n| n.key == key)
    }

    pub fn vm(&self, node_key: &str, vm_id: &str) -> Option<(&NodeEntry, &Vm)> {
        let n = self.node(node_key)?;
        Some((n, n.snap.vms.iter().find(|v| v.id == vm_id)?))
    }

    pub fn event(&self, seq: u64) -> Option<&JournalEntry> {
        self.journal.iter().find(|e| e.seq == seq)
    }

    /// Something on screen is changing on its own, so redraw on a timer.
    pub fn animating(&self) -> bool {
        !self.paused
            && self.nodes.iter().any(|n| {
                (n.snap.ok_at_ms.is_none() && n.snap.error.is_none())
                    || n.snap.vms.iter().any(|v| v.phase().is_transient())
            })
    }

    // ── rows ──────────────────────────────────────────────────────────────

    fn vm_matches(&self, n: &NodeEntry, vm: &Vm) -> bool {
        let phase = vm.phase();
        let in_scope = match self.scope {
            Scope::All => true,
            Scope::Live => phase.is_live(),
            Scope::Attention => phase.needs_attention(),
        };
        in_scope && (self.filter.is_empty() || self.text_matches(n, Some(vm)))
    }

    fn text_matches(&self, n: &NodeEntry, vm: Option<&Vm>) -> bool {
        let needle = self.filter.to_lowercase();
        let hit = |s: &str| s.to_lowercase().contains(&needle);
        match vm {
            None => hit(&n.snap.name) || hit(&n.snap.endpoint),
            Some(vm) => {
                hit(&vm.name)
                    || hit(&vm.id)
                    || hit(&vm.app_id)
                    || hit(&vm.image)
                    || hit(vm.phase().label())
                    || vm.instance_id.as_deref().is_some_and(hit)
                    || hit(&n.snap.name)
            }
        }
    }

    fn node_attention(n: &NodeEntry) -> bool {
        n.snap.error.is_some() || n.snap.vms.iter().any(|v| v.phase().needs_attention())
    }

    fn cmp_vms(&self, a: (&NodeEntry, &Vm), b: (&NodeEntry, &Vm)) -> Ordering {
        let by_name = |a: &Vm, b: &Vm| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        };
        let (na, va) = a;
        let (nb, vb) = b;
        let ord = match self.sort {
            SortKey::Status => va.phase().cmp(&vb.phase()),
            SortKey::Name => Ordering::Equal,
            SortKey::Node => na.snap.name.cmp(&nb.snap.name),
            // Biggest first reads best for quantities.
            SortKey::Uptime => vb.uptime_secs.cmp(&va.uptime_secs),
            SortKey::Vcpu => vb.vcpu.cmp(&va.vcpu),
            SortKey::Memory => vb.memory_mb.cmp(&va.memory_mb),
        }
        .then_with(|| by_name(va, vb));
        if self.sort_rev {
            ord.reverse()
        } else {
            ord
        }
    }

    pub fn rows(&self) -> Vec<Row> {
        match self.tab {
            Tab::Fleet => self.fleet_rows(),
            Tab::Vms => self.vm_rows(),
            Tab::Events => self.event_rows(),
        }
    }

    fn sorted_vms(&self, node: usize) -> Vec<usize> {
        let n = &self.nodes[node];
        let mut idx: Vec<usize> = (0..n.snap.vms.len())
            .filter(|&i| self.vm_matches(n, &n.snap.vms[i]))
            .collect();
        idx.sort_by(|&a, &b| self.cmp_vms((n, &n.snap.vms[a]), (n, &n.snap.vms[b])));
        idx
    }

    fn fleet_rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        for (ni, n) in self.nodes.iter().enumerate() {
            let vms = self.sorted_vms(ni);
            let filtered_out =
                !self.filter.is_empty() && vms.is_empty() && !self.text_matches(n, None);
            let calm = self.scope == Scope::Attention && !Self::node_attention(n);
            if filtered_out || calm {
                continue;
            }
            rows.push(Row {
                key: RowKey::Node(n.key.clone()),
                node: ni,
                vm: None,
                event: None,
                last: false,
            });
            if self.folded.contains(&n.key) {
                continue;
            }
            let count = vms.len();
            for (i, vi) in vms.into_iter().enumerate() {
                rows.push(Row {
                    key: RowKey::Vm(n.key.clone(), n.snap.vms[vi].id.clone()),
                    node: ni,
                    vm: Some(vi),
                    event: None,
                    last: i + 1 == count,
                });
            }
        }
        rows
    }

    fn vm_rows(&self) -> Vec<Row> {
        let mut all: Vec<(usize, usize)> = Vec::new();
        for (ni, n) in self.nodes.iter().enumerate() {
            for (vi, vm) in n.snap.vms.iter().enumerate() {
                if self.vm_matches(n, vm) {
                    all.push((ni, vi));
                }
            }
        }
        all.sort_by(|&(na, va), &(nb, vb)| {
            let (a, b) = (&self.nodes[na], &self.nodes[nb]);
            self.cmp_vms((a, &a.snap.vms[va]), (b, &b.snap.vms[vb]))
        });
        all.into_iter()
            .map(|(ni, vi)| Row {
                key: RowKey::Vm(
                    self.nodes[ni].key.clone(),
                    self.nodes[ni].snap.vms[vi].id.clone(),
                ),
                node: ni,
                vm: Some(vi),
                event: None,
                last: false,
            })
            .collect()
    }

    fn event_rows(&self) -> Vec<Row> {
        let needle = self.filter.to_lowercase();
        self.journal
            .iter()
            .enumerate()
            .filter(|(_, e)| match self.scope {
                Scope::Attention => e.bad,
                _ => true,
            })
            .filter(|(_, e)| {
                needle.is_empty()
                    || [&e.node, &e.title, &e.body]
                        .into_iter()
                        .chain(e.vm_name.as_ref())
                        .chain(e.vm_id.as_ref())
                        .any(|s| s.to_lowercase().contains(&needle))
            })
            .map(|(i, e)| Row {
                key: RowKey::Event(e.seq),
                node: self
                    .nodes
                    .iter()
                    .position(|n| n.key == e.node_key)
                    .unwrap_or(usize::MAX),
                vm: None,
                event: Some(i),
                last: false,
            })
            .collect()
    }

    pub fn count(&self, tab: Tab) -> usize {
        match tab {
            Tab::Fleet => self.nodes.len(),
            Tab::Vms => self
                .nodes
                .iter()
                .map(|n| n.snap.vms.iter().filter(|v| self.vm_matches(n, v)).count())
                .sum(),
            Tab::Events => self.journal.len(),
        }
    }

    // ── selection ─────────────────────────────────────────────────────────

    /// Keep the selection on the same item across polls; when it went away,
    /// stay at the same position.
    pub fn clamp_selection(&mut self) {
        let rows = self.rows();
        if rows.is_empty() {
            self.sel = None;
            self.sel_idx = 0;
            self.offset = 0;
            return;
        }
        let idx = self
            .sel
            .as_ref()
            .filter(|_| self.sel_pinned)
            .and_then(|k| rows.iter().position(|r| &r.key == k))
            .unwrap_or(self.sel_idx.min(rows.len() - 1));
        self.select_idx(&rows, idx);
    }

    fn select_idx(&mut self, rows: &[Row], idx: usize) {
        let idx = idx.min(rows.len().saturating_sub(1));
        self.sel_idx = idx;
        self.sel = rows.get(idx).map(|r| r.key.clone());
        let h = self.list_height.max(1);
        if idx < self.offset {
            self.offset = idx;
        } else if idx >= self.offset + h {
            self.offset = idx + 1 - h;
        }
        self.offset = self.offset.min(rows.len().saturating_sub(h));
    }

    pub fn selected_index(&self) -> usize {
        self.sel_idx
    }

    pub fn move_by(&mut self, delta: isize) {
        self.sel_pinned = true;
        let rows = self.rows();
        if rows.is_empty() {
            return;
        }
        let idx = (self.sel_idx as isize + delta).clamp(0, rows.len() as isize - 1);
        self.select_idx(&rows, idx as usize);
    }

    pub fn move_to(&mut self, idx: usize) {
        self.sel_pinned = true;
        let rows = self.rows();
        self.select_idx(&rows, idx);
    }

    pub fn set_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            self.sel = None;
            self.sel_idx = 0;
            self.sel_pinned = false;
            self.offset = 0;
            self.clamp_selection();
        }
    }

    // ── input ─────────────────────────────────────────────────────────────

    pub fn fold(&mut self, open: bool) {
        self.sel_pinned = true;
        match self.sel.clone() {
            Some(RowKey::Node(k)) => {
                if open {
                    self.folded.remove(&k);
                } else {
                    self.folded.insert(k);
                }
            }
            Some(RowKey::Vm(k, _)) if !open && self.tab == Tab::Fleet => {
                self.sel = Some(RowKey::Node(k));
            }
            _ => {}
        }
        self.clamp_selection();
    }

    pub fn toggle_fold_all(&mut self) {
        self.sel_pinned = true;
        if self.folded.is_empty() {
            self.folded = self.nodes.iter().map(|n| n.key.clone()).collect();
            if let Some(RowKey::Vm(k, _)) = self.sel.clone() {
                self.sel = Some(RowKey::Node(k));
            }
        } else {
            self.folded.clear();
        }
        self.clamp_selection();
    }

    pub fn cycle_scope(&mut self) {
        self.scope = self.scope.next();
        self.clamp_selection();
    }

    pub fn cycle_sort(&mut self, forward: bool) {
        self.sort = self.sort.step(forward);
        self.clamp_selection();
    }

    pub fn invert_sort(&mut self) {
        self.sort_rev = !self.sort_rev;
        self.clamp_selection();
    }

    pub fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.clamp_selection();
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
        if !paused {
            for (s, nodes, w) in std::mem::take(&mut self.pending) {
                self.apply_nodes(s, nodes, w);
            }
        }
    }

    pub fn step_interval(&mut self, faster: bool) -> u64 {
        let i = INTERVAL_STEPS_MS
            .iter()
            .position(|&s| s >= self.interval_ms)
            .unwrap_or(INTERVAL_STEPS_MS.len() - 1);
        let i = if faster {
            i.saturating_sub(1)
        } else {
            (i + 1).min(INTERVAL_STEPS_MS.len() - 1)
        };
        self.interval_ms = INTERVAL_STEPS_MS[i];
        self.interval_ms
    }

    /// The VM the selection points at, directly or through an event.
    pub fn selected_vm(&self) -> Option<(String, String)> {
        match self.sel.as_ref()? {
            RowKey::Vm(n, v) => Some((n.clone(), v.clone())),
            RowKey::Event(seq) => {
                let e = self.event(*seq)?;
                Some((e.node_key.clone(), e.vm_id.clone()?))
            }
            RowKey::Node(_) => None,
        }
    }

    /// Start the action prompt for the selected VM.
    pub fn begin_action(&mut self) {
        if self.read_only {
            self.toast("read-only: started with --read-only", true);
            return;
        }
        let Some((node_key, vm_id)) = self.selected_vm() else {
            self.toast("select a VM to act on", true);
            return;
        };
        let Some((n, vm)) = self.vm(&node_key, &vm_id) else {
            return;
        };
        if !n.writable {
            self.toast(format!("read-only: {}", n.snap.name), true);
            return;
        }
        self.input = Some(Input::Choose {
            node_key,
            vm_id,
            vm_name: vm.name.clone(),
        });
    }

    pub fn choose_action(&mut self, action: Action) {
        if let Some(Input::Choose {
            node_key,
            vm_id,
            vm_name,
        }) = self.input.take()
        {
            self.input = Some(Input::Confirm {
                node_key,
                vm_id,
                vm_name,
                action,
            });
        }
    }

    pub fn confirm_action(&mut self) -> Option<Effect> {
        let Some(Input::Confirm {
            node_key,
            vm_id,
            vm_name,
            action,
        }) = self.input.take()
        else {
            return None;
        };
        let n = self.node(&node_key)?;
        let what = format!("{vm_name} on {}", n.snap.name);
        let source = n.source;
        let node = n.snap.name.clone();
        let now = self.now_ms;
        self.push_journal(JournalEntry {
            seq: 0,
            at_ms: now,
            kind: EntryKind::Action,
            node_key,
            node,
            vm_id: Some(vm_id.clone()),
            vm_name: Some(vm_name),
            title: action.label().into(),
            body: "requested from this terminal".into(),
            bad: false,
        });
        self.toast(format!("{}: {what}…", action.label()), false);
        Some(Effect::Act {
            source,
            vm_id,
            what,
            action,
        })
    }

    /// Open the detail view for the selection.
    pub fn open_detail(&mut self) -> Vec<Effect> {
        let target = match self.sel.clone() {
            Some(RowKey::Event(seq)) => match self.event(seq) {
                Some(e) => match &e.vm_id {
                    Some(v) if self.vm(&e.node_key, v).is_some() => {
                        RowKey::Vm(e.node_key.clone(), v.clone())
                    }
                    _ if self.node(&e.node_key).is_some() => RowKey::Node(e.node_key.clone()),
                    _ => return vec![],
                },
                None => return vec![],
            },
            Some(k) => k,
            None => return vec![],
        };
        self.detail = Some(Detail::new(target));
        self.detail_fetch()
    }

    pub fn set_detail_tab(&mut self, tab: DetailTab) -> Vec<Effect> {
        let Some(d) = self.detail.as_mut() else {
            return vec![];
        };
        if !d.tabs().contains(&tab) {
            return vec![];
        }
        d.tab = tab;
        d.pan = 0;
        d.follow = matches!(tab, DetailTab::Log(_));
        d.scroll = match tab {
            DetailTab::Log(ch) => d
                .logs
                .get(ch.as_str())
                .map_or(0, |b| b.lines.len().saturating_sub(d.body_height.max(1))),
            _ => 0,
        };
        self.detail_fetch()
    }

    pub fn step_detail_tab(&mut self, forward: bool) -> Vec<Effect> {
        let Some(d) = self.detail.as_ref() else {
            return vec![];
        };
        let tabs = d.tabs();
        let i = tabs.iter().position(|t| *t == d.tab).unwrap_or(0);
        let n = tabs.len();
        let next = tabs[if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        }];
        self.set_detail_tab(next)
    }

    /// Log fetch for the open detail tab, if it shows a log that is due.
    pub fn detail_fetch(&mut self) -> Vec<Effect> {
        let Some(d) = self.detail.as_ref() else {
            return vec![];
        };
        let (DetailTab::Log(channel), RowKey::Vm(node_key, vm_id)) = (d.tab, &d.target) else {
            return vec![];
        };
        let Some(n) = self.node(node_key) else {
            return vec![];
        };
        let effect = Effect::Logs {
            source: n.source,
            node: n.snap.name.clone(),
            vm_id: vm_id.clone(),
            channel,
        };
        let interval = self.interval_ms;
        let now = self.now_ms;
        let Some(d) = self.detail.as_mut() else {
            return vec![];
        };
        let buf = d.logs.entry(channel.as_str()).or_default();
        let due = buf
            .fetched_at_ms
            .is_none_or(|t| now.saturating_sub(t) >= interval);
        if buf.loading || !due {
            return vec![];
        }
        buf.loading = true;
        vec![effect]
    }

    pub fn detail_lines_len(&self) -> usize {
        let Some(d) = self.detail.as_ref() else {
            return 0;
        };
        match d.tab {
            DetailTab::Log(ch) => d.logs.get(ch.as_str()).map_or(0, |b| b.lines.len()),
            _ => usize::MAX,
        }
    }

    pub fn scroll_detail(&mut self, delta: isize) {
        let len = self.detail_lines_len();
        let Some(d) = self.detail.as_mut() else {
            return;
        };
        let max = if len == usize::MAX {
            usize::MAX / 2
        } else {
            len.saturating_sub(d.body_height.max(1))
        };
        let next = (d.scroll as isize + delta).clamp(0, max as isize) as usize;
        d.scroll = next;
        if matches!(d.tab, DetailTab::Log(_)) {
            d.follow = next >= max;
        }
    }

    pub fn tick(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        self.frame = self.frame.wrapping_add(1);
        if self.toast.as_ref().is_some_and(|t| t.until_ms <= now_ms) {
            self.toast = None;
        }
    }
}

/// How a node is named on screen.
pub fn display_node(s: &NodeSnapshot) -> String {
    s.name.clone()
}

// ── fleet totals ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Totals {
    pub nodes: usize,
    pub nodes_up: usize,
    pub nodes_connecting: usize,
    pub vms: usize,
    pub by_phase: Vec<(Phase, usize)>,
    pub vcpu_used: u64,
    pub vcpu_max: u64,
    pub mem_used_mb: u64,
    pub mem_max_mb: u64,
    pub gpus_used: usize,
    pub gpus: usize,
    pub disk_gb: u64,
}

pub fn totals(nodes: &[NodeEntry]) -> Totals {
    let mut t = Totals {
        nodes: nodes.len(),
        ..Default::default()
    };
    let mut phases: HashMap<Phase, usize> = HashMap::new();
    for n in nodes {
        let s = &n.snap;
        if s.online() {
            t.nodes_up += 1;
        } else if s.error.is_none() {
            t.nodes_connecting += 1;
        }
        t.vms += s.vms.len();
        for vm in &s.vms {
            *phases.entry(vm.phase()).or_default() += 1;
        }
        t.vcpu_used += s.vcpu_used() as u64;
        t.mem_used_mb += s.memory_used_mb();
        t.disk_gb += s.disk_gb();
        if let Some(r) = &s.resources {
            t.vcpu_max += r.max_vcpu as u64;
            t.mem_max_mb += r.max_memory_mb as u64;
        }
        t.gpus += s.gpus.len();
        t.gpus_used += s.gpus_used();
    }
    let mut by_phase: Vec<_> = phases.into_iter().collect();
    by_phase.sort();
    t.by_phase = by_phase;
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{GuestEvent, Resources};

    fn vm(id: &str, name: &str, status: &str, vcpu: u32) -> Vm {
        Vm {
            id: id.into(),
            name: name.into(),
            status: status.into(),
            running: status == "running",
            boot_progress: "done".into(),
            vcpu,
            memory_mb: 1024 * vcpu,
            ..Default::default()
        }
    }

    fn node(name: &str, vms: Vec<Vm>) -> NodeSnapshot {
        NodeSnapshot {
            name: name.into(),
            endpoint: format!("http://{name}:9080"),
            ok_at_ms: Some(1),
            resources: Some(Resources {
                max_cvms: 10,
                max_vcpu: 64,
                max_memory_mb: 65536,
            }),
            vms,
            ..Default::default()
        }
    }

    fn state() -> State {
        let mut s = State::new(vec!["a".into(), "b".into()], 2000, false);
        s.now_ms = 10_000;
        s.apply_nodes(
            0,
            vec![node(
                "a",
                vec![
                    vm("1", "web", "running", 4),
                    vm("2", "db", "exited", 8),
                    vm("3", "old", "stopped", 2),
                ],
            )],
            true,
        );
        s.apply_nodes(1, vec![node("b", vec![vm("4", "api", "running", 2)])], true);
        s
    }

    fn keys(s: &State) -> Vec<String> {
        s.rows()
            .iter()
            .map(|r| match &r.key {
                RowKey::Node(k) => format!("N:{k}"),
                RowKey::Vm(_, v) => v.clone(),
                RowKey::Event(e) => format!("E{e}"),
            })
            .collect()
    }

    #[test]
    fn fleet_tree_sorts_by_status_then_name() {
        let s = state();
        // exited (attention) before running before stopped.
        assert_eq!(keys(&s), ["N:0/a", "2", "1", "3", "N:1/b", "4"]);
        let mut s = s;
        s.sort = SortKey::Name;
        s.clamp_selection();
        assert_eq!(keys(&s), ["N:0/a", "2", "3", "1", "N:1/b", "4"]);
        s.sort = SortKey::Vcpu;
        assert_eq!(keys(&s), ["N:0/a", "2", "1", "3", "N:1/b", "4"]);
        s.invert_sort();
        assert_eq!(keys(&s), ["N:0/a", "3", "1", "2", "N:1/b", "4"]);
    }

    #[test]
    fn scopes_and_filter() {
        let mut s = state();
        s.cycle_scope(); // live
        assert_eq!(keys(&s), ["N:0/a", "1", "N:1/b", "4"]);
        s.cycle_scope(); // attention: calm node b disappears
        assert_eq!(keys(&s), ["N:0/a", "2"]);
        s.cycle_scope();
        s.set_filter("API".into());
        assert_eq!(keys(&s), ["N:1/b", "4"]);
        s.set_filter("b".into()); // "web", "db", and every VM on node "b"
        assert_eq!(keys(&s), ["N:0/a", "2", "1", "N:1/b", "4"]);
    }

    #[test]
    fn vm_tab_is_flat_across_nodes() {
        let mut s = state();
        s.set_tab(Tab::Vms);
        s.sort = SortKey::Name;
        assert_eq!(keys(&s), ["4", "2", "3", "1"]);
        assert_eq!(s.count(Tab::Vms), 4);
    }

    #[test]
    fn selection_follows_item_across_polls() {
        let mut s = state();
        s.move_to(3); // "3" old
        assert_eq!(s.sel, Some(RowKey::Vm("0/a".into(), "3".into())));
        // A new VM shifts "old" down a row; the selection moves with it.
        s.apply_nodes(
            0,
            vec![node(
                "a",
                vec![
                    vm("0", "new", "running", 1),
                    vm("1", "web", "exited", 4),
                    vm("2", "db", "exited", 8),
                    vm("3", "old", "stopped", 2),
                ],
            )],
            true,
        );
        assert_eq!(s.sel, Some(RowKey::Vm("0/a".into(), "3".into())));
        assert_eq!(s.selected_index(), 4);
        // It disappears: selection stays at the same position.
        s.apply_nodes(0, vec![node("a", vec![vm("0", "new", "running", 1)])], true);
        assert_eq!(s.selected_index(), 3);
        assert_eq!(s.sel, Some(RowKey::Vm("1/b".into(), "4".into())));
    }

    #[test]
    fn selection_stays_on_top_until_the_user_moves() {
        let mut s = State::new(vec!["a".into(), "b".into()], 2000, false);
        s.apply_nodes(1, vec![node("b", vec![])], true);
        assert_eq!(s.sel, Some(RowKey::Node("1/b".into())));
        s.apply_nodes(0, vec![node("a", vec![])], true);
        assert_eq!(s.sel, Some(RowKey::Node("0/a".into())));
    }

    #[test]
    fn folding() {
        let mut s = state();
        s.move_to(1);
        s.fold(false); // on a VM: jump to its node
        assert_eq!(s.sel, Some(RowKey::Node("0/a".into())));
        s.fold(false);
        assert_eq!(keys(&s), ["N:0/a", "N:1/b", "4"]);
        s.fold(true);
        assert_eq!(keys(&s).len(), 6);
        s.toggle_fold_all();
        assert_eq!(keys(&s), ["N:0/a", "N:1/b"]);
        s.toggle_fold_all();
        assert_eq!(keys(&s).len(), 6);
    }

    #[test]
    fn journal_records_transitions_and_outages() {
        let mut s = state();
        let base = s.journal.len();
        s.now_ms = 20_000;
        s.apply_nodes(
            0,
            vec![node(
                "a",
                vec![vm("1", "web", "exited", 4), vm("2", "db", "exited", 8)],
            )],
            true,
        );
        let titles: Vec<_> = s.journal.iter().take(2).map(|e| e.title.clone()).collect();
        assert!(titles.contains(&"running → exited".to_string()));
        assert!(titles.contains(&"removed".to_string()));
        assert!(s
            .journal
            .iter()
            .any(|e| e.bad && e.title == "running → exited"));

        let mut down = node("a", vec![]);
        down.error = Some("connection refused".into());
        s.apply_nodes(0, vec![down], true);
        assert_eq!(s.journal[0].kind, EntryKind::NodeDown);
        // A failed poll says nothing about VMs: no "removed" storm.
        assert_eq!(s.journal.iter().filter(|e| e.title == "removed").count(), 1);
        s.apply_nodes(0, vec![node("a", vec![])], true);
        assert_eq!(s.journal[0].kind, EntryKind::NodeUp);
        assert!(s.journal.len() > base);
    }

    #[test]
    fn guest_events_are_deduplicated_and_ordered() {
        let mut s = State::new(vec!["a".into()], 2000, false);
        s.now_ms = 50_000;
        let mut v = vm("1", "web", "running", 1);
        v.events = vec![
            GuestEvent {
                event: "boot.progress".into(),
                body: "done".into(),
                timestamp_ms: 2000,
            },
            GuestEvent {
                event: "boot.progress".into(),
                body: "booting".into(),
                timestamp_ms: 1000,
            },
        ];
        s.apply_nodes(0, vec![node("a", vec![v.clone()])], true);
        s.apply_nodes(0, vec![node("a", vec![v])], true);
        let guest: Vec<_> = s
            .journal
            .iter()
            .filter(|e| e.kind == EntryKind::Guest)
            .map(|e| e.at_ms)
            .collect();
        assert_eq!(guest, [2000, 1000]);
    }

    #[test]
    fn actions_need_a_writable_direct_node() {
        let mut s = state();
        s.move_to(1);
        s.begin_action();
        assert!(matches!(s.input, Some(Input::Choose { .. })));
        s.choose_action(Action::Stop);
        let eff = s.confirm_action().unwrap();
        assert!(matches!(
            eff,
            Effect::Act {
                source: 0,
                action: Action::Stop,
                ..
            }
        ));
        assert_eq!(s.journal[0].kind, EntryKind::Action);

        s.apply_nodes(1, vec![node("c", vec![vm("9", "x", "running", 1)])], false);
        s.sel = Some(RowKey::Vm("1/c".into(), "9".into()));
        s.begin_action();
        assert!(s.input.is_none());
        assert!(s.toast.as_ref().unwrap().text.contains("read-only"));
    }

    #[test]
    fn restart_goes_through_the_same_confirmation() {
        let mut s = state();
        s.move_to(1);
        s.begin_action();
        s.choose_action(Action::Restart);
        assert!(matches!(
            s.input,
            Some(Input::Confirm {
                action: Action::Restart,
                ..
            })
        ));
        let eff = s.confirm_action().unwrap();
        assert!(matches!(
            eff,
            Effect::Act {
                action: Action::Restart,
                ..
            }
        ));
        assert_eq!(s.journal[0].title, "restart");
    }

    #[test]
    fn pause_defers_updates() {
        let mut s = state();
        s.set_paused(true);
        s.apply_nodes(1, vec![node("b", vec![])], true);
        assert_eq!(s.nodes[1].snap.vms.len(), 1);
        s.set_paused(false);
        assert_eq!(s.nodes[1].snap.vms.len(), 0);
    }

    #[test]
    fn interval_steps() {
        let mut s = state();
        assert_eq!(s.step_interval(true), 1000);
        assert_eq!(s.step_interval(true), 1000);
        assert_eq!(s.step_interval(false), 2000);
        assert_eq!(s.step_interval(false), 5000);
    }

    #[test]
    fn totals_count_live_allocation() {
        let s = state();
        let t = totals(&s.nodes);
        assert_eq!(t.nodes, 2);
        assert_eq!(t.nodes_up, 2);
        assert_eq!(t.vms, 4);
        // exited and stopped VMs hold nothing.
        assert_eq!(t.vcpu_used, 6);
        assert_eq!(t.vcpu_max, 128);
    }

    #[test]
    fn logs_follow_tail() {
        let mut s = state();
        s.move_to(1);
        s.open_detail();
        let eff = s.set_detail_tab(DetailTab::Log(LogChannel::Serial));
        assert_eq!(eff.len(), 1);
        s.detail.as_mut().unwrap().body_height = 10;
        let target = s.detail.as_ref().unwrap().target.clone();
        let text: String = (0..100).map(|i| format!("line {i}\n")).collect();
        s.apply_logs(&target, LogChannel::Serial, Ok(text));
        assert_eq!(s.detail.as_ref().unwrap().scroll, 90);
        s.scroll_detail(-5);
        assert!(!s.detail.as_ref().unwrap().follow);
        s.scroll_detail(100);
        assert!(s.detail.as_ref().unwrap().follow);
        // Not due again until an interval passed.
        assert!(s.detail_fetch().is_empty());
        s.now_ms += 5000;
        assert_eq!(s.detail_fetch().len(), 1);
    }
}
