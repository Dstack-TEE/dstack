// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Interactive dashboard: terminal setup, the event loop, and key and mouse
//! handling. State lives in [`model`], drawing in [`ui`].

pub mod model;
pub mod ui;

use crate::collector::{self, Command, LogRequest, Update};
use crate::fmt::now_ms;
use crate::source::Source;
use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use model::{DetailTab, Effect, Input, RowKey, State, Tab};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Restores the terminal on drop and on panic, so a crash never leaves the
/// shell in raw mode on the alternate screen.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            hook(info);
        }));
        Ok(Self)
    }
}

fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}

pub async fn run(sources: Vec<Source>, interval_ms: u64) -> Result<()> {
    let names = sources.iter().map(|s| s.spec.name.clone()).collect();
    let sources: Vec<Arc<Source>> = sources.into_iter().map(Arc::new).collect();
    let mut handle = collector::spawn(sources, interval_ms);
    let mut state = State::new(names, interval_ms);
    state.tick(now_ms());

    let _guard = TerminalGuard::enter()?;
    let mut term: Terminal<CrosstermBackend<Stdout>> =
        Terminal::new(CrosstermBackend::new(io::stdout()))?;
    term.clear()?;

    // crossterm's reader blocks, so it gets a thread of its own.
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<Event>();
    std::thread::spawn(move || loop {
        match event::read() {
            Ok(ev) => {
                if ev_tx.send(ev).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    });

    let mut clicks = ClickTracker::default();
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_draw = Instant::now() - Duration::from_secs(1);
    let mut dirty = true;

    loop {
        if dirty {
            term.draw(|f| ui::draw(f, &mut state))?;
            last_draw = Instant::now();
            dirty = false;
        }
        let effects = tokio::select! {
            Some(ev) = ev_rx.recv() => {
                dirty = true;
                state.tick(now_ms());
                handle_event(&mut state, ev, &mut clicks)
            }
            Some(up) = handle.updates.recv() => {
                dirty = true;
                state.tick(now_ms());
                apply_update(&mut state, up);
                Vec::new()
            }
            _ = ticker.tick() => {
                state.tick(now_ms());
                // Spinners and toasts animate at 10 fps; otherwise redraw
                // once a second so relative times stay true.
                if state.animating() || state.toast.is_some() || last_draw.elapsed() >= Duration::from_secs(1) {
                    dirty = true;
                }
                if state.paused { Vec::new() } else { state.detail_fetch() }
            }
        };
        for e in effects {
            match e {
                Effect::Quit => return Ok(()),
                Effect::Refresh => {
                    let _ = handle.commands.send(Command::RefreshNow);
                }
                Effect::SetInterval(ms) => {
                    handle.interval_ms.store(ms, Ordering::Relaxed);
                    let _ = handle.commands.send(Command::RefreshNow);
                }
                Effect::Logs {
                    source,
                    node,
                    vm_id,
                    channel,
                } => {
                    let _ = handle.commands.send(Command::Logs(LogRequest {
                        source,
                        node,
                        vm_id,
                        channel,
                        lines: model::LOG_LINES,
                    }));
                }
            }
        }
    }
}

fn apply_update(state: &mut State, up: Update) {
    match up {
        Update::Nodes { source, nodes } => state.apply_nodes(source, nodes),
        Update::Logs { req, result } => {
            let Some(node_key) = state
                .nodes
                .iter()
                .find(|n| n.source == req.source && n.snap.name == req.node)
                .map(|n| n.key.clone())
            else {
                return;
            };
            state.apply_logs(&RowKey::Vm(node_key, req.vm_id), req.channel, result);
        }
    }
}

fn handle_event(state: &mut State, ev: Event, clicks: &mut ClickTracker) -> Vec<Effect> {
    match ev {
        Event::Key(k) if k.kind != KeyEventKind::Release => handle_key(state, k),
        Event::Mouse(m) => handle_mouse(state, m, clicks),
        _ => Vec::new(),
    }
}

fn handle_key(state: &mut State, k: KeyEvent) -> Vec<Effect> {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    if ctrl && matches!(k.code, KeyCode::Char('c')) {
        return vec![Effect::Quit];
    }
    if state.help {
        state.help = false;
        return Vec::new();
    }
    // Prompts take every key while open.
    match state.input.clone() {
        Some(Input::Filter(mut buf)) => {
            match k.code {
                KeyCode::Esc => {
                    state.input = None;
                    state.set_filter(String::new());
                }
                KeyCode::Enter => state.input = None,
                KeyCode::Backspace => {
                    buf.pop();
                    state.set_filter(buf.clone());
                    state.input = Some(Input::Filter(buf));
                }
                KeyCode::Char(c) if !ctrl => {
                    buf.push(c);
                    state.set_filter(buf.clone());
                    state.input = Some(Input::Filter(buf));
                }
                KeyCode::Char('u') if ctrl => {
                    state.set_filter(String::new());
                    state.input = Some(Input::Filter(String::new()));
                }
                _ => {}
            }
            return Vec::new();
        }
        None => {}
    }
    if state.detail.is_some() {
        return handle_detail_key(state, k);
    }
    let page = state.list_height.max(1) as isize;
    match k.code {
        KeyCode::Char('q') => return vec![Effect::Quit],
        KeyCode::Esc => {
            if !state.filter.is_empty() {
                state.set_filter(String::new());
            } else if state.preview {
                state.preview = false;
            }
        }
        KeyCode::Char('1') => state.set_tab(Tab::Fleet),
        KeyCode::Char('2') => state.set_tab(Tab::Vms),
        KeyCode::Char('3') => state.set_tab(Tab::Events),
        KeyCode::Tab | KeyCode::BackTab => {
            let i = Tab::ALL.iter().position(|t| *t == state.tab).unwrap_or(0);
            let n = Tab::ALL.len();
            let next = if k.code == KeyCode::Tab {
                (i + 1) % n
            } else {
                (i + n - 1) % n
            };
            state.set_tab(Tab::ALL[next]);
        }
        KeyCode::Up | KeyCode::Char('k') => state.move_by(-1),
        KeyCode::Down | KeyCode::Char('j') => state.move_by(1),
        KeyCode::PageUp => state.move_by(-page),
        KeyCode::PageDown => state.move_by(page),
        KeyCode::Home | KeyCode::Char('g') => state.move_to(0),
        KeyCode::End | KeyCode::Char('G') => state.move_to(usize::MAX),
        KeyCode::Left | KeyCode::Char('h') => state.fold(false),
        KeyCode::Right | KeyCode::Char('l') => state.fold(true),
        KeyCode::Char('z') => state.toggle_fold_all(),
        KeyCode::Enter => return state.open_detail(),
        KeyCode::Char('v') => state.preview = !state.preview,
        KeyCode::Char('a') => state.cycle_scope(),
        KeyCode::Char('s') | KeyCode::Char('>') => state.cycle_sort(true),
        KeyCode::Char('S') | KeyCode::Char('<') => state.cycle_sort(false),
        KeyCode::Char('I') => state.invert_sort(),
        KeyCode::Char('/') => state.input = Some(Input::Filter(state.filter.clone())),
        KeyCode::Char('r') => {
            state.toast("refreshing…", false);
            return vec![Effect::Refresh];
        }
        KeyCode::Char('p') | KeyCode::Char(' ') => state.set_paused(!state.paused),
        KeyCode::Char('+') | KeyCode::Char('=') => {
            return vec![Effect::SetInterval(state.step_interval(true))]
        }
        KeyCode::Char('-') | KeyCode::Char('_') => {
            return vec![Effect::SetInterval(state.step_interval(false))]
        }
        KeyCode::Char('?') => state.help = true,
        _ => {}
    }
    Vec::new()
}

fn handle_detail_key(state: &mut State, k: KeyEvent) -> Vec<Effect> {
    let page = state.detail.as_ref().map_or(10, |d| d.body_height.max(1)) as isize;
    match k.code {
        KeyCode::Esc | KeyCode::Char('q') => state.detail = None,
        KeyCode::Tab | KeyCode::Char(']') => return state.step_detail_tab(true),
        KeyCode::BackTab | KeyCode::Char('[') => return state.step_detail_tab(false),
        KeyCode::Char(c @ '1'..='9') => {
            let i = c as usize - '1' as usize;
            let tab = state.detail.as_ref().and_then(|d| d.tabs().get(i).copied());
            if let Some(tab) = tab {
                return state.set_detail_tab(tab);
            }
        }
        KeyCode::Up | KeyCode::Char('k') => state.scroll_detail(-1),
        KeyCode::Down | KeyCode::Char('j') => state.scroll_detail(1),
        KeyCode::PageUp => state.scroll_detail(-page),
        KeyCode::PageDown | KeyCode::Char(' ') => state.scroll_detail(page),
        KeyCode::Home | KeyCode::Char('g') => state.scroll_detail(isize::MIN / 2),
        KeyCode::End | KeyCode::Char('G') => state.scroll_detail(isize::MAX / 2),
        KeyCode::Left | KeyCode::Char('h') => {
            if let Some(d) = state.detail.as_mut() {
                d.pan = d.pan.saturating_sub(8);
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if let Some(d) = state.detail.as_mut() {
                if matches!(d.tab, DetailTab::Log(_)) {
                    d.pan += 8;
                }
            }
        }
        KeyCode::Char('f') => {
            if let Some(d) = state.detail.as_mut() {
                if matches!(d.tab, DetailTab::Log(_)) {
                    d.follow = !d.follow;
                }
            }
            if state.detail.as_ref().is_some_and(|d| d.follow) {
                state.scroll_detail(isize::MAX / 2);
            }
        }
        KeyCode::Char('r') => return vec![Effect::Refresh],
        KeyCode::Char('?') => state.help = true,
        _ => {}
    }
    Vec::new()
}

#[derive(Default)]
struct ClickTracker {
    last: Option<(Instant, u16, u16)>,
}

impl ClickTracker {
    fn double(&mut self, x: u16, y: u16) -> bool {
        let now = Instant::now();
        let double = self.last.is_some_and(|(t, lx, ly)| {
            now.duration_since(t) < Duration::from_millis(400) && lx == x && ly == y
        });
        self.last = if double { None } else { Some((now, x, y)) };
        double
    }
}

fn handle_mouse(state: &mut State, m: MouseEvent, clicks: &mut ClickTracker) -> Vec<Effect> {
    if state.detail.is_some() {
        return match m.kind {
            MouseEventKind::ScrollUp => {
                state.scroll_detail(-3);
                Vec::new()
            }
            MouseEventKind::ScrollDown => {
                state.scroll_detail(3);
                Vec::new()
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let hit = state
                    .hits
                    .detail_tabs
                    .iter()
                    .find(|(x0, x1, y, _)| m.row == *y && m.column >= *x0 && m.column < *x1)
                    .map(|h| h.3);
                match hit {
                    Some(tab) => state.set_detail_tab(tab),
                    None => Vec::new(),
                }
            }
            _ => Vec::new(),
        };
    }
    match m.kind {
        MouseEventKind::ScrollUp => state.move_by(-3),
        MouseEventKind::ScrollDown => state.move_by(3),
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(tab) = state
                .hits
                .tabs
                .iter()
                .find(|(x0, x1, y, _)| m.row == *y && m.column >= *x0 && m.column < *x1)
                .map(|h| h.3)
            {
                state.set_tab(tab);
                return Vec::new();
            }
            let (y0, h) = (state.hits.list_y, state.hits.list_h);
            if m.row >= y0 && m.row < y0 + h {
                let idx = state.offset + (m.row - y0) as usize;
                let was = state.selected_index();
                let double = clicks.double(m.column, m.row);
                state.move_to(idx);
                if state.selected_index() != idx {
                    return Vec::new();
                }
                // Clicking the selected node folds it; double-click opens.
                if double {
                    return state.open_detail();
                }
                if was == idx {
                    if let Some(RowKey::Node(k)) = state.sel.clone() {
                        let open = state.folded.contains(&k);
                        state.fold(open);
                    }
                }
            }
        }
        _ => {}
    }
    Vec::new()
}
