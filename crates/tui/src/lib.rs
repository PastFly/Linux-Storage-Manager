use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use lsm_core::{
    BlockDevice, DiagnosticSeverity, ExtendAnalysis, ExtendabilityStatus, HostCapabilities,
    HostSnapshot, NodeKind, StorageGraph,
};
use lsm_discovery::{analyze_extendability, discover_capabilities, discover_snapshot};
use lsm_planner::{
    analyze_layout_opportunity, analyze_lvm_underlying_growth, list_provisioning_opportunities,
    plan_extend, ExtendRequest, Growth, GrowthRouteAlternative, LayoutAlternative, Operation,
    PlanStatus, PlanStep, PreflightCheck, PreflightState, ProvisioningOpportunity,
    ProvisioningSpaceKind, Reversibility,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Wrap};
use ratatui::Terminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopControl {
    Continue,
    Refresh,
    KernelRescan,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanLayoutMode {
    Compact,
    Wide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Disks,
    Volumes,
    Swap,
    Mounts,
    Diagnostics,
    Plans,
    Create,
}

impl Section {
    const ALL: [Section; 7] = [
        Section::Disks,
        Section::Volumes,
        Section::Swap,
        Section::Mounts,
        Section::Diagnostics,
        Section::Plans,
        Section::Create,
    ];

    fn label(self) -> &'static str {
        match self {
            Section::Disks => "Disks",
            Section::Volumes => "Volumes",
            Section::Swap => "Swap",
            Section::Mounts => "Mounts",
            Section::Diagnostics => "Diagnostics",
            Section::Plans => "Extend",
            Section::Create => "Create",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AppState {
    section_index: usize,
    selected_device: usize,
    content_scroll: u16,
    plan_growth_index: usize,
}

impl AppState {
    fn new(_snapshot: &HostSnapshot) -> Self {
        let selected_device = 0;
        Self {
            section_index: 0,
            selected_device,
            content_scroll: 0,
            plan_growth_index: 0,
        }
    }

    fn section(self) -> Section {
        Section::ALL[self.section_index]
    }

    fn next_section(&mut self) {
        let next = (self.section_index + 1).min(Section::ALL.len() - 1);
        if next != self.section_index {
            self.section_index = next;
            self.content_scroll = 0;
        }
    }

    fn previous_section(&mut self) {
        let previous = self.section_index.saturating_sub(1);
        if previous != self.section_index {
            self.section_index = previous;
            self.content_scroll = 0;
        }
    }

    fn scroll_down(&mut self) {
        self.content_scroll = self.content_scroll.saturating_add(1);
    }

    fn scroll_up(&mut self) {
        self.content_scroll = self.content_scroll.saturating_sub(1);
    }

    fn set_section(&mut self, index: usize) {
        if self.section_index != index {
            self.section_index = index;
            self.content_scroll = 0;
        }
    }

    fn select_next_device(&mut self, snapshot: &HostSnapshot, volumes_only: bool) {
        let len = visible_device_rows(&snapshot.storage, volumes_only).len();
        if len > 0 {
            self.selected_device = (self.selected_device + 1).min(len - 1);
        }
    }

    fn clamp_device_selection(&mut self, snapshot: &HostSnapshot) {
        let len = match self.section() {
            Section::Volumes => visible_device_rows(&snapshot.storage, true).len(),
            Section::Plans => plan_candidate_rows(snapshot).len(),
            Section::Create => list_provisioning_opportunities(snapshot).len(),
            _ => visible_device_rows(&snapshot.storage, false).len(),
        };
        self.selected_device = self.selected_device.min(len.saturating_sub(1));
    }

    fn select_next_plan_candidate(&mut self, snapshot: &HostSnapshot) {
        let len = plan_candidate_rows(snapshot).len();
        if len > 0 {
            let next = (self.selected_device + 1).min(len - 1);
            if next != self.selected_device {
                self.selected_device = next;
                self.plan_growth_index = 0;
            }
        }
    }

    fn select_previous_plan_candidate(&mut self) {
        let previous = self.selected_device.saturating_sub(1);
        if previous != self.selected_device {
            self.selected_device = previous;
            self.plan_growth_index = 0;
        }
    }

    fn select_next_create_candidate(&mut self, snapshot: &HostSnapshot) {
        let len = list_provisioning_opportunities(snapshot).len();
        if len > 0 {
            self.selected_device = (self.selected_device + 1).min(len - 1);
        }
    }

    fn select_previous_create_candidate(&mut self) {
        self.selected_device = self.selected_device.saturating_sub(1);
    }

    fn plan_growth_for_snapshot(&self, snapshot: &HostSnapshot) -> Growth {
        let options = plan_growth_options(snapshot, self.selected_device);
        options
            .get(self.plan_growth_index.min(options.len().saturating_sub(1)))
            .copied()
            .unwrap_or(Growth::MaxFree)
    }

    fn next_plan_growth_for_snapshot(&mut self, snapshot: &HostSnapshot) {
        let len = plan_growth_options(snapshot, self.selected_device).len();
        if len > 0 {
            self.plan_growth_index = (self.plan_growth_index + 1).min(len - 1);
        }
    }

    fn previous_plan_growth(&mut self) {
        self.plan_growth_index = self.plan_growth_index.saturating_sub(1);
    }

    fn select_previous_device(&mut self) {
        self.selected_device = self.selected_device.saturating_sub(1);
    }
}

const PLAN_GROWTH_PRESETS: [Growth; 4] = [
    Growth::ByBytes(512 * 1024 * 1024),
    Growth::ByBytes(1024 * 1024 * 1024),
    Growth::ByBytes(4 * 1024 * 1024 * 1024),
    Growth::MaxFree,
];

#[derive(Clone, Copy)]
struct DeviceRow<'a> {
    depth: usize,
    device: &'a BlockDevice,
}

pub fn run(snapshot: HostSnapshot, capabilities: HostCapabilities) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = event_loop(&mut terminal, snapshot, capabilities);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    mut snapshot: HostSnapshot,
    mut capabilities: HostCapabilities,
) -> Result<()> {
    let mut state = AppState::new(&snapshot);
    let mut refresh_status: Option<String> = None;

    loop {
        terminal.draw(|frame| {
            draw(
                frame,
                &snapshot,
                &capabilities,
                state,
                refresh_status.as_deref(),
            )
        })?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match handle_key_event(&mut state, &snapshot, key) {
                    LoopControl::Quit => return Ok(()),
                    LoopControl::Refresh => match discover_snapshot() {
                        Ok(fresh) => {
                            snapshot = fresh;
                            capabilities = discover_capabilities();
                            state.content_scroll = 0;
                            state.plan_growth_index = 0;
                            state.clamp_device_selection(&snapshot);
                            refresh_status = Some("Refreshed".to_owned());
                        }
                        Err(error) => {
                            refresh_status = Some(format!("Refresh failed: {error}"));
                        }
                    },
                    LoopControl::KernelRescan => {
                        match kernel_rescan_selected_disk(&snapshot, state) {
                            Ok(kernel_name) => {
                                std::thread::sleep(Duration::from_millis(250));
                                match discover_snapshot() {
                                    Ok(fresh) => {
                                        snapshot = fresh;
                                        capabilities = discover_capabilities();
                                        state.content_scroll = 0;
                                        state.plan_growth_index = 0;
                                        state.clamp_device_selection(&snapshot);
                                        refresh_status = Some(format!("Rescanned {kernel_name}"));
                                    }
                                    Err(error) => {
                                        refresh_status = Some(format!(
                                            "Rescan succeeded, refresh failed: {error}"
                                        ));
                                    }
                                }
                            }
                            Err(error) => {
                                refresh_status = Some(format!("Rescan failed: {error}"));
                            }
                        }
                    }
                    LoopControl::Continue => {}
                }
            }
        }
    }
}

fn handle_key_event(state: &mut AppState, snapshot: &HostSnapshot, key: KeyEvent) -> LoopControl {
    if key.kind != KeyEventKind::Press {
        return LoopControl::Continue;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => LoopControl::Quit,
        KeyCode::Char('r') => LoopControl::Refresh,
        KeyCode::Char('R') => LoopControl::KernelRescan,
        KeyCode::Up | KeyCode::Char('k') => {
            match state.section() {
                Section::Disks | Section::Volumes => state.select_previous_device(),
                Section::Plans => state.select_previous_plan_candidate(),
                Section::Create => state.select_previous_create_candidate(),
                _ => state.scroll_up(),
            }
            LoopControl::Continue
        }
        KeyCode::Down | KeyCode::Char('j') => {
            match state.section() {
                Section::Disks | Section::Volumes => {
                    let volumes_only = state.section() == Section::Volumes;
                    state.select_next_device(snapshot, volumes_only)
                }
                Section::Plans => state.select_next_plan_candidate(snapshot),
                Section::Create => state.select_next_create_candidate(snapshot),
                _ => state.scroll_down(),
            }
            LoopControl::Continue
        }
        KeyCode::Left | KeyCode::BackTab => {
            state.previous_section();
            state.clamp_device_selection(snapshot);
            LoopControl::Continue
        }
        KeyCode::Right | KeyCode::Tab => {
            state.next_section();
            state.clamp_device_selection(snapshot);
            LoopControl::Continue
        }
        KeyCode::Char('1') => {
            state.set_section(0);
            state.clamp_device_selection(snapshot);
            LoopControl::Continue
        }
        KeyCode::Char('2') => {
            state.set_section(1);
            state.clamp_device_selection(snapshot);
            LoopControl::Continue
        }
        KeyCode::Char('3') => {
            state.set_section(2);
            LoopControl::Continue
        }
        KeyCode::Char('4') => {
            state.set_section(3);
            LoopControl::Continue
        }
        KeyCode::Char('5') => {
            state.set_section(4);
            LoopControl::Continue
        }
        KeyCode::Char('6') => {
            state.set_section(5);
            state.clamp_device_selection(snapshot);
            LoopControl::Continue
        }
        KeyCode::Char('7') => {
            state.set_section(6);
            state.clamp_device_selection(snapshot);
            LoopControl::Continue
        }
        KeyCode::Char('[') | KeyCode::Char('-') | KeyCode::Char('_') | KeyCode::PageUp
            if state.section() == Section::Plans =>
        {
            state.previous_plan_growth();
            LoopControl::Continue
        }
        KeyCode::Char(']') | KeyCode::Char('+') | KeyCode::PageDown
            if state.section() == Section::Plans =>
        {
            state.next_plan_growth_for_snapshot(snapshot);
            LoopControl::Continue
        }
        KeyCode::Char('=') if state.section() == Section::Plans => {
            state.next_plan_growth_for_snapshot(snapshot);
            LoopControl::Continue
        }
        _ => LoopControl::Continue,
    }
}

fn draw(
    frame: &mut ratatui::Frame<'_>,
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    state: AppState,
    refresh_status: Option<&str>,
) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let header = header_text(snapshot);
    frame.render_widget(
        Paragraph::new(header)
            .style(Style::default().add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL)),
        outer[0],
    );

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(20), Constraint::Min(40)])
        .split(outer[1]);

    frame.render_widget(
        Paragraph::new(sidebar_lines(state))
            .block(Block::default().borders(Borders::ALL).title(" Storage ")),
        body[0],
    );

    render_section(frame, body[1], snapshot, capabilities, state);

    frame.render_widget(
        Paragraph::new(toolbar_line(state.section(), refresh_status))
            .block(Block::default().borders(Borders::ALL)),
        outer[2],
    );
}

fn sidebar_lines(state: AppState) -> Vec<Line<'static>> {
    Section::ALL
        .iter()
        .enumerate()
        .map(|(index, section)| {
            let marker = if index == state.section_index {
                "›"
            } else {
                " "
            };
            let line = Line::from(format!("{marker} {}  {}", index + 1, section.label()));
            if index == state.section_index {
                line.style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED))
            } else {
                line
            }
        })
        .collect()
}

fn render_section(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    state: AppState,
) {
    match state.section() {
        Section::Disks => render_devices(frame, area, snapshot, state, false),
        Section::Volumes => render_devices(frame, area, snapshot, state, true),
        Section::Swap => render_swap(frame, area, snapshot, state),
        Section::Mounts => render_mounts(frame, area, snapshot, state),
        Section::Diagnostics => render_diagnostics(frame, area, snapshot, capabilities, state),
        Section::Plans => render_plan_hint(frame, area, snapshot, capabilities, state),
        Section::Create => render_create(frame, area, snapshot, state),
    }
}

fn render_devices(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    state: AppState,
    volumes_only: bool,
) {
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
        .split(area);

    let rows = visible_device_rows(&snapshot.storage, volumes_only);
    let title = if volumes_only {
        " Volumes "
    } else {
        " Devices "
    };
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new("No matching devices discovered.")
                .block(Block::default().borders(Borders::ALL).title(title)),
            panes[0],
        );
    } else {
        let table_rows = rows.iter().enumerate().map(|(index, row)| {
            let rendered = Row::new(device_table_cells(snapshot, *row));
            if index == state.selected_device {
                rendered.style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED))
            } else {
                rendered
            }
        });
        let header = Row::new(["Device", "Size", "FS / Role", "Mount"])
            .style(Style::default().add_modifier(Modifier::BOLD));
        let table = Table::new(
            table_rows,
            [
                Constraint::Min(20),
                Constraint::Length(11),
                Constraint::Length(19),
                Constraint::Min(8),
            ],
        )
        .header(header)
        .column_spacing(1)
        .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(table, panes[0]);
    }

    if let Some(row) = rows.get(state.selected_device) {
        let details = device_detail_rows(snapshot, row.device)
            .into_iter()
            .map(Row::new);
        let table = Table::new(details, [Constraint::Length(14), Constraint::Min(10)])
            .column_spacing(1)
            .block(Block::default().borders(Borders::ALL).title(" Details "));
        frame.render_widget(table, panes[1]);
    } else {
        frame.render_widget(
            Paragraph::new("No device selected.")
                .block(Block::default().borders(Borders::ALL).title(" Details ")),
            panes[1],
        );
    }
}

fn render_swap(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    state: AppState,
) {
    if snapshot.swaps.is_empty() {
        frame.render_widget(
            Paragraph::new("No active swap areas discovered.")
                .block(Block::default().borders(Borders::ALL).title(" Swap ")),
            area,
        );
        return;
    }

    let rows = snapshot
        .swaps
        .iter()
        .skip(state.content_scroll as usize)
        .map(|swap| {
            Row::new([
                swap.name.clone(),
                swap.kind.clone(),
                human_bytes(swap.size_bytes),
                human_bytes(swap.used_bytes),
                swap.priority.to_string(),
            ])
        });
    let header = Row::new(["Device", "Type", "Size", "Used", "Priority"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let table = Table::new(
        rows,
        [
            Constraint::Length(30),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .column_spacing(1)
    .block(Block::default().borders(Borders::ALL).title(" Swap "));
    frame.render_widget(table, area);
}

fn render_mounts(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    state: AppState,
) {
    let mounts = storage_mounts(snapshot);
    if mounts.is_empty() {
        frame.render_widget(
            Paragraph::new("No storage mounts discovered.").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Storage mounts "),
            ),
            area,
        );
        return;
    }

    let rows = mounts
        .into_iter()
        .skip(state.content_scroll as usize)
        .map(|mount| Row::new(mount_table_cells(mount)));
    let header = Row::new(["Target", "Source", "Filesystem"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let table = Table::new(
        rows,
        [
            Constraint::Length(28),
            Constraint::Min(40),
            Constraint::Length(14),
        ],
    )
    .header(header)
    .column_spacing(1)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Storage mounts "),
    );
    frame.render_widget(table, area);
}

fn render_diagnostics(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    state: AppState,
) {
    let table_height = if snapshot.diagnostics.is_empty() {
        4
    } else {
        (snapshot.diagnostics.len() as u16 + 3).min(12)
    };
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(table_height),
            Constraint::Min(5),
            Constraint::Length(5),
        ])
        .split(area);

    if snapshot.diagnostics.is_empty() {
        frame.render_widget(
            Paragraph::new("No diagnostics reported.").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Diagnostics "),
            ),
            sections[0],
        );
        frame.render_widget(
            Paragraph::new("No diagnostic selected.")
                .block(Block::default().borders(Borders::ALL).title(" Details ")),
            sections[1],
        );
    } else {
        let selected = (state.content_scroll as usize).min(snapshot.diagnostics.len() - 1);
        let start = selected.saturating_sub(4);
        let rows = snapshot
            .diagnostics
            .iter()
            .enumerate()
            .skip(start)
            .take(10)
            .map(|(index, item)| {
                let row = Row::new(diagnostic_summary_cells(item));
                if index == selected {
                    row.style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED))
                } else {
                    row
                }
            });
        let table = Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Min(34),
                Constraint::Length(18),
            ],
        )
        .header(
            Row::new(["Severity", "Code", "Device"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .column_spacing(1)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Diagnostics "),
        );
        frame.render_widget(table, sections[0]);

        let item = &snapshot.diagnostics[selected];
        let detail_lines = vec![
            Line::from(format!("Code      {}", item.code)),
            Line::from(format!(
                "Device    {}",
                item.device.as_deref().unwrap_or("-")
            )),
            Line::from(""),
            Line::from(item.message.clone()),
        ];
        frame.render_widget(
            Paragraph::new(detail_lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Details ")),
            sections[1],
        );
    }

    let available = capabilities
        .tools
        .iter()
        .filter(|tool| tool.available)
        .count();
    let missing = capabilities
        .tools
        .iter()
        .filter(|tool| !tool.available)
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let capability_lines = vec![
        Line::from(format!(
            "Available: {available}/{} tools",
            capabilities.tools.len()
        )),
        Line::from(format!(
            "Missing: {}",
            if missing.is_empty() { "none" } else { &missing }
        )),
    ];
    frame.render_widget(
        Paragraph::new(capability_lines)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Capabilities "),
            ),
        sections[2],
    );
}

fn render_plan_hint(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    state: AppState,
) {
    let rows = plan_candidate_rows(snapshot);
    let Some(row) = rows.get(state.selected_device) else {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from("No filesystem targets were discovered."),
                Line::from(""),
                Line::from("Extend shows discovered leaf filesystems; unsupported paths stay visible as blocked."),
                Line::from("No changes will be made."),
            ])
            .block(Block::default().borders(Borders::ALL).title(" Plans ")),
            area,
        );
        return;
    };

    let target = plan_target(row.device);
    let analysis = match analyze_extendability(snapshot, &target) {
        Ok(analysis) => analysis,
        Err(error) => {
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from("Growth analysis"),
                    Line::from(""),
                    Line::from(format!("Target          {target}")),
                    Line::from("Status          Analysis unavailable"),
                    Line::from(format!("Reason          {error}")),
                    Line::from(""),
                    Line::from("No changes will be made."),
                ])
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Plans ")),
                area,
            );
            return;
        }
    };
    let growth = state.plan_growth_for_snapshot(snapshot);

    match plan_layout_mode(area.width) {
        PlanLayoutMode::Wide => render_plan_wide(
            frame,
            area,
            snapshot,
            capabilities,
            &target,
            growth,
            &analysis,
        ),
        PlanLayoutMode::Compact => render_plan_compact(
            frame,
            area,
            snapshot,
            capabilities,
            &target,
            growth,
            &analysis,
        ),
    }
}

fn render_create(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    state: AppState,
) {
    let opportunities = list_provisioning_opportunities(snapshot);
    if opportunities.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from("No verified free-space sources were discovered."),
                Line::from(""),
                Line::from("This section will host creation of partitions, LVM volumes, filesystems and swap."),
                Line::from("Provisioning remains advisory/read-only in M1A."),
            ])
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" Create ")),
            area,
        );
        return;
    }

    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    let rows = opportunities
        .iter()
        .enumerate()
        .map(|(index, opportunity)| {
            let row = Row::new([
                provisioning_kind_label(opportunity.kind).to_owned(),
                opportunity.source.clone(),
                human_bytes(opportunity.available_bytes),
                opportunity
                    .future_actions
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "-".to_owned()),
            ]);
            if index == state.selected_device {
                row.style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED))
            } else {
                row
            }
        });

    let table = Table::new(
        rows,
        [
            Constraint::Length(13),
            Constraint::Length(28),
            Constraint::Length(14),
            Constraint::Min(30),
        ],
    )
    .header(
        Row::new(["Space", "Source", "Available", "Future workflow"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .column_spacing(1)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Create — discovered free space "),
    );
    frame.render_widget(table, panes[0]);

    let selected = state.selected_device.min(opportunities.len() - 1);
    frame.render_widget(
        Paragraph::new(provisioning_detail_lines(&opportunities[selected]))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Planned use "),
            ),
        panes[1],
    );
}

fn provisioning_kind_label(kind: ProvisioningSpaceKind) -> &'static str {
    match kind {
        ProvisioningSpaceKind::BlankDisk => "Blank disk",
        ProvisioningSpaceKind::DiskTail => "Disk tail",
        ProvisioningSpaceKind::LvmFreeExtents => "VG free",
    }
}

fn provisioning_detail_lines(opportunity: &ProvisioningOpportunity) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("Source          {}", opportunity.source)),
        Line::from(format!(
            "Type            {}",
            provisioning_kind_label(opportunity.kind)
        )),
        Line::from(format!(
            "Available       {}",
            human_bytes_precise(opportunity.available_bytes)
        )),
        Line::from(format!(
            "Disk            {}",
            opportunity.disk.as_deref().unwrap_or("-")
        )),
        Line::from(format!(
            "Volume group    {}",
            opportunity.volume_group.as_deref().unwrap_or("-")
        )),
        Line::from(format!(
            "Sector size     {}",
            opportunity
                .sector_size_bytes
                .map(|bytes| format!("{bytes} B"))
                .unwrap_or_else(|| "-".to_owned())
        )),
        Line::from(""),
        Line::from("Future automatic workflow"),
    ];

    for (index, action) in opportunity.future_actions.iter().enumerate() {
        lines.push(Line::from(format!("{}. {}", index + 1, action)));
    }

    if !opportunity.blockers.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Current blockers"));
        for blocker in &opportunity.blockers {
            lines.push(Line::from(format!("- {blocker}")));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(
        "Preview only: no partition, LVM, filesystem, mount or swap change is executed.",
    ));
    lines
}

fn render_plan_compact(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    target: &str,
    growth: Growth,
    analysis: &ExtendAnalysis,
) {
    let mut lines = plan_summary_lines(target, growth, analysis);
    lines.push(Line::from(""));
    lines.extend(strict_plan_lines(snapshot, capabilities, target, growth));
    if let Some((opportunity_growth, alternative)) =
        probe_layout_opportunity(snapshot, capabilities, target)
    {
        lines.push(Line::from(""));
        lines.extend(layout_opportunity_summary_lines(
            opportunity_growth,
            &alternative,
        ));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("No changes will be made."));

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" Plans ")),
        area,
    );
}

fn render_plan_wide(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    target: &str,
    growth: Growth,
    analysis: &ExtendAnalysis,
) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(columns[1]);

    let plan = plan_extend(
        snapshot,
        capabilities,
        ExtendRequest {
            target: target.to_owned(),
            growth,
        },
    );

    let mut summary = plan_summary_lines(target, growth, analysis);
    match &plan {
        Ok(plan) if plan.status() == PlanStatus::Preview => {
            summary.extend(plan_preview_summary_lines(plan));
        }
        Ok(plan) => {
            summary.push(Line::from(""));
            summary.push(Line::from("Strict preview"));
            summary.push(Line::from("Planner         Blocked"));
            if let Some(blocker) = plan.blockers().first() {
                summary.push(Line::from(format!(
                    "Blocker         [{}] {}",
                    blocker.code, blocker.message
                )));
            }
        }
        Err(error) => {
            summary.push(Line::from(""));
            summary.push(Line::from("Strict preview"));
            summary.push(Line::from("Planner         Error"));
            summary.push(Line::from(format!("Reason          {error}")));
        }
    }
    if let Some((opportunity_growth, alternative)) =
        probe_layout_opportunity(snapshot, capabilities, target)
    {
        summary.push(Line::from(""));
        summary.extend(layout_opportunity_summary_lines(
            opportunity_growth,
            &alternative,
        ));
    }
    summary.push(Line::from(""));
    summary.push(Line::from("No changes will be made."));

    frame.render_widget(
        Paragraph::new(summary)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" Summary ")),
        columns[0],
    );

    match plan {
        Ok(plan) if plan.status() == PlanStatus::Preview => {
            let preflight_rows = plan.preflight_checks().iter().map(|check| {
                let row = Row::new(preflight_table_cells(check));
                if check.state == PreflightState::Required {
                    row.style(Style::default().add_modifier(Modifier::BOLD))
                } else {
                    row
                }
            });
            let preflight = Table::new(
                preflight_rows,
                [
                    Constraint::Length(6),
                    Constraint::Length(30),
                    Constraint::Min(24),
                ],
            )
            .header(
                Row::new(["State", "Check", "Details"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1)
            .block(Block::default().borders(Borders::ALL).title(" Preflight "));
            frame.render_widget(preflight, right[0]);

            let step_rows = plan.steps().iter().map(|step| {
                let row = Row::new(plan_step_table_cells(step));
                if step.reversibility == Reversibility::Irreversible {
                    row.style(Style::default().add_modifier(Modifier::BOLD))
                } else {
                    row
                }
            });
            let steps = Table::new(
                step_rows,
                [
                    Constraint::Length(3),
                    Constraint::Min(26),
                    Constraint::Length(12),
                    Constraint::Length(8),
                ],
            )
            .header(
                Row::new(["#", "Operation", "Risk", "After"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1)
            .block(Block::default().borders(Borders::ALL).title(" Plan steps "));
            frame.render_widget(steps, right[1]);
        }
        Ok(plan) => {
            if let Some(route) = plan.growth_route_alternatives().first() {
                frame.render_widget(
                    Paragraph::new(growth_route_lines(route))
                        .wrap(Wrap { trim: false })
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(" Automatic growth route "),
                        ),
                    columns[1],
                );
            } else if let Some(alternative) = plan.layout_alternatives().first() {
                frame.render_widget(
                    Paragraph::new(layout_alternative_lines(alternative))
                        .wrap(Wrap { trim: false })
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(" Layout alternative "),
                        ),
                    columns[1],
                );
            } else {
                let message = plan
                    .blockers()
                    .first()
                    .map(|blocker| format!("[{}] {}", blocker.code, blocker.message))
                    .unwrap_or_else(|| "No blocker details available.".to_owned());
                frame.render_widget(
                    Paragraph::new(message)
                        .wrap(Wrap { trim: false })
                        .block(Block::default().borders(Borders::ALL).title(" Preflight ")),
                    columns[1],
                );
            }
        }
        Err(error) => {
            frame.render_widget(
                Paragraph::new(error.to_string())
                    .wrap(Wrap { trim: false })
                    .block(Block::default().borders(Borders::ALL).title(" Preflight ")),
                columns[1],
            );
        }
    }
}

fn device_table_cells(snapshot: &HostSnapshot, row: DeviceRow<'_>) -> [String; 4] {
    let path = row.device.path.as_deref().unwrap_or(&row.device.name);
    let label = format!("{}{}", "  ".repeat(row.depth), path);
    let role = device_role(snapshot, row.device);
    let filesystem = row
        .device
        .filesystem
        .as_ref()
        .map(|fs| fs.fs_type.as_str())
        .unwrap_or("-");
    let descriptor = if role == "Extended container" {
        role.to_owned()
    } else {
        filesystem.to_owned()
    };
    let mount = if row.device.mountpoints.is_empty() {
        "-".to_owned()
    } else {
        row.device.mountpoints.join(", ")
    };
    [
        label,
        device_size_for_display(snapshot, row.device),
        descriptor,
        mount,
    ]
}

fn mount_table_cells(mount: &lsm_core::MountEntry) -> [String; 3] {
    [
        mount.target.clone(),
        mount.source.clone().unwrap_or_else(|| "-".to_owned()),
        mount.fs_type.clone().unwrap_or_else(|| "-".to_owned()),
    ]
}

#[cfg(test)]
fn diagnostic_table_cells(item: &lsm_core::StorageDiagnostic) -> [String; 3] {
    let severity = match item.severity {
        DiagnosticSeverity::Info => "Info",
        DiagnosticSeverity::Warning => "Warning",
        DiagnosticSeverity::Error => "Error",
    };
    [severity.to_owned(), item.code.clone(), item.message.clone()]
}

fn diagnostic_summary_cells(item: &lsm_core::StorageDiagnostic) -> [String; 3] {
    let severity = match item.severity {
        DiagnosticSeverity::Info => "Info",
        DiagnosticSeverity::Warning => "Warning",
        DiagnosticSeverity::Error => "Error",
    };
    [
        severity.to_owned(),
        item.code.clone(),
        item.device.clone().unwrap_or_else(|| "-".to_owned()),
    ]
}

fn device_detail_rows(snapshot: &HostSnapshot, device: &BlockDevice) -> Vec<[String; 2]> {
    let path = device.path.as_deref().unwrap_or(&device.name);
    let filesystem = device
        .filesystem
        .as_ref()
        .map(|item| item.fs_type.as_str())
        .unwrap_or("-");
    let mounts = if device.mountpoints.is_empty() {
        "-".to_owned()
    } else {
        device.mountpoints.join(", ")
    };
    let mut rows = vec![
        ["Device".to_owned(), path.to_owned()],
        ["Type".to_owned(), device_role(snapshot, device).to_owned()],
        ["Size".to_owned(), device_size_for_display(snapshot, device)],
        ["Filesystem".to_owned(), filesystem.to_owned()],
        ["Mounted at".to_owned(), mounts],
        [
            "Partition tbl".to_owned(),
            device.partition_table.as_deref().unwrap_or("-").to_owned(),
        ],
        [
            "Kernel name".to_owned(),
            device.kernel_name.as_deref().unwrap_or("-").to_owned(),
        ],
    ];
    if matches!(device.kind, NodeKind::Disk | NodeKind::Loop) {
        if let Some(bytes) = disk_tail_free_bytes(snapshot, device) {
            rows.push(["Tail free".to_owned(), human_bytes(bytes)]);
        }
    }
    rows
}

fn preflight_display_detail(check: &PreflightCheck) -> &'static str {
    match check.code.as_str() {
        "collectors-complete" => "Discovery inputs complete",
        "diagnostics-clean" => "No blocking diagnostics",
        "mount-rw" => "Single matching RW mount",
        "tooling-available" => "Required tools available",
        "partition-geometry-consistent" => "lsblk/sfdisk geometry consistent",
        "adjacent-capacity-verified" => "Growth fits verified adjacent space",
        "lvm-identity-consistent" => "PV/VG/LV identities consistent",
        "lvm-layout-supported" => "Supported linear LVM layout",
        "capacity-verified" => "Growth fits verified VG free space",
        "runtime-identity-recheck" => "Revalidate identities and plan basis",
        "filesystem-health" => "Check health/features/grow support",
        "exclusive-lock" => "Acquire exclusive operation lock",
        "metadata-backup" => "Create and verify metadata backup",
        "execution-approval" => "Approve exact fresh plan",
        _ => "See structured plan details",
    }
}

fn preflight_table_cells(check: &PreflightCheck) -> [String; 3] {
    let state = match check.state {
        PreflightState::Verified => "[OK]",
        PreflightState::Required => "[REQ]",
    };
    [
        state.to_owned(),
        check.code.clone(),
        preflight_display_detail(check).to_owned(),
    ]
}

fn plan_step_table_cells(step: &PlanStep) -> [String; 4] {
    [
        step.id.to_string(),
        operation_summary(&step.operation),
        reversibility_label(step.reversibility).to_owned(),
        if step.depends_on.is_empty() {
            "-".to_owned()
        } else {
            step.depends_on
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        },
    ]
}

fn plan_layout_mode(width: u16) -> PlanLayoutMode {
    if width >= 120 {
        PlanLayoutMode::Wide
    } else {
        PlanLayoutMode::Compact
    }
}

fn plan_summary_lines(
    target: &str,
    growth: Growth,
    analysis: &ExtendAnalysis,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Growth analysis"),
        Line::from(""),
        Line::from(format!("Target          {target}")),
        Line::from(format!(
            "Device          {}",
            analysis.device.as_deref().unwrap_or("-")
        )),
        Line::from(format!(
            "Filesystem      {}",
            analysis.filesystem.as_deref().unwrap_or("-")
        )),
        Line::from(format!(
            "Current size    {}",
            analysis
                .current_size_bytes
                .map(human_bytes_precise)
                .unwrap_or_else(|| "-".to_owned())
        )),
        Line::from(""),
    ];
    lines.extend(analysis_summary_lines(analysis));
    lines.push(Line::from(""));
    lines.push(Line::from("Strict preview"));
    lines.push(Line::from(format!(
        "Requested       {}",
        growth_label(growth)
    )));
    lines
}

fn plan_preview_summary_lines(plan: &lsm_planner::PlanPreview) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("Planner         Preview ready")];
    if let Some(change) = plan.size_change() {
        lines.push(Line::from("Layout          LVM"));
        lines.push(Line::from(format!(
            "Growth          {}",
            human_bytes(change.rounded_growth_bytes)
        )));
        lines.push(Line::from(format!(
            "Expected size   {}",
            human_bytes_precise(change.expected_lv_size_bytes)
        )));
        lines.push(Line::from(format!(
            "VG free after   {}",
            human_bytes(change.remaining_vg_free_bytes)
        )));
    }
    if let Some(change) = plan.partition_size_change() {
        lines.push(Line::from("Layout          Direct partition"));
        lines.push(Line::from(format!("Disk            {}", change.disk)));
        lines.push(Line::from(format!(
            "Growth          {}",
            human_bytes(change.rounded_growth_bytes)
        )));
        lines.push(Line::from(format!(
            "Expected size   {}",
            human_bytes_precise(change.expected_partition_size_bytes)
        )));
        lines.push(Line::from(format!(
            "Adjacent after  {}",
            human_bytes(change.remaining_adjacent_free_bytes)
        )));
    }
    lines
}

#[cfg(test)]
fn toolbar_text(section: Section) -> String {
    if section == Section::Plans {
        "↑↓ Target   PgUp/PgDn Size   Tab Section   r Refresh   R Rescan   q Quit   Read-only"
            .to_owned()
    } else {
        "↑↓ Navigate   Tab Section   1-7 Jump   r Refresh   R Rescan   q Quit   Read-only"
            .to_owned()
    }
}

fn toolbar_line(section: Section, refresh_status: Option<&str>) -> Line<'static> {
    let items: Vec<(&'static str, &'static str)> = if section == Section::Plans {
        vec![
            ("↑↓", "Target"),
            ("PgUp/PgDn", "Size"),
            ("Tab", "Section"),
            ("r", "Refresh"),
            ("R", "Rescan"),
            ("q", "Quit"),
        ]
    } else {
        vec![
            ("↑↓", "Navigate"),
            ("Tab", "Section"),
            ("1-7", "Jump"),
            ("r", "Refresh"),
            ("R", "Rescan"),
            ("q", "Quit"),
        ]
    };

    let mut spans = vec![Span::raw(" ")];
    for (key, label) in items {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
        ));
        spans.push(Span::raw(format!(" {label}  ")));
    }
    spans.push(Span::raw("Read-only"));
    if let Some(status) = refresh_status {
        spans.push(Span::raw(format!("   {status}")));
    }
    Line::from(spans)
}

fn device_rows(graph: &StorageGraph) -> Vec<DeviceRow<'_>> {
    let mut rows = Vec::new();
    for device in &graph.block_devices {
        append_device_rows(device, 0, &mut rows);
    }
    rows
}

fn append_device_rows<'a>(device: &'a BlockDevice, depth: usize, rows: &mut Vec<DeviceRow<'a>>) {
    rows.push(DeviceRow { depth, device });
    for child in &device.children {
        append_device_rows(child, depth + 1, rows);
    }
}

fn rescan_sysfs_path(kernel_name: &str) -> Option<PathBuf> {
    if kernel_name.is_empty()
        || !kernel_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(
        PathBuf::from("/sys/class/block")
            .join(kernel_name)
            .join("device/rescan"),
    )
}

fn selected_disk_kernel_name(snapshot: &HostSnapshot, state: AppState) -> Option<String> {
    if state.section() != Section::Disks {
        return None;
    }
    let rows = visible_device_rows(&snapshot.storage, false);
    let selected = rows.get(state.selected_device)?.device;
    match selected.kind {
        NodeKind::Disk => selected.kernel_name.clone(),
        NodeKind::Partition => {
            let parent = selected.parent_kernel_name.as_deref()?;
            snapshot
                .storage
                .block_devices
                .iter()
                .find(|device| {
                    device.kind == NodeKind::Disk && device.kernel_name.as_deref() == Some(parent)
                })
                .and_then(|device| device.kernel_name.clone())
        }
        _ => None,
    }
}

fn kernel_rescan_selected_disk(snapshot: &HostSnapshot, state: AppState) -> Result<String> {
    let kernel_name = selected_disk_kernel_name(snapshot, state)
        .ok_or_else(|| anyhow!("select a disk or its partition in the Disks section"))?;
    let path = rescan_sysfs_path(&kernel_name)
        .ok_or_else(|| anyhow!("invalid kernel block-device name"))?;
    if !path.is_file() {
        return Err(anyhow!(
            "kernel rescan control is unavailable for /dev/{kernel_name}"
        ));
    }
    std::fs::write(&path, b"1\n").with_context(|| format!("write {}", path.display()))?;
    Ok(kernel_name)
}

fn header_text(snapshot: &HostSnapshot) -> String {
    let errors = snapshot
        .diagnostics
        .iter()
        .filter(|item| item.severity == DiagnosticSeverity::Error)
        .count();
    let warnings = snapshot
        .diagnostics
        .iter()
        .filter(|item| item.severity == DiagnosticSeverity::Warning)
        .count();

    let diagnostic_text = match (errors, warnings) {
        (0, 0) => "No warnings".to_owned(),
        (0, 1) => "1 warning".to_owned(),
        (0, count) => format!("{count} warnings"),
        (1, 0) => "1 error".to_owned(),
        (count, 0) => format!("{count} errors"),
        (errors, warnings) => format!("{errors} errors, {warnings} warnings"),
    };

    format!(" Linux Storage Manager   Read-only   {diagnostic_text} ")
}

fn device_role(snapshot: &HostSnapshot, device: &BlockDevice) -> &'static str {
    if is_extended_partition(snapshot, device) {
        return "Extended container";
    }
    match device.kind {
        NodeKind::Disk => "Disk",
        NodeKind::Partition => "Partition",
        NodeKind::Lvm => "LVM volume",
        NodeKind::Crypt => "Encrypted volume",
        NodeKind::Raid => "RAID",
        NodeKind::Loop => "Loop device",
        NodeKind::Rom => "Optical device",
        NodeKind::Zram => "ZRAM",
        NodeKind::Unknown => "Unknown",
    }
}

fn device_size_for_display(snapshot: &HostSnapshot, device: &BlockDevice) -> String {
    if is_extended_partition(snapshot, device) {
        "container".to_owned()
    } else {
        human_bytes(device.size_bytes)
    }
}

fn is_extended_partition(snapshot: &HostSnapshot, device: &BlockDevice) -> bool {
    let Some(path) = device.path.as_deref() else {
        return false;
    };
    snapshot.partition_tables.iter().any(|table| {
        table.label.as_deref() == Some("dos")
            && table.partitions.iter().any(|record| {
                if record.node != path {
                    return false;
                }
                let Some(raw) = record.partition_type.as_deref() else {
                    return false;
                };
                let trimmed = raw.trim();
                let normalized = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                    .unwrap_or(trimmed);
                u8::from_str_radix(normalized, 16)
                    .map(|kind| matches!(kind, 0x05 | 0x0f | 0x85))
                    .unwrap_or(false)
            })
    })
}

fn disk_tail_free_bytes(snapshot: &HostSnapshot, disk: &BlockDevice) -> Option<u64> {
    if !matches!(disk.kind, NodeKind::Disk | NodeKind::Loop) {
        return None;
    }
    let disk_path = disk.path.as_deref()?;
    let table = snapshot
        .partition_tables
        .iter()
        .find(|table| table.device == disk_path)?;
    let sector_size = table.sector_size_bytes?;
    if sector_size == 0 {
        return None;
    }

    let disk_sectors = disk.size_bytes / sector_size;
    let limit = match table.label.as_deref()? {
        "dos" => disk_sectors,
        "gpt" => table
            .last_lba
            .and_then(|last| last.checked_add(1))
            .map(|usable| usable.min(disk_sectors))?,
        _ => return None,
    };
    let last_partition_end = table
        .partitions
        .iter()
        .filter_map(|record| record.start_sector.checked_add(record.size_sectors))
        .max()
        .unwrap_or(0);
    let free_sectors = limit.checked_sub(last_partition_end)?;
    free_sectors.checked_mul(sector_size)
}

fn visible_device_rows(graph: &StorageGraph, volumes_only: bool) -> Vec<DeviceRow<'_>> {
    device_rows(graph)
        .into_iter()
        .filter(|row| {
            !volumes_only
                || !matches!(
                    row.device.kind,
                    NodeKind::Disk | NodeKind::Loop | NodeKind::Rom
                )
        })
        .collect()
}

fn storage_mounts(snapshot: &HostSnapshot) -> Vec<&lsm_core::MountEntry> {
    const PSEUDO_FS: &[&str] = &[
        "proc",
        "sysfs",
        "securityfs",
        "cgroup",
        "cgroup2",
        "pstore",
        "bpf",
        "tracefs",
        "debugfs",
        "configfs",
        "fusectl",
        "devtmpfs",
        "devpts",
        "tmpfs",
        "hugetlbfs",
        "mqueue",
        "ramfs",
        "autofs",
        "binfmt_misc",
    ];

    snapshot
        .mounts
        .iter()
        .filter(|mount| {
            mount
                .fs_type
                .as_deref()
                .map(|fs| !PSEUDO_FS.contains(&fs))
                .unwrap_or(true)
        })
        .collect()
}

fn plan_candidate_rows(snapshot: &HostSnapshot) -> Vec<DeviceRow<'_>> {
    device_rows(&snapshot.storage)
        .into_iter()
        .filter(|row| {
            row.device
                .filesystem
                .as_ref()
                .map(|fs| !matches!(fs.fs_type.as_str(), "swap" | "LVM2_member"))
                .unwrap_or(false)
                && !row
                    .device
                    .mountpoints
                    .iter()
                    .any(|mount| mount.as_str() == "[SWAP]")
                && row.device.children.is_empty()
                && !is_extended_partition(snapshot, row.device)
        })
        .collect()
}

fn growth_presets_for_capacity(capacity: Option<u64>) -> Vec<Growth> {
    const ADAPTIVE_BYTES: [u64; 7] = [
        512 * 1024,
        1024 * 1024,
        8 * 1024 * 1024,
        64 * 1024 * 1024,
        512 * 1024 * 1024,
        1024 * 1024 * 1024,
        4 * 1024 * 1024 * 1024,
    ];

    let Some(capacity) = capacity else {
        return PLAN_GROWTH_PRESETS.to_vec();
    };

    let mut options: Vec<Growth> = ADAPTIVE_BYTES
        .into_iter()
        .filter(|bytes| *bytes <= capacity)
        .map(Growth::ByBytes)
        .collect();
    options.push(Growth::MaxFree);
    options
}

fn plan_growth_options(snapshot: &HostSnapshot, selected_device: usize) -> Vec<Growth> {
    let rows = plan_candidate_rows(snapshot);
    let Some(row) = rows.get(selected_device) else {
        return vec![Growth::MaxFree];
    };
    let target = plan_target(row.device);
    let analyzed_capacity = analyze_extendability(snapshot, &target)
        .ok()
        .and_then(|analysis| {
            analysis
                .immediate_growth_bytes
                .or(analysis.potential_underlying_growth_bytes)
        })
        .filter(|bytes| *bytes > 0);
    let layout_capacity = analyze_layout_opportunity(snapshot, &target)
        .map(|opportunity| opportunity.max_target_growth_bytes);
    let lvm_route_capacity = analyze_lvm_underlying_growth(
        snapshot,
        &ExtendRequest {
            target: target.clone(),
            growth: Growth::MaxFree,
        },
    )
    .map(|route| route.max_growth_bytes);
    let capacity = [analyzed_capacity, layout_capacity, lvm_route_capacity]
        .into_iter()
        .flatten()
        .max();

    let mut options = growth_presets_for_capacity(capacity);
    if let Some(capacity) = capacity {
        if let Some(growth) = preferred_layout_growth(capacity) {
            if !options.contains(&growth) {
                options.push(growth);
            }
        }
    }
    options
}

fn preferred_layout_growth(max_target_growth_bytes: u64) -> Option<Growth> {
    layout_opportunity_probe_sizes()
        .into_iter()
        .find(|bytes| *bytes <= max_target_growth_bytes)
        .map(Growth::ByBytes)
}

fn analysis_summary_lines(analysis: &ExtendAnalysis) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    match analysis.status {
        ExtendabilityStatus::Ready => {
            lines.push(Line::from("Can grow        Yes"));
            if let Some(bytes) = analysis.immediate_growth_bytes {
                lines.push(Line::from(format!(
                    "Available       {}",
                    human_bytes(bytes)
                )));
            }
        }
        ExtendabilityStatus::NeedsUnderlyingResize => {
            lines.push(Line::from(
                "Can grow        Yes, lower layer resize required",
            ));
            if let Some(bytes) = analysis.potential_underlying_growth_bytes {
                lines.push(Line::from(format!(
                    "Adjacent free   {}",
                    human_bytes(bytes)
                )));
            }
        }
        ExtendabilityStatus::NeedsUnderlyingCapacity => {
            lines.push(Line::from("Can grow        No in-place capacity"));
            lines.push(Line::from("Adjacent free   0 B"));
        }
        ExtendabilityStatus::NeedsGeometry => {
            lines.push(Line::from("Can grow        Unknown"));
            lines.push(Line::from("Blocker         Incomplete partition geometry"));
        }
        ExtendabilityStatus::RequiresMount => {
            lines.push(Line::from("Can grow        Blocked"));
            lines.push(Line::from("Blocker         Filesystem must be mounted"));
        }
        ExtendabilityStatus::UnsupportedFilesystem => {
            lines.push(Line::from("Can grow        Unsupported"));
        }
        ExtendabilityStatus::Unknown => {
            lines.push(Line::from("Can grow        Unknown"));
        }
    }

    if let Some(reason) = analysis.reasons.first() {
        lines.push(Line::from(""));
        lines.push(Line::from("Why"));
        lines.push(Line::from(format!("  {reason}")));
    }
    if let Some(step) = analysis.steps.first() {
        lines.push(Line::from("Next step"));
        lines.push(Line::from(format!("  {step}")));
    }

    lines
}

fn operation_summary(operation: &Operation) -> String {
    match operation {
        Operation::RevalidateSnapshot => "Revalidate snapshot".to_owned(),
        Operation::BackupLvmMetadata { .. } => "Backup LVM metadata".to_owned(),
        Operation::BackupPartitionTableMetadata { disk, .. } => {
            format!("Backup partition table {disk}")
        }
        Operation::ExtendPartition { partition, .. } => {
            format!("Extend partition {partition}")
        }
        Operation::ExtendLogicalVolume {
            additional_extents, ..
        } => format!("Extend logical volume by {additional_extents} extents"),
        Operation::GrowFilesystem {
            fs_type,
            mountpoint,
        } => format!("Grow {fs_type} on {mountpoint}"),
        Operation::RediscoverAndVerify => "Rediscover and verify".to_owned(),
    }
}

fn reversibility_label(reversibility: Reversibility) -> &'static str {
    match reversibility {
        Reversibility::NotApplicable => "check",
        Reversibility::Reversible => "reversible",
        Reversibility::Irreversible => "irreversible",
    }
}

fn plan_step_lines(steps: &[PlanStep]) -> Vec<Line<'static>> {
    steps
        .iter()
        .map(|step| {
            let dependency = if step.depends_on.is_empty() {
                String::new()
            } else {
                format!(
                    "  after {}",
                    step.depends_on
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            Line::from(format!(
                "{}  {}  [{}]{}",
                step.id,
                operation_summary(&step.operation),
                reversibility_label(step.reversibility),
                dependency
            ))
        })
        .collect()
}

fn preflight_lines(checks: &[PreflightCheck]) -> Vec<Line<'static>> {
    checks
        .iter()
        .map(|check| {
            let marker = match check.state {
                PreflightState::Verified => "[OK] ",
                PreflightState::Required => "[REQ]",
            };
            Line::from(format!("{marker} {:<30} {}", check.code, check.message))
        })
        .collect()
}

fn layout_opportunity_probe_sizes() -> [u64; 5] {
    [
        4 * 1024 * 1024 * 1024,
        2 * 1024 * 1024 * 1024,
        1024 * 1024 * 1024,
        512 * 1024 * 1024,
        64 * 1024 * 1024,
    ]
}

fn probe_layout_opportunity(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    target: &str,
) -> Option<(Growth, LayoutAlternative)> {
    for bytes in layout_opportunity_probe_sizes() {
        let growth = Growth::ByBytes(bytes);
        let plan = plan_extend(
            snapshot,
            capabilities,
            ExtendRequest {
                target: target.to_owned(),
                growth,
            },
        )
        .ok()?;
        if let Some(alternative) = plan.layout_alternatives().first() {
            return Some((growth, alternative.clone()));
        }
    }
    None
}

fn layout_opportunity_summary_lines(
    growth: Growth,
    alternative: &LayoutAlternative,
) -> Vec<Line<'static>> {
    vec![
        Line::from("Tail opportunity"),
        Line::from(format!("Potential       {}", growth_label(growth))),
        Line::from(format!(
            "Disk tail       {}",
            human_bytes(alternative.disk_tail_free_bytes)
        )),
        Line::from(format!(
            "Swap migration  {}",
            human_bytes(alternative.swap_bytes)
        )),
        Line::from(format!(
            "Blocking        {}",
            alternative.blocking_devices.join(", ")
        )),
        Line::from("Strategy        swap partition -> swapfile"),
    ]
}

fn growth_route_lines(route: &GrowthRouteAlternative) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Automatic growth route"),
        Line::from(format!("Target          {}", route.target)),
        Line::from(format!("Disk            {}", route.disk)),
        Line::from(format!(
            "Partition       {}",
            route.partition.as_deref().unwrap_or("-")
        )),
        Line::from(format!("PV              {}", route.physical_volume)),
        Line::from(format!("VG              {}", route.volume_group)),
        Line::from(format!("LV              {}", route.logical_volume)),
        Line::from(format!(
            "VG free now     {}",
            human_bytes(route.existing_vg_free_bytes)
        )),
        Line::from(format!(
            "PV slack        {}",
            human_bytes(route.pv_device_slack_bytes)
        )),
        Line::from(format!(
            "Adjacent raw    {}",
            human_bytes(route.adjacent_partition_free_bytes)
        )),
        Line::from(format!(
            "Potential       {}",
            human_bytes(route.max_growth_bytes)
        )),
        Line::from(format!(
            "Partition grow  {}",
            human_bytes(route.required_partition_growth_bytes)
        )),
        Line::from(""),
        Line::from("Planned route"),
    ];
    for (index, step) in route.steps.iter().enumerate() {
        lines.push(Line::from(format!("{}. {}", index + 1, step)));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Advisory only: M1A does not execute this chained route.",
    ));
    lines
}

fn layout_alternative_lines(alternative: &LayoutAlternative) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Layout alternative"),
        Line::from(format!(
            "Target growth   +{}",
            human_bytes(alternative.requested_growth_bytes)
        )),
        Line::from(format!(
            "Disk tail       {}",
            human_bytes(alternative.disk_tail_free_bytes)
        )),
        Line::from(format!(
            "Swap migrate    {}",
            human_bytes(alternative.swap_bytes)
        )),
        Line::from(format!(
            "Root raw grow   {}",
            human_bytes(alternative.required_partition_growth_bytes)
        )),
        Line::from(format!(
            "Raw tail after  {}",
            human_bytes(alternative.remaining_raw_tail_bytes)
        )),
        Line::from(format!(
            "Blocking        {}",
            alternative.blocking_devices.join(", ")
        )),
        Line::from(""),
        Line::from("Alternative steps"),
    ];
    for (index, step) in alternative.steps.iter().enumerate() {
        lines.push(Line::from(format!("{}. {}", index + 1, step)));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Advisory only: this layout migration is not executable in M1A.",
    ));
    lines
}

fn growth_label(growth: Growth) -> String {
    match growth {
        Growth::ByBytes(bytes) => format!("+{}", human_bytes(bytes)),
        Growth::MaxFree => "Max free".to_owned(),
    }
}

fn strict_plan_lines(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    target: &str,
    growth: Growth,
) -> Vec<Line<'static>> {
    match plan_extend(
        snapshot,
        capabilities,
        ExtendRequest {
            target: target.to_owned(),
            growth,
        },
    ) {
        Ok(plan) if plan.status() == PlanStatus::Preview => {
            let mut lines = vec![Line::from("Planner         Preview ready")];
            if let Some(change) = plan.size_change() {
                lines.push(Line::from("Layout          LVM"));
                lines.push(Line::from(format!(
                    "Growth          {}",
                    human_bytes(change.rounded_growth_bytes)
                )));
                lines.push(Line::from(format!(
                    "Expected size   {}",
                    human_bytes_precise(change.expected_lv_size_bytes)
                )));
                lines.push(Line::from(format!(
                    "VG free after   {}",
                    human_bytes(change.remaining_vg_free_bytes)
                )));
            }
            if let Some(change) = plan.partition_size_change() {
                lines.push(Line::from("Layout          Direct partition"));
                lines.push(Line::from(format!("Disk            {}", change.disk)));
                lines.push(Line::from(format!(
                    "Growth          {}",
                    human_bytes(change.rounded_growth_bytes)
                )));
                lines.push(Line::from(format!(
                    "Expected size   {}",
                    human_bytes_precise(change.expected_partition_size_bytes)
                )));
                lines.push(Line::from(format!(
                    "Adjacent after  {}",
                    human_bytes(change.remaining_adjacent_free_bytes)
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from("Preflight"));
            lines.extend(preflight_lines(plan.preflight_checks()));
            lines.push(Line::from(""));
            lines.push(Line::from("Plan steps"));
            lines.extend(plan_step_lines(plan.steps()));
            lines
        }
        Ok(plan) => {
            let mut lines = vec![Line::from("Planner         Blocked")];
            if let Some(blocker) = plan.blockers().first() {
                lines.push(Line::from(format!(
                    "Blocker         [{}] {}",
                    blocker.code, blocker.message
                )));
            }
            if let Some(route) = plan.growth_route_alternatives().first() {
                lines.push(Line::from(""));
                lines.extend(growth_route_lines(route));
            } else if let Some(alternative) = plan.layout_alternatives().first() {
                lines.push(Line::from(""));
                lines.extend(layout_alternative_lines(alternative));
            }
            lines
        }
        Err(error) => vec![
            Line::from("Planner         Error"),
            Line::from(format!("Reason          {error}")),
        ],
    }
}

fn plan_target(device: &BlockDevice) -> String {
    device
        .mountpoints
        .iter()
        .find(|mount| mount.as_str() != "[SWAP]")
        .cloned()
        .or_else(|| device.path.clone())
        .unwrap_or_else(|| device.name.clone())
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn human_bytes_precise(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    match unit {
        0 => format!("{bytes} {}", UNITS[unit]),
        1 | 2 => format!("{value:.1} {}", UNITS[unit]),
        _ => format!("{value:.3} {}", UNITS[unit]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::{CollectorState, CollectorStatus, Filesystem};

    fn device(name: &str, kind: NodeKind, children: Vec<BlockDevice>) -> BlockDevice {
        BlockDevice {
            name: name.to_string(),
            kernel_name: Some(name.to_string()),
            path: Some(format!("/dev/{name}")),
            kind,
            size_bytes: 1024,
            start_512_sector: None,
            logical_sector_bytes: Some(512),
            filesystem: None,
            mountpoints: Vec::new(),
            parent_kernel_name: None,
            model: None,
            serial: None,
            uuid: None,
            partition_uuid: None,
            partition_table: None,
            children,
        }
    }

    fn snapshot() -> HostSnapshot {
        let mut root = device(
            "sda",
            NodeKind::Disk,
            vec![device("sda1", NodeKind::Partition, vec![])],
        );
        root.children[0].filesystem = Some(Filesystem {
            fs_type: "ext4".into(),
            version: Some("1.0".into()),
        });
        root.children[0].mountpoints = vec!["/".into()];

        HostSnapshot {
            storage: StorageGraph {
                block_devices: vec![root],
            },
            partition_tables: Vec::new(),
            mounts: Vec::new(),
            fstab: Vec::new(),
            swaps: Vec::new(),
            lvm: None,
            diagnostics: Vec::new(),
            collectors: vec![CollectorStatus {
                component: "lsblk".into(),
                state: CollectorState::Complete,
                detail: None,
            }],
        }
    }

    #[test]
    fn navigation_exposes_expected_sections() {
        assert_eq!(
            Section::ALL,
            [
                Section::Disks,
                Section::Volumes,
                Section::Swap,
                Section::Mounts,
                Section::Diagnostics,
                Section::Plans,
                Section::Create,
            ]
        );
    }

    #[test]
    fn flattened_devices_preserve_hierarchy_and_selection() {
        let snap = snapshot();
        let rows = device_rows(&snap.storage);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].depth, 0);
        assert_eq!(rows[0].device.name, "sda");
        assert_eq!(rows[1].depth, 1);
        assert_eq!(rows[1].device.name, "sda1");

        let mut state = AppState::new(&snap);
        state.select_next_device(&snap, false);
        assert_eq!(state.selected_device, 1);
        state.select_next_device(&snap, false);
        assert_eq!(state.selected_device, 1);
        state.select_previous_device();
        assert_eq!(state.selected_device, 0);
    }

    #[test]
    fn volumes_selection_uses_filtered_rows_not_global_device_index() {
        let snap = snapshot();
        let rows = visible_device_rows(&snap.storage, true);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device.name, "sda1");
    }

    #[test]
    fn default_mount_view_hides_pseudo_filesystems_but_keeps_real_storage() {
        let mut snap = snapshot();
        snap.mounts = vec![
            lsm_core::MountEntry {
                source: Some("proc".into()),
                target: "/proc".into(),
                fs_type: Some("proc".into()),
                options: vec!["rw".into()],
            },
            lsm_core::MountEntry {
                source: Some("/dev/sda1".into()),
                target: "/".into(),
                fs_type: Some("ext4".into()),
                options: vec!["rw".into()],
            },
            lsm_core::MountEntry {
                source: Some("//server/share".into()),
                target: "/mnt/share".into(),
                fs_type: Some("cifs".into()),
                options: vec!["rw".into()],
            },
        ];

        let mounts = storage_mounts(&snap);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].target, "/");
        assert_eq!(mounts[1].target, "/mnt/share");
    }

    #[test]
    fn dos_extended_partition_is_presented_as_container_not_one_kib_volume() {
        let mut snap = snapshot();
        snap.storage.block_devices[0].children.push(device(
            "sda2",
            NodeKind::Partition,
            vec![device("sda5", NodeKind::Partition, vec![])],
        ));
        snap.storage.block_devices[0].children[1].size_bytes = 1024;
        snap.partition_tables.push(lsm_core::PartitionTable {
            device: "/dev/sda".into(),
            label: Some("dos".into()),
            id: None,
            unit: Some("sectors".into()),
            first_lba: None,
            last_lba: None,
            sector_size_bytes: Some(512),
            partitions: vec![
                lsm_core::PartitionRecord {
                    node: "/dev/sda2".into(),
                    start_sector: 100,
                    size_sectors: 1000,
                    partition_type: Some("5".into()),
                    uuid: None,
                    name: None,
                    attrs: None,
                    bootable: None,
                },
                lsm_core::PartitionRecord {
                    node: "/dev/sda5".into(),
                    start_sector: 101,
                    size_sectors: 999,
                    partition_type: Some("82".into()),
                    uuid: None,
                    name: None,
                    attrs: None,
                    bootable: None,
                },
            ],
        });

        let extended = &snap.storage.block_devices[0].children[1];
        assert_eq!(device_role(&snap, extended), "Extended container");
        assert_eq!(device_size_for_display(&snap, extended), "container");
    }

    #[test]
    fn content_scroll_resets_when_section_changes() {
        let snap = snapshot();
        let mut state = AppState::new(&snap);
        state.section_index = 3;
        state.scroll_down();
        state.scroll_down();
        assert_eq!(state.content_scroll, 2);
        state.next_section();
        assert_eq!(state.content_scroll, 0);
    }

    #[test]
    fn compact_header_reports_only_readonly_and_actionable_diagnostics() {
        let mut snap = snapshot();
        snap.diagnostics.push(lsm_core::StorageDiagnostic {
            code: "warn".into(),
            severity: DiagnosticSeverity::Warning,
            message: "warning".into(),
            device: None,
        });
        let text = header_text(&snap);
        assert!(text.contains("Read-only"));
        assert!(text.contains("1 warning"));
        assert!(!text.contains("tools"));
    }

    #[test]
    fn extend_targets_exclude_swap_and_container_devices() {
        let mut snap = snapshot();
        let mut extended = device("sda2", NodeKind::Partition, vec![]);
        extended.size_bytes = 1024;
        let mut swap = device("sda5", NodeKind::Partition, vec![]);
        swap.filesystem = Some(Filesystem {
            fs_type: "swap".into(),
            version: Some("1".into()),
        });
        swap.mountpoints = vec!["[SWAP]".into()];
        snap.storage.block_devices[0].children.push(extended);
        snap.storage.block_devices[0].children.push(swap);

        let rows = plan_candidate_rows(&snap);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device.name, "sda1");
    }

    #[test]
    fn analysis_summary_exposes_capacity_and_reason() {
        let analysis = lsm_core::ExtendAnalysis {
            target: "/".into(),
            device: Some("/dev/sda1".into()),
            filesystem: Some("ext4".into()),
            current_size_bytes: Some(9_711_910_912),
            immediate_growth_bytes: None,
            potential_underlying_growth_bytes: Some(1_047_552),
            status: lsm_core::ExtendabilityStatus::NeedsUnderlyingResize,
            reasons: vec![
                "1047552 bytes of adjacent capacity were detected after the target partition"
                    .into(),
            ],
            steps: vec!["grow the partition into verified adjacent free space".into()],
        };

        let text = analysis_summary_lines(&analysis)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Can grow"));
        assert!(text.contains("1023.0 KiB"));
        assert!(text.contains("Adjacent free"));
        assert!(text.contains("grow the partition"));
    }

    #[test]
    fn default_mount_view_hides_binfmt_misc() {
        let mut snap = snapshot();
        snap.mounts = vec![
            lsm_core::MountEntry {
                source: Some("binfmt_misc".into()),
                target: "/proc/sys/fs/binfmt_misc".into(),
                fs_type: Some("binfmt_misc".into()),
                options: vec!["rw".into()],
            },
            lsm_core::MountEntry {
                source: Some("/dev/sda1".into()),
                target: "/".into(),
                fs_type: Some("ext4".into()),
                options: vec!["rw".into()],
            },
        ];

        let mounts = storage_mounts(&snap);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].target, "/");
    }

    #[test]
    fn plan_growth_presets_are_safe_and_cycle_without_execution() {
        let snap = snapshot();
        let mut state = AppState::new(&snap);
        state.section_index = 5;

        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            lsm_planner::Growth::ByBytes(512 * 1024 * 1024)
        );
        state.next_plan_growth_for_snapshot(&snap);
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            lsm_planner::Growth::ByBytes(1024 * 1024 * 1024)
        );
        state.next_plan_growth_for_snapshot(&snap);
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            lsm_planner::Growth::ByBytes(4 * 1024 * 1024 * 1024)
        );
        state.next_plan_growth_for_snapshot(&snap);
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            lsm_planner::Growth::MaxFree
        );
        state.next_plan_growth_for_snapshot(&snap);
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            lsm_planner::Growth::MaxFree
        );
        state.previous_plan_growth();
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            lsm_planner::Growth::ByBytes(4 * 1024 * 1024 * 1024)
        );
    }

    #[test]
    fn plus_press_advances_once_and_repeat_release_are_ignored() {
        use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

        let snap = snapshot();
        let mut state = AppState::new(&snap);
        state.section_index = 5;

        let press = KeyEvent {
            code: KeyCode::Char('+'),
            modifiers: KeyModifiers::SHIFT,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };
        assert_eq!(
            handle_key_event(&mut state, &snap, press),
            LoopControl::Continue
        );
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            Growth::ByBytes(1024 * 1024 * 1024)
        );

        let repeat = KeyEvent {
            kind: KeyEventKind::Repeat,
            ..press
        };
        assert_eq!(
            handle_key_event(&mut state, &snap, repeat),
            LoopControl::Continue
        );
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            Growth::ByBytes(1024 * 1024 * 1024)
        );

        let release = KeyEvent {
            kind: KeyEventKind::Release,
            ..press
        };
        assert_eq!(
            handle_key_event(&mut state, &snap, release),
            LoopControl::Continue
        );
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            Growth::ByBytes(1024 * 1024 * 1024)
        );
    }

    #[test]
    fn repeated_plus_at_max_free_remains_bounded() {
        use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

        let snap = snapshot();
        let mut state = AppState::new(&snap);
        state.section_index = 5;
        state.plan_growth_index = PLAN_GROWTH_PRESETS.len() - 1;

        let press = KeyEvent {
            code: KeyCode::Char('+'),
            modifiers: KeyModifiers::SHIFT,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };

        for _ in 0..100 {
            assert_eq!(
                handle_key_event(&mut state, &snap, press),
                LoopControl::Continue
            );
        }
        assert_eq!(state.plan_growth_for_snapshot(&snap), Growth::MaxFree);
    }

    #[test]
    fn minus_variants_and_page_keys_change_plan_growth() {
        use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

        let snap = snapshot();
        let mut state = AppState::new(&snap);
        state.section_index = 5;
        state.plan_growth_index = 2;

        let plain_minus = KeyEvent {
            code: KeyCode::Char('-'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };
        assert_eq!(
            handle_key_event(&mut state, &snap, plain_minus),
            LoopControl::Continue
        );
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            Growth::ByBytes(1024 * 1024 * 1024)
        );

        let shifted_minus = KeyEvent {
            code: KeyCode::Char('_'),
            modifiers: KeyModifiers::SHIFT,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };
        assert_eq!(
            handle_key_event(&mut state, &snap, shifted_minus),
            LoopControl::Continue
        );
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            Growth::ByBytes(512 * 1024 * 1024)
        );

        let page_down = KeyEvent {
            code: KeyCode::PageDown,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };
        assert_eq!(
            handle_key_event(&mut state, &snap, page_down),
            LoopControl::Continue
        );
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            Growth::ByBytes(1024 * 1024 * 1024)
        );

        let page_up = KeyEvent {
            code: KeyCode::PageUp,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };
        assert_eq!(
            handle_key_event(&mut state, &snap, page_up),
            LoopControl::Continue
        );
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            Growth::ByBytes(512 * 1024 * 1024)
        );
    }

    #[test]
    fn plain_equals_in_plans_is_treated_as_plus_key() {
        use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

        let snap = snapshot();
        let mut state = AppState::new(&snap);
        state.section_index = 5;

        let equals = KeyEvent {
            code: KeyCode::Char('='),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };

        assert_eq!(
            handle_key_event(&mut state, &snap, equals),
            LoopControl::Continue
        );
        assert_eq!(
            state.plan_growth_for_snapshot(&snap),
            Growth::ByBytes(1024 * 1024 * 1024)
        );
    }

    #[test]
    fn adaptive_growth_presets_hide_values_larger_than_verified_capacity() {
        let presets = growth_presets_for_capacity(Some(1_047_552));
        assert_eq!(presets, vec![Growth::ByBytes(512 * 1024), Growth::MaxFree]);
    }

    #[test]
    fn adaptive_growth_presets_fall_back_when_capacity_is_unknown() {
        assert_eq!(
            growth_presets_for_capacity(None),
            PLAN_GROWTH_PRESETS.to_vec()
        );
    }

    #[test]
    fn precise_size_display_distinguishes_small_growth_on_large_volume() {
        assert_eq!(human_bytes_precise(9_711_910_912), "9.045 GiB");
        assert_eq!(human_bytes_precise(9_712_958_464), "9.046 GiB");
    }

    #[test]
    fn plan_step_lines_show_dependencies_and_reversibility() {
        let steps = vec![
            lsm_planner::PlanStep {
                id: 1,
                depends_on: vec![],
                operation: lsm_planner::Operation::RevalidateSnapshot,
                reversibility: lsm_planner::Reversibility::NotApplicable,
            },
            lsm_planner::PlanStep {
                id: 2,
                depends_on: vec![1],
                operation: lsm_planner::Operation::BackupPartitionTableMetadata {
                    disk: "/dev/sda".into(),
                    table_label: "dos".into(),
                    table_id: Some("0xf5b1b569".into()),
                },
                reversibility: lsm_planner::Reversibility::Reversible,
            },
            lsm_planner::PlanStep {
                id: 3,
                depends_on: vec![2],
                operation: lsm_planner::Operation::ExtendPartition {
                    partition: "/dev/sda1".into(),
                    start_sector: 2048,
                    old_size_sectors: 18_968_576,
                    new_size_sectors: 18_969_600,
                    sector_size_bytes: 512,
                },
                reversibility: lsm_planner::Reversibility::Irreversible,
            },
            lsm_planner::PlanStep {
                id: 4,
                depends_on: vec![3],
                operation: lsm_planner::Operation::GrowFilesystem {
                    fs_type: "ext4".into(),
                    mountpoint: "/".into(),
                },
                reversibility: lsm_planner::Reversibility::Irreversible,
            },
            lsm_planner::PlanStep {
                id: 5,
                depends_on: vec![4],
                operation: lsm_planner::Operation::RediscoverAndVerify,
                reversibility: lsm_planner::Reversibility::NotApplicable,
            },
        ];

        let text = plan_step_lines(&steps)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("1  Revalidate snapshot"));
        assert!(text.contains("2  Backup partition table /dev/sda"));
        assert!(text.contains("after 1"));
        assert!(text.contains("3  Extend partition /dev/sda1"));
        assert!(text.contains("irreversible"));
        assert!(text.contains("4  Grow ext4 on /"));
        assert!(text.contains("5  Rediscover and verify"));
    }

    #[test]
    fn operation_summary_keeps_lvm_preview_human_readable() {
        let operation = lsm_planner::Operation::ExtendLogicalVolume {
            lv_uuid: "lv-uuid".into(),
            additional_extents: 8,
            expected_lv_size_bytes: 42 * 1024 * 1024,
        };
        assert_eq!(
            operation_summary(&operation),
            "Extend logical volume by 8 extents"
        );
    }

    #[test]
    fn preflight_lines_distinguish_verified_and_required_checks() {
        let checks = vec![
            lsm_planner::PreflightCheck {
                code: "geometry".into(),
                state: lsm_planner::PreflightState::Verified,
                message: "partition geometry is consistent".into(),
            },
            lsm_planner::PreflightCheck {
                code: "filesystem-health".into(),
                state: lsm_planner::PreflightState::Required,
                message: "filesystem health must be checked".into(),
            },
        ];

        let text = preflight_lines(&checks)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("[OK]  geometry"));
        assert!(text.contains("[REQ] filesystem-health"));
        assert!(text.contains("filesystem health must be checked"));
    }

    #[test]
    fn device_table_cells_include_hierarchy_filesystem_and_mount() {
        let snap = snapshot();
        let rows = device_rows(&snap.storage);
        let cells = device_table_cells(&snap, rows[1]);

        assert_eq!(cells[0], "  /dev/sda1");
        assert_eq!(cells[1], "1.0 KiB");
        assert_eq!(cells[2], "ext4");
        assert_eq!(cells[3], "/");
    }

    #[test]
    fn mount_table_cells_keep_target_source_and_filesystem_separate() {
        let mount = lsm_core::MountEntry {
            source: Some("//server/share".into()),
            target: "/mnt/share".into(),
            fs_type: Some("cifs".into()),
            options: vec!["rw".into()],
        };
        assert_eq!(
            mount_table_cells(&mount),
            [
                "/mnt/share".to_owned(),
                "//server/share".to_owned(),
                "cifs".to_owned(),
            ]
        );
    }

    #[test]
    fn toolbar_is_contextual_for_plans_and_regular_sections() {
        let plans = toolbar_text(Section::Plans);
        assert!(plans.contains("PgUp/PgDn"));
        assert!(plans.contains("Size"));
        assert!(plans.contains("Target"));

        let disks = toolbar_text(Section::Disks);
        assert!(disks.contains("1-7"));
        assert!(disks.contains("Section"));
        assert!(!disks.contains("PgUp/PgDn"));

        let create = toolbar_text(Section::Create);
        assert!(create.contains("1-7"));
        assert!(create.contains("Navigate"));
    }

    #[test]
    fn diagnostic_cells_keep_severity_code_and_message_separate() {
        let item = lsm_core::StorageDiagnostic {
            code: "geometry-warning".into(),
            severity: DiagnosticSeverity::Warning,
            message: "geometry requires attention".into(),
            device: Some("/dev/sda1".into()),
        };
        assert_eq!(
            diagnostic_table_cells(&item),
            [
                "Warning".to_owned(),
                "geometry-warning".to_owned(),
                "geometry requires attention".to_owned(),
            ]
        );
    }

    #[test]
    fn detail_rows_are_structured_key_value_pairs() {
        let snap = snapshot();
        let device = &snap.storage.block_devices[0].children[0];
        let rows = device_detail_rows(&snap, device);
        assert!(rows.contains(&["Device".to_owned(), "/dev/sda1".to_owned()]));
        assert!(rows.contains(&["Filesystem".to_owned(), "ext4".to_owned()]));
        assert!(rows.contains(&["Mounted at".to_owned(), "/".to_owned()]));
    }

    #[test]
    fn preflight_and_plan_step_cells_are_table_ready() {
        let check = lsm_planner::PreflightCheck {
            code: "filesystem-health".into(),
            state: lsm_planner::PreflightState::Required,
            message: "verify filesystem health".into(),
        };
        assert_eq!(
            preflight_table_cells(&check),
            [
                "[REQ]".to_owned(),
                "filesystem-health".to_owned(),
                "Check health/features/grow support".to_owned(),
            ]
        );

        let step = lsm_planner::PlanStep {
            id: 3,
            depends_on: vec![2],
            operation: lsm_planner::Operation::ExtendPartition {
                partition: "/dev/sda1".into(),
                start_sector: 2048,
                old_size_sectors: 100,
                new_size_sectors: 200,
                sector_size_bytes: 512,
            },
            reversibility: lsm_planner::Reversibility::Irreversible,
        };
        assert_eq!(
            plan_step_table_cells(&step),
            [
                "3".to_owned(),
                "Extend partition /dev/sda1".to_owned(),
                "irreversible".to_owned(),
                "2".to_owned(),
            ]
        );
    }

    #[test]
    fn plans_use_wide_layout_only_when_terminal_has_room() {
        assert_eq!(plan_layout_mode(140), PlanLayoutMode::Wide);
        assert_eq!(plan_layout_mode(109), PlanLayoutMode::Compact);
    }

    #[test]
    fn preflight_display_details_are_compact_but_structured_messages_stay_unchanged() {
        let check = lsm_planner::PreflightCheck {
            code: "runtime-identity-recheck".into(),
            state: lsm_planner::PreflightState::Required,
            message: "revalidate device, filesystem and plan basis immediately before mutation"
                .into(),
        };
        assert_eq!(
            preflight_display_detail(&check),
            "Revalidate identities and plan basis"
        );
        assert_eq!(
            check.message,
            "revalidate device, filesystem and plan basis immediately before mutation"
        );
    }

    #[test]
    fn diagnostic_summary_separates_device_from_full_message() {
        let item = lsm_core::StorageDiagnostic {
            code: "fstab-device-not-in-lsblk".into(),
            severity: DiagnosticSeverity::Warning,
            message: "full diagnostic message".into(),
            device: Some("/dev/sr0".into()),
        };
        assert_eq!(
            diagnostic_summary_cells(&item),
            [
                "Warning".to_owned(),
                "fstab-device-not-in-lsblk".to_owned(),
                "/dev/sr0".to_owned(),
            ]
        );
    }

    #[test]
    fn analysis_reason_and_next_step_render_on_separate_indented_lines() {
        let analysis = lsm_core::ExtendAnalysis {
            target: "/".into(),
            device: Some("/dev/sda1".into()),
            filesystem: Some("ext4".into()),
            current_size_bytes: Some(9_711_910_912),
            immediate_growth_bytes: None,
            potential_underlying_growth_bytes: Some(1_047_552),
            status: lsm_core::ExtendabilityStatus::NeedsUnderlyingResize,
            reasons: vec!["verified adjacent capacity detected".into()],
            steps: vec!["grow the partition first".into()],
        };

        let text = analysis_summary_lines(&analysis)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Why\n  verified adjacent capacity detected"));
        assert!(text.contains("Next step\n  grow the partition first"));
    }

    #[test]
    fn refresh_key_requests_fresh_discovery_without_mutating_storage() {
        use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

        let snap = snapshot();
        let mut state = AppState::new(&snap);
        let refresh = KeyEvent {
            code: KeyCode::Char('r'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };

        assert_eq!(
            handle_key_event(&mut state, &snap, refresh),
            LoopControl::Refresh
        );
    }

    #[test]
    fn dos_disk_tail_free_uses_current_disk_size_after_last_partition() {
        let mut snap = snapshot();
        snap.storage.block_devices[0].size_bytes = 11 * 1024 * 1024;
        snap.partition_tables = vec![lsm_core::PartitionTable {
            device: "/dev/sda".into(),
            label: Some("dos".into()),
            id: Some("0x12345678".into()),
            unit: Some("sectors".into()),
            first_lba: None,
            last_lba: None,
            sector_size_bytes: Some(512),
            partitions: vec![
                lsm_core::PartitionRecord {
                    node: "/dev/sda1".into(),
                    start_sector: 2_048,
                    size_sectors: 8_192,
                    partition_type: Some("83".into()),
                    uuid: None,
                    name: None,
                    attrs: None,
                    bootable: None,
                },
                lsm_core::PartitionRecord {
                    node: "/dev/sda2".into(),
                    start_sector: 12_288,
                    size_sectors: 8_192,
                    partition_type: Some("5".into()),
                    uuid: None,
                    name: None,
                    attrs: None,
                    bootable: None,
                },
                lsm_core::PartitionRecord {
                    node: "/dev/sda5".into(),
                    start_sector: 12_290,
                    size_sectors: 8_188,
                    partition_type: Some("82".into()),
                    uuid: None,
                    name: None,
                    attrs: None,
                    bootable: None,
                },
            ],
        }];

        let disk = &snap.storage.block_devices[0];
        assert_eq!(disk_tail_free_bytes(&snap, disk), Some(1024 * 1024));

        let rows = device_detail_rows(&snap, disk);
        assert!(rows.contains(&["Tail free".to_owned(), "1.0 MiB".to_owned()]));
    }

    #[test]
    fn toolbar_exposes_refresh_in_all_sections() {
        assert!(toolbar_text(Section::Disks).contains("Refresh"));
        assert!(toolbar_text(Section::Plans).contains("Refresh"));
    }

    #[test]
    fn layout_alternative_lines_explain_swap_migration_without_claiming_execution() {
        let alternative = lsm_planner::LayoutAlternative {
            code: "migrate-tail-swap".into(),
            summary: "tail is blocked by swap".into(),
            disk: "/dev/sda".into(),
            target: "/dev/sda1".into(),
            requested_growth_bytes: 1024 * 1024 * 1024,
            disk_tail_free_bytes: 1025 * 1024 * 1024,
            swap_bytes: 975 * 1024 * 1024,
            required_partition_growth_bytes: 1999 * 1024 * 1024,
            remaining_raw_tail_bytes: 2 * 1024 * 1024,
            blocking_devices: vec!["/dev/sda2".into(), "/dev/sda5".into()],
            steps: vec![
                "verify hibernation and swapoff safety".into(),
                "migrate swap to a swapfile".into(),
            ],
        };

        let text = layout_alternative_lines(&alternative)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Layout alternative"));
        assert!(text.contains("+1.0 GiB"));
        assert!(text.contains("/dev/sda2, /dev/sda5"));
        assert!(text.contains("swapfile"));
        assert!(text.contains("Advisory only"));
    }

    #[test]
    fn opportunity_probe_sizes_include_one_gib_before_smaller_fallbacks() {
        assert_eq!(
            layout_opportunity_probe_sizes(),
            [
                4 * 1024 * 1024 * 1024,
                2 * 1024 * 1024 * 1024,
                1024 * 1024 * 1024,
                512 * 1024 * 1024,
                64 * 1024 * 1024,
            ]
        );
    }

    #[test]
    fn lowercase_refresh_and_uppercase_rescan_are_distinct_actions() {
        use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

        let snap = snapshot();
        let mut state = AppState::new(&snap);
        let key = |code| KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };

        assert_eq!(
            handle_key_event(&mut state, &snap, key(KeyCode::Char('r'))),
            LoopControl::Refresh
        );
        assert_eq!(
            handle_key_event(&mut state, &snap, key(KeyCode::Char('R'))),
            LoopControl::KernelRescan
        );
    }

    #[test]
    fn rescan_sysfs_path_rejects_path_traversal_and_accepts_kernel_names() {
        assert_eq!(
            rescan_sysfs_path("sda").unwrap(),
            std::path::PathBuf::from("/sys/class/block/sda/device/rescan")
        );
        assert_eq!(
            rescan_sysfs_path("nvme0n1").unwrap(),
            std::path::PathBuf::from("/sys/class/block/nvme0n1/device/rescan")
        );
        assert!(rescan_sysfs_path("../sda").is_none());
        assert!(rescan_sysfs_path("sda/../../x").is_none());
    }

    #[test]
    fn preferred_layout_growth_selects_one_gib_for_live_tail_capacity() {
        assert_eq!(
            preferred_layout_growth(1_075_838_976),
            Some(Growth::ByBytes(1024 * 1024 * 1024))
        );
        assert_eq!(
            preferred_layout_growth(600 * 1024 * 1024),
            Some(Growth::ByBytes(512 * 1024 * 1024))
        );
        assert_eq!(preferred_layout_growth(32 * 1024 * 1024), None);
    }

    #[test]
    fn plan_target_prefers_mountpoint_then_device_path() {
        let snap = snapshot();
        let rows = device_rows(&snap.storage);
        assert_eq!(plan_target(rows[1].device), "/");
        assert_eq!(plan_target(rows[0].device), "/dev/sda");
    }
}
