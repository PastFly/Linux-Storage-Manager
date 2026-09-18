use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use lsm_core::{
    BlockDevice, DiagnosticSeverity, ExtendAnalysis, ExtendabilityStatus, HostCapabilities,
    HostSnapshot, NodeKind, StorageGraph,
};
use lsm_discovery::analyze_extendability;
use lsm_planner::{plan_extend, ExtendRequest, Growth, PlanStatus};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Disks,
    Volumes,
    Swap,
    Mounts,
    Diagnostics,
    Plans,
}

impl Section {
    const ALL: [Section; 6] = [
        Section::Disks,
        Section::Volumes,
        Section::Swap,
        Section::Mounts,
        Section::Diagnostics,
        Section::Plans,
    ];

    fn label(self) -> &'static str {
        match self {
            Section::Disks => "Disks",
            Section::Volumes => "Volumes",
            Section::Swap => "Swap",
            Section::Mounts => "Mounts",
            Section::Diagnostics => "Diagnostics",
            Section::Plans => "Plans",
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
            _ => visible_device_rows(&snapshot.storage, false).len(),
        };
        self.selected_device = self.selected_device.min(len.saturating_sub(1));
    }

    fn select_next_plan_candidate(&mut self, snapshot: &HostSnapshot) {
        let len = plan_candidate_rows(snapshot).len();
        if len > 0 {
            self.selected_device = (self.selected_device + 1).min(len - 1);
        }
    }

    fn plan_growth(&self) -> Growth {
        PLAN_GROWTH_PRESETS[self.plan_growth_index]
    }

    fn next_plan_growth(&mut self) {
        self.plan_growth_index = (self.plan_growth_index + 1).min(PLAN_GROWTH_PRESETS.len() - 1);
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

pub fn run(snapshot: &HostSnapshot, capabilities: &HostCapabilities) -> Result<()> {
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
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
) -> Result<()> {
    let mut state = AppState::new(snapshot);

    loop {
        terminal.draw(|frame| draw(frame, snapshot, capabilities, state))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Up | KeyCode::Char('k') => match state.section() {
                        Section::Disks | Section::Volumes | Section::Plans => {
                            state.select_previous_device()
                        }
                        _ => state.scroll_up(),
                    },
                    KeyCode::Down | KeyCode::Char('j') => match state.section() {
                        Section::Disks | Section::Volumes => {
                            let volumes_only = state.section() == Section::Volumes;
                            state.select_next_device(snapshot, volumes_only)
                        }
                        Section::Plans => state.select_next_plan_candidate(snapshot),
                        _ => state.scroll_down(),
                    },
                    KeyCode::Left | KeyCode::BackTab => {
                        state.previous_section();
                        state.clamp_device_selection(snapshot);
                    }
                    KeyCode::Right | KeyCode::Tab => {
                        state.next_section();
                        state.clamp_device_selection(snapshot);
                    }
                    KeyCode::Char('1') => {
                        state.set_section(0);
                        state.clamp_device_selection(snapshot);
                    }
                    KeyCode::Char('2') => {
                        state.set_section(1);
                        state.clamp_device_selection(snapshot);
                    }
                    KeyCode::Char('3') => state.set_section(2),
                    KeyCode::Char('4') => state.set_section(3),
                    KeyCode::Char('5') => state.set_section(4),
                    KeyCode::Char('6') => {
                        state.set_section(5);
                        state.clamp_device_selection(snapshot);
                    }
                    KeyCode::Char('[') | KeyCode::Char('-')
                        if state.section() == Section::Plans =>
                    {
                        state.previous_plan_growth();
                    }
                    KeyCode::Char(']') | KeyCode::Char('+')
                        if state.section() == Section::Plans =>
                    {
                        state.next_plan_growth();
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw(
    frame: &mut ratatui::Frame<'_>,
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    state: AppState,
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
        Paragraph::new(if state.section() == Section::Plans {
            " ↑↓ target   [ ] / - + size   ←→/Tab section   q/Esc quit   preview only, no writes "
        } else {
            " ↑↓/jk navigate   ←→/Tab section   1-6 jump   q/Esc quit   no writes are performed "
        })
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
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(area);

    let rows = visible_device_rows(&snapshot.storage, volumes_only);
    let mut lines = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let marker = if index == state.selected_device {
            "›"
        } else {
            " "
        };
        let fs = row
            .device
            .filesystem
            .as_ref()
            .map(|item| item.fs_type.as_str())
            .unwrap_or("-");
        let role = device_role(snapshot, row.device);
        let descriptor = if role == "Extended container" {
            role
        } else {
            fs
        };
        let path = row.device.path.as_deref().unwrap_or(&row.device.name);
        let indent = "  ".repeat(row.depth);
        let line = Line::from(format!(
            "{marker} {indent}{path:<16} {:>9}  {descriptor}",
            device_size_for_display(snapshot, row.device)
        ));
        lines.push(if index == state.selected_device {
            line.style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED))
        } else {
            line
        });
    }
    if lines.is_empty() {
        lines.push(Line::from("No matching devices discovered."));
    }

    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(
            if volumes_only {
                " Volumes "
            } else {
                " Devices "
            },
        )),
        panes[0],
    );

    let detail = rows
        .get(state.selected_device)
        .map(|row| device_detail_lines(snapshot, row.device))
        .unwrap_or_else(|| vec![Line::from("No device selected.")]);
    frame.render_widget(
        Paragraph::new(detail).block(Block::default().borders(Borders::ALL).title(" Details ")),
        panes[1],
    );
}

fn render_swap(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    state: AppState,
) {
    let mut lines = vec![Line::from(format!(
        "Active swap areas: {}",
        snapshot.swaps.len()
    ))];
    for swap in &snapshot.swaps {
        lines.push(Line::from(format!(
            "{}   {}   size {}   used {}   priority {}",
            swap.name,
            swap.kind,
            human_bytes(swap.size_bytes),
            human_bytes(swap.used_bytes),
            swap.priority
        )));
    }
    if snapshot.swaps.is_empty() {
        lines.push(Line::from("No active swap areas discovered."));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((state.content_scroll, 0))
            .block(Block::default().borders(Borders::ALL).title(" Swap ")),
        area,
    );
}

fn render_mounts(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    state: AppState,
) {
    let mut lines = Vec::new();
    for mount in storage_mounts(snapshot) {
        lines.push(Line::from(format!(
            "{:<24}  {:<18}  {}",
            mount.target,
            mount.source.as_deref().unwrap_or("-"),
            mount.fs_type.as_deref().unwrap_or("-")
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from("No mount entries discovered."));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((state.content_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Storage mounts "),
            ),
        area,
    );
}

fn render_diagnostics(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    state: AppState,
) {
    let mut lines = Vec::new();
    for item in &snapshot.diagnostics {
        lines.push(Line::from(format!("{:?}  {}", item.severity, item.code)));
        lines.push(Line::from(format!("  {}", item.message)));
        lines.push(Line::from(""));
    }
    if lines.is_empty() {
        lines.push(Line::from("No diagnostics reported."));
        lines.push(Line::from(""));
    }
    let available = capabilities
        .tools
        .iter()
        .filter(|tool| tool.available)
        .count();
    lines.push(Line::from(format!(
        "Capabilities: {available}/{} tools available",
        capabilities.tools.len()
    )));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((state.content_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Diagnostics "),
            ),
        area,
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
    let lines = if let Some(row) = rows.get(state.selected_device) {
        let target = plan_target(row.device);
        match analyze_extendability(snapshot, &target) {
            Ok(analysis) => {
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
                            .map(human_bytes)
                            .unwrap_or_else(|| "-".to_owned())
                    )),
                    Line::from(""),
                ];
                lines.extend(analysis_summary_lines(&analysis));
                lines.push(Line::from(""));
                lines.push(Line::from("Strict plan preview"));
                lines.push(Line::from(format!(
                    "Requested       {}",
                    growth_label(state.plan_growth())
                )));
                lines.extend(strict_plan_lines(
                    snapshot,
                    capabilities,
                    row.device,
                    &target,
                    state.plan_growth(),
                ));
                lines.push(Line::from(""));
                lines.push(Line::from("No changes will be made."));
                lines
            }
            Err(error) => vec![
                Line::from("Growth analysis"),
                Line::from(""),
                Line::from(format!("Target          {target}")),
                Line::from("Status          Analysis unavailable"),
                Line::from(format!("Reason          {error}")),
                Line::from(""),
                Line::from("No changes will be made."),
            ],
        }
    } else {
        vec![
            Line::from("No supported filesystem targets were discovered."),
            Line::from(""),
            Line::from("Plans currently analyzes ext4/XFS filesystems only."),
            Line::from("No changes will be made."),
        ]
    };

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" Plans ")),
        area,
    );
}

fn device_detail_lines(snapshot: &HostSnapshot, device: &BlockDevice) -> Vec<Line<'static>> {
    let path = device.path.as_deref().unwrap_or(&device.name);
    let fs = device
        .filesystem
        .as_ref()
        .map(|item| item.fs_type.as_str())
        .unwrap_or("-");
    let mounts = if device.mountpoints.is_empty() {
        "-".to_owned()
    } else {
        device.mountpoints.join(", ")
    };

    vec![
        Line::from(format!("Device       {path}")),
        Line::from(format!("Type         {}", device_role(snapshot, device))),
        Line::from(format!(
            "Size         {}",
            device_size_for_display(snapshot, device)
        )),
        Line::from(format!("Filesystem   {fs}")),
        Line::from(format!("Mounted at   {mounts}")),
        Line::from(format!(
            "Partition tbl {}",
            device.partition_table.as_deref().unwrap_or("-")
        )),
        Line::from(format!(
            "Kernel name   {}",
            device.kernel_name.as_deref().unwrap_or("-")
        )),
    ]
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
                .map(|fs| matches!(fs.fs_type.as_str(), "ext4" | "xfs"))
                .unwrap_or(false)
                && row
                    .device
                    .mountpoints
                    .iter()
                    .any(|mount| mount.as_str() != "[SWAP]")
                && !is_extended_partition(snapshot, row.device)
        })
        .collect()
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
        lines.push(Line::from(format!("Why             {reason}")));
    }
    if let Some(step) = analysis.steps.first() {
        lines.push(Line::from(format!("Next step       {step}")));
    }

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
    device: &BlockDevice,
    target: &str,
    growth: Growth,
) -> Vec<Line<'static>> {
    if device.kind != NodeKind::Lvm {
        return vec![
            Line::from("Planner         Not available for direct partition resize in M1A"),
            Line::from("Safety          Advisory analysis only; executor is absent"),
        ];
    }

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
                lines.push(Line::from(format!(
                    "Growth          {}",
                    human_bytes(change.rounded_growth_bytes)
                )));
                lines.push(Line::from(format!(
                    "Expected size   {}",
                    human_bytes(change.expected_lv_size_bytes)
                )));
                lines.push(Line::from(format!(
                    "VG free after   {}",
                    human_bytes(change.remaining_vg_free_bytes)
                )));
            }
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
    fn plans_only_include_growable_filesystem_targets() {
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
        let mut state = AppState::new(&snapshot());
        state.section_index = 5;

        assert_eq!(
            state.plan_growth(),
            lsm_planner::Growth::ByBytes(512 * 1024 * 1024)
        );
        state.next_plan_growth();
        assert_eq!(
            state.plan_growth(),
            lsm_planner::Growth::ByBytes(1024 * 1024 * 1024)
        );
        state.next_plan_growth();
        assert_eq!(
            state.plan_growth(),
            lsm_planner::Growth::ByBytes(4 * 1024 * 1024 * 1024)
        );
        state.next_plan_growth();
        assert_eq!(state.plan_growth(), lsm_planner::Growth::MaxFree);
        state.next_plan_growth();
        assert_eq!(state.plan_growth(), lsm_planner::Growth::MaxFree);
        state.previous_plan_growth();
        assert_eq!(
            state.plan_growth(),
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
        assert_eq!(handle_key_event(&mut state, &snap, press), LoopControl::Continue);
        assert_eq!(
            state.plan_growth(),
            Growth::ByBytes(1024 * 1024 * 1024)
        );

        let repeat = KeyEvent { kind: KeyEventKind::Repeat, ..press };
        assert_eq!(handle_key_event(&mut state, &snap, repeat), LoopControl::Continue);
        assert_eq!(
            state.plan_growth(),
            Growth::ByBytes(1024 * 1024 * 1024)
        );

        let release = KeyEvent { kind: KeyEventKind::Release, ..press };
        assert_eq!(handle_key_event(&mut state, &snap, release), LoopControl::Continue);
        assert_eq!(
            state.plan_growth(),
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
            assert_eq!(handle_key_event(&mut state, &snap, press), LoopControl::Continue);
        }
        assert_eq!(state.plan_growth(), Growth::MaxFree);
    }

    #[test]
    fn plan_target_prefers_mountpoint_then_device_path() {
        let snap = snapshot();
        let rows = device_rows(&snap.storage);
        assert_eq!(plan_target(rows[1].device), "/");
        assert_eq!(plan_target(rows[0].device), "/dev/sda");
    }
}
