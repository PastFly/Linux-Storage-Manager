use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use lsm_core::{
    BlockDevice, DiagnosticSeverity, HostCapabilities, HostSnapshot, NodeKind, StorageGraph,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
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
}

impl AppState {
    fn new(_snapshot: &HostSnapshot) -> Self {
        let selected_device = 0;
        Self {
            section_index: 0,
            selected_device,
        }
    }

    fn section(self) -> Section {
        Section::ALL[self.section_index]
    }

    fn next_section(&mut self) {
        self.section_index = (self.section_index + 1).min(Section::ALL.len() - 1);
    }

    fn previous_section(&mut self) {
        self.section_index = self.section_index.saturating_sub(1);
    }

    fn select_next_device(&mut self, snapshot: &HostSnapshot, volumes_only: bool) {
        let len = visible_device_rows(&snapshot.storage, volumes_only).len();
        if len > 0 {
            self.selected_device = (self.selected_device + 1).min(len - 1);
        }
    }

    fn clamp_device_selection(&mut self, snapshot: &HostSnapshot) {
        let volumes_only = self.section() == Section::Volumes;
        let len = visible_device_rows(&snapshot.storage, volumes_only).len();
        self.selected_device = self.selected_device.min(len.saturating_sub(1));
    }

    fn select_previous_device(&mut self) {
        self.selected_device = self.selected_device.saturating_sub(1);
    }
}

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
                        _ => state.previous_section(),
                    },
                    KeyCode::Down | KeyCode::Char('j') => match state.section() {
                        Section::Disks | Section::Volumes | Section::Plans => {
                            let volumes_only = state.section() == Section::Volumes;
                            state.select_next_device(snapshot, volumes_only)
                        }
                        _ => state.next_section(),
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
                        state.section_index = 0;
                        state.clamp_device_selection(snapshot);
                    }
                    KeyCode::Char('2') => {
                        state.section_index = 1;
                        state.clamp_device_selection(snapshot);
                    }
                    KeyCode::Char('3') => state.section_index = 2,
                    KeyCode::Char('4') => state.section_index = 3,
                    KeyCode::Char('5') => state.section_index = 4,
                    KeyCode::Char('6') => {
                        state.section_index = 5;
                        state.clamp_device_selection(snapshot);
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

    let available = capabilities
        .tools
        .iter()
        .filter(|tool| tool.available)
        .count();
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

    let header = format!(
        " Linux Storage Manager   READ-ONLY   tools {available}/{}   diagnostics {errors}E/{warnings}W ",
        capabilities.tools.len()
    );
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

    render_section(frame, body[1], snapshot, state);

    frame.render_widget(
        Paragraph::new(
            " ↑↓/jk navigate   ←→/Tab section   1-6 jump   q/Esc quit   no writes are performed ",
        )
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
    state: AppState,
) {
    match state.section() {
        Section::Disks => render_devices(frame, area, snapshot, state, false),
        Section::Volumes => render_devices(frame, area, snapshot, state, true),
        Section::Swap => render_swap(frame, area, snapshot),
        Section::Mounts => render_mounts(frame, area, snapshot),
        Section::Diagnostics => render_diagnostics(frame, area, snapshot),
        Section::Plans => render_plan_hint(frame, area, snapshot, state),
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
        let path = row.device.path.as_deref().unwrap_or(&row.device.name);
        let indent = "  ".repeat(row.depth);
        let line = Line::from(format!(
            "{marker} {indent}{path:<16} {:>9}  {fs}",
            human_bytes(row.device.size_bytes)
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
        .map(|row| device_detail_lines(row.device))
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
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Swap ")),
        area,
    );
}

fn render_mounts(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
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
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Mounts ")),
        area,
    );
}

fn render_diagnostics(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    snapshot: &HostSnapshot,
) {
    let mut lines = Vec::new();
    for item in &snapshot.diagnostics {
        lines.push(Line::from(format!(
            "{:?}  {}  {}",
            item.severity, item.code, item.message
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from("No diagnostics reported."));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
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
    state: AppState,
) {
    let rows = device_rows(&snapshot.storage);
    let lines = if let Some(row) = rows.get(state.selected_device) {
        let target = plan_target(row.device);
        vec![
            Line::from("Plan preview is CLI-backed and remains non-executable."),
            Line::from(""),
            Line::from(format!("Selected target: {target}")),
            Line::from(format!(
                "Preview: storagemgr plan extend {target} --by 1GiB"
            )),
            Line::from(format!("Explain: storagemgr explain {target}")),
            Line::from(""),
            Line::from("No apply/executor exists in this build."),
        ]
    } else {
        vec![Line::from("No device selected.")]
    };

    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Plans ")),
        area,
    );
}

fn device_detail_lines(device: &BlockDevice) -> Vec<Line<'static>> {
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
        Line::from(format!("Type         {:?}", device.kind)),
        Line::from(format!("Size         {}", human_bytes(device.size_bytes))),
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
    fn plan_target_prefers_mountpoint_then_device_path() {
        let snap = snapshot();
        let rows = device_rows(&snap.storage);
        assert_eq!(plan_target(rows[1].device), "/");
        assert_eq!(plan_target(rows[0].device), "/dev/sda");
    }
}
