use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use lsm_core::{BlockDevice, HostCapabilities, StorageGraph};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph};
use ratatui::Terminal;

pub fn run(graph: &StorageGraph, capabilities: &HostCapabilities) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = event_loop(&mut terminal, graph, capabilities);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    graph: &StorageGraph,
    capabilities: &HostCapabilities,
) -> Result<()> {
    loop {
        terminal.draw(|frame| {
            let areas = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(frame.area());

            let mut lines = Vec::new();
            for device in &graph.block_devices {
                append_device_lines(device, 0, &mut lines);
            }

            let available = capabilities.tools.iter().filter(|tool| tool.available).count();
            let title = format!(
                " Linux Storage Manager — M0 read-only | tools {available}/{} ",
                capabilities.tools.len()
            );
            frame.render_widget(
                Paragraph::new(lines).block(Block::bordered().title(title)),
                areas[0],
            );
            frame.render_widget(
                Paragraph::new("q / Esc: quit   No storage-changing operations exist in M0")
                    .block(Block::bordered()),
                areas[1],
            );
        })?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                    return Ok(());
                }
            }
        }
    }
}

fn append_device_lines<'a>(device: &'a BlockDevice, depth: usize, lines: &mut Vec<Line<'a>>) {
    let indent = "  ".repeat(depth);
    let mountpoints = if device.mountpoints.is_empty() {
        String::new()
    } else {
        format!("  [{}]", device.mountpoints.join(", "))
    };
    let filesystem = device
        .filesystem
        .as_ref()
        .map(|fs| format!("  {}", fs.fs_type))
        .unwrap_or_default();
    let size = human_bytes(device.size_bytes);

    lines.push(Line::from(format!(
        "{indent}{}  {:?}  {size}{filesystem}{mountpoints}",
        device.path.as_deref().unwrap_or(&device.name),
        device.kind
    )));

    for child in &device.children {
        append_device_lines(child, depth + 1, lines);
    }
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
