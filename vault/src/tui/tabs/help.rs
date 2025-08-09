use crate::tui::app::App;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

pub fn render_help_tab(f: &mut Frame, _app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0)])
        .split(area);

    let help_text = vec![
        Line::from("SecretRust Vault Help"),
        Line::from(""),
        Line::from("Global Commands:"),
        Line::from("  q - Quit application"),
        Line::from("  :q - Quit application (vim style)"),
        Line::from("  /quit - Quit application (slash command)"),
        Line::from("  Ctrl+C - Quit application"),
        Line::from("  Ctrl+D - Quit application"),
        Line::from("  Tab - Cycle through tabs"),
        Line::from("  1-5 - Switch to specific tab"),
        Line::from("  u - Lock/unlock vault"),
        Line::from(""),
        Line::from("Keys Tab:"),
        Line::from("  Up/Down - Navigate items"),
        Line::from("  d - Delete selected item"),
        Line::from(""),
        Line::from("Search Tab:"),
        Line::from("  s - Edit search pattern"),
        Line::from("  Up/Down - Navigate results"),
        Line::from("  d - Delete selected item"),
        Line::from(""),
        Line::from("Add Tab:"),
        Line::from("  k - Edit key field"),
        Line::from("  v - Edit value field"),
        Line::from("  a - Add entry"),
        Line::from(""),
        Line::from("Settings Tab:"),
        Line::from("  p - Edit new passphrase"),
        Line::from("  c - Edit confirm passphrase"),
        Line::from("  r - Rotate encryption key"),
        Line::from(""),
        Line::from("When editing text:"),
        Line::from("  Enter - Confirm"),
        Line::from("  Esc - Cancel"),
        Line::from(""),
        Line::from("Security Features:"),
        Line::from("  • Session timeout after 5 minutes of inactivity"),
        Line::from("  • Secure memory handling for sensitive data"),
        Line::from("  • Key rotation for enhanced security"),
    ];

    let help =
        Paragraph::new(help_text).block(Block::default().borders(Borders::ALL).title("Help"));

    f.render_widget(help, chunks[0]);
}
