use crate::tui::app::App;
use crate::tui::types::{AppMode, InputField};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

pub fn render_settings_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    // New passphrase input
    let new_pass_style = match app.mode {
        AppMode::Input(InputField::NewPassphrase) => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    };

    // Use asterisks to mask the passphrase
    let masked_new_pass = "*".repeat(app.state.new_passphrase.len());
    let new_pass_input = Paragraph::new(masked_new_pass).style(new_pass_style).block(
        Block::default()
            .borders(Borders::ALL)
            .title("New Passphrase"),
    );
    f.render_widget(new_pass_input, chunks[0]);

    // Confirm passphrase input
    let confirm_pass_style = match app.mode {
        AppMode::Input(InputField::ConfirmPassphrase) => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    };

    // Use asterisks to mask the passphrase
    let masked_confirm_pass = "*".repeat(app.state.confirm_passphrase.len());
    let confirm_pass_input = Paragraph::new(masked_confirm_pass)
        .style(confirm_pass_style)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Confirm Passphrase"),
        );
    f.render_widget(confirm_pass_input, chunks[1]);

    // Security status
    let security_status = Paragraph::new(vec![
        Line::from(format!("Session timeout: {} minutes", 5)),
        Line::from(format!(
            "Argon2 memory: {} KB",
            app.state.argon2_memory_cost
        )),
        Line::from(format!("Argon2 time cost: {}", app.state.argon2_time_cost)),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Security Status"),
    );
    f.render_widget(security_status, chunks[2]);

    // Instructions
    let instructions = Paragraph::new(vec![
        Line::from("Press 'p' to edit new passphrase"),
        Line::from("Press 'c' to edit confirm passphrase"),
        Line::from("Press Enter to save (when both match)"),
        Line::from("Press 'r' to rotate encryption key"),
        Line::from(""),
        Line::from("Press 'u' to lock/unlock vault"),
        Line::from(""),
        Line::from("Passphrase Requirements:"),
        Line::from("• Minimum length: 12 characters"),
        Line::from("• Must contain uppercase and lowercase letters"),
        Line::from("• Must contain numbers"),
        Line::from("• Must contain special characters"),
        Line::from("• Should not contain easily guessable information"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Instructions"));
    f.render_widget(instructions, chunks[3]);
}
