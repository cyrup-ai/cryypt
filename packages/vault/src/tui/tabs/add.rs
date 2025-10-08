use crate::tui::app::App;
use crate::tui::types::{AppMode, InputField};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

pub fn render_add_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    // Key input
    let key_style = match app.mode {
        AppMode::Input(InputField::NewKey) => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    };
    // Create a temporary String to help with type inference
    let key_input = Paragraph::new(app.state.new_key.as_str())
        .style(key_style)
        .block(Block::default().borders(Borders::ALL).title("Key"));
    f.render_widget(key_input, chunks[0]);

    // Value input
    let value_style = match app.mode {
        AppMode::Input(InputField::NewValue) => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    };
    // Create a temporary String to help with type inference
    let value_input = Paragraph::new(app.state.new_value.as_str())
        .style(value_style)
        .block(Block::default().borders(Borders::ALL).title("Value"));
    f.render_widget(value_input, chunks[1]);

    // Instructions
    let instructions = Paragraph::new(vec![
        Line::from("Press 'k' to edit key"),
        Line::from("Press 'v' to edit value"),
        Line::from("Press 'a' to add entry"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Instructions"));
    f.render_widget(instructions, chunks[2]);
}
