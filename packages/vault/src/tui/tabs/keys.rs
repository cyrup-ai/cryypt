use crate::tui::app::App;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

pub fn render_keys_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // Keys list
    let items: Vec<ListItem> = app
        .state
        .vault_items
        .iter()
        .enumerate()
        .map(|(i, (key, value))| {
            let content = if let Ok(str_val) = value.expose_as_str() {
                // Truncate long values for display
                let display_val = if str_val.len() > 50 {
                    format!("{}...", &str_val[..47])
                } else {
                    str_val.to_string()
                };
                format!("{key}: {display_val}")
            } else {
                format!("{}: [complex value]", key)
            };

            let style = if i == app.state.selected_index {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![Span::styled(content, style)]))
        })
        .collect();

    let keys_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Vault Keys"))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(keys_list, chunks[0]);

    // Instructions
    let instructions = Paragraph::new(vec![
        Line::from("Up/Down - Navigate items"),
        Line::from("d - Delete selected item"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Instructions"));

    f.render_widget(instructions, chunks[1]);
}
