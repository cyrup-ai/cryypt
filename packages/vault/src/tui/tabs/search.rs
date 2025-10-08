use crate::tui::app::App;
use crate::tui::types::{AppMode, InputField};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

pub fn render_search_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Search input
    let input_style = match &app.mode {
        AppMode::Input(InputField::Search) => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    };
    // Use a String to avoid type inference issues
    let search_input = Paragraph::new(app.state.search_pattern.as_str())
        .style(input_style)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Search Pattern (regex)"),
        );

    f.render_widget(search_input, chunks[0]);

    // Search results
    let items: Vec<ListItem> = app
        .state
        .search_results
        .iter()
        .enumerate()
        .map(|(i, (key, value))| {
            let content = if let Ok(str_val) = value.expose_as_str() {
                format!("{key}: {str_val}")
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

    let search_list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Search Results"),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(search_list, chunks[1]);
}
