//! AWS Secrets list view rendering

use super::super::super::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

/// Render the AWS Secrets list view
pub fn render_aws_secrets_list(f: &mut Frame, app: &mut App, area: Rect) {
    // Split into two sections: secrets list and help
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    // Create list items from secrets
    let secrets = &app.state.aws.secrets;
    let list_items: Vec<ListItem> = secrets
        .iter()
        .map(|s| ListItem::new(Span::raw(s.name.clone())))
        .collect();

    // Create the list widget
    let list = List::new(list_items)
        .block(Block::default().title("Secrets").borders(Borders::ALL))
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    // Create list state with selection
    let mut list_state = ListState::default();
    list_state.select(Some(
        app.state
            .aws
            .selected_index
            .min(secrets.len().saturating_sub(1)),
    ));

    // Render the list widget
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    // Render help text
    super::help_text::render_aws_help_text(f, chunks[1]);
}
