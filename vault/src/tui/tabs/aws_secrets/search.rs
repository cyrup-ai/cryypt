//! AWS Secrets search functionality

use super::super::super::app::App;
use super::super::super::types::{AppMode, InputField};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

/// Render the AWS Secrets search view
pub fn render_aws_secrets_search(f: &mut Frame, app: &mut App, area: Rect) {
    // Split area into search input, results, and help sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);

    // Create the search input widget
    let search_input = Paragraph::new(app.state.aws.search_query.clone())
        .block(Block::default().title("Search").borders(Borders::ALL))
        .style(
            if let AppMode::Input(InputField::AwsSearchPattern) = app.mode {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            },
        );

    // Render the search input
    f.render_widget(search_input, chunks[0]);

    // Create list items from search results
    let results = &app.state.aws.search_results;
    let list_items: Vec<ListItem> = results
        .iter()
        .map(|s| ListItem::new(Span::raw(s.name.clone())))
        .collect();

    // Create the search results list
    let results_list = List::new(list_items)
        .block(Block::default().title("Results").borders(Borders::ALL))
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
            .min(results.len().saturating_sub(1)),
    ));

    // Render the results list
    f.render_stateful_widget(results_list, chunks[1], &mut list_state);

    // Render help text
    super::help_text::render_aws_help_text(f, chunks[2]);
}
