//! AWS Secrets create form rendering

use super::super::super::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};

/// Render the AWS Secrets create view
pub fn render_aws_secrets_create(f: &mut Frame, app: &mut App, area: Rect) {
    // Split area into form fields and help
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(area);

    // Create the name input widget
    let name_input = Paragraph::new(app.state.aws.new_secret_name.clone())
        .block(Block::default().title("Secret Name").borders(Borders::ALL))
        .style(
            Style::default().fg(if app.state.aws.create_field_index == 0 {
                Color::Yellow
            } else {
                Color::White
            }),
        );

    // Create the value input widget
    let value_input = Paragraph::new(app.state.aws.new_secret_value.clone())
        .block(Block::default().title("Secret Value").borders(Borders::ALL))
        .style(
            Style::default().fg(if app.state.aws.create_field_index == 1 {
                Color::Yellow
            } else {
                Color::White
            }),
        );

    // Create the description input widget
    let description_input = Paragraph::new(app.state.aws.new_secret_description.clone())
        .block(
            Block::default()
                .title("Description (Optional)")
                .borders(Borders::ALL),
        )
        .style(
            Style::default().fg(if app.state.aws.create_field_index == 2 {
                Color::Yellow
            } else {
                Color::White
            }),
        );

    // Render the form inputs
    f.render_widget(name_input, chunks[0]);
    f.render_widget(value_input, chunks[1]);
    f.render_widget(description_input, chunks[2]);

    // Render help text
    super::help_text::render_aws_create_help_text(f, chunks[4]);
}
