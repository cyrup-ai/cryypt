//! AWS Secrets update form rendering

use super::super::super::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};

/// Render the AWS Secrets update view
pub fn render_aws_secrets_update(f: &mut Frame, app: &mut App, area: Rect) {
    // Split area into info, value input, and help
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(area);

    // Get the current secret name
    let current_secret = app.state.aws.current_secret.clone();

    // Create the info widget
    let info = Paragraph::new(format!("Updating secret: {current_secret}"))
        .block(Block::default().title("Secret Info").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    // Create the value input widget
    let value_input = Paragraph::new(app.state.aws.update_secret_value.clone())
        .block(
            Block::default()
                .title("New Secret Value")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::Yellow));

    // Render the info and input
    f.render_widget(info, chunks[0]);
    f.render_widget(value_input, chunks[1]);

    // Render help text
    super::help_text::render_aws_update_help_text(f, chunks[3]);
}
