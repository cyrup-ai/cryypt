//! AWS Secrets view mode rendering

use super::super::super::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

/// Render the AWS Secrets view mode
pub fn render_aws_secrets_view(f: &mut Frame, app: &mut App, area: Rect) {
    // Split area into content and help sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    // Get the current secret content
    let content = app.state.aws.current_secret.clone();

    // Create paragraph for the content
    let content_widget = Paragraph::new(content)
        .block(
            Block::default()
                .title("Secret Content")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true });

    // Render the content
    f.render_widget(content_widget, chunks[0]);

    // Render help text
    super::help_text::render_aws_help_text(f, chunks[1]);
}
