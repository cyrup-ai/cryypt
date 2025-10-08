//! Main AWS Secrets tab rendering and layout coordination

use super::super::super::app::App;
use super::super::super::types::AwsSecretsStateMode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

/// Renders the AWS Secrets Manager tab
pub fn render_aws_secrets_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(area);

    // Render the header with AWS region and profile information
    let title = format!(
        "AWS Secrets Manager (Region: {}, Profile: {})",
        app.state.aws.region, app.state.aws.profile
    );
    let header = Paragraph::new(title)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(header, chunks[0]);

    // Render the appropriate content based on the current AWS secrets state mode
    match &app.state.aws.mode {
        AwsSecretsStateMode::List => super::list_view::render_aws_secrets_list(f, app, chunks[1]),
        AwsSecretsStateMode::View => super::view_mode::render_aws_secrets_view(f, app, chunks[1]),
        AwsSecretsStateMode::Search => super::search::render_aws_secrets_search(f, app, chunks[1]),
        AwsSecretsStateMode::Create => {
            super::create_form::render_aws_secrets_create(f, app, chunks[1])
        }
        AwsSecretsStateMode::Update => {
            super::update_form::render_aws_secrets_update(f, app, chunks[1])
        }
    }

    // Render the status bar at the bottom
    let status_text = if app.state.aws.status_message.contains("Error") {
        Span::styled(
            &app.state.aws.status_message,
            Style::default().fg(Color::Red),
        )
    } else if app.state.aws.status_message.contains("Connected") {
        Span::styled(
            &app.state.aws.status_message,
            Style::default().fg(Color::Green),
        )
    } else {
        Span::styled(
            &app.state.aws.status_message,
            Style::default().fg(Color::Yellow),
        )
    };

    let status = Paragraph::new(Line::from(vec![status_text]))
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default());
    f.render_widget(status, chunks[2]);
}
