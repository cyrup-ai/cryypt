use super::app::App;
use super::tabs::*;
use super::types::AppTab;
use ratatui::{
    Frame,
    backend::Backend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
};

pub fn ui<B: Backend>(f: &mut Frame, app: &mut App) {
    // Create layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(3), // Status/Messages
        ])
        .split(f.area());

    // Render tabs
    let tabs: Vec<Line> = [
        AppTab::Keys,
        AppTab::Search,
        AppTab::Add,
        AppTab::Settings,
        AppTab::Pass,
        AppTab::AwsSecrets,
        AppTab::Help,
    ]
    .iter()
    .map(|t| {
        let tab_str = t.to_string();
        match app.active_tab {
            current if &current == t => Line::from(vec![Span::styled(
                tab_str,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )]),
            _ => Line::from(vec![Span::raw(tab_str)]),
        }
    })
    .collect();

    let tabs = Tabs::new(tabs)
        .block(Block::default().borders(Borders::ALL).title("Tabs"))
        .select(app.active_tab as usize)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Yellow));

    f.render_widget(tabs, chunks[0]);

    // Render main content based on active tab
    match app.active_tab {
        AppTab::Keys => render_keys_tab(f, app, chunks[1]),
        AppTab::Search => render_search_tab(f, app, chunks[1]),
        AppTab::Add => render_add_tab(f, app, chunks[1]),
        AppTab::Settings => render_settings_tab(f, app, chunks[1]),
        AppTab::Pass => render_pass_tab(f, app, chunks[1]),
        AppTab::AwsSecrets => render_aws_secrets_tab(f, app, chunks[1]),
        AppTab::Help => render_help_tab(f, app, chunks[1]),
    }

    // Render status/messages
    let mut status_text = vec![];

    if let Some(ref error) = app.state.error_message {
        status_text.push(Line::from(vec![
            Span::styled("Error: ", Style::default().fg(Color::Red)),
            Span::raw(error),
        ]));
    } else if let Some(ref success) = app.state.success_message {
        status_text.push(Line::from(vec![
            Span::styled("Success: ", Style::default().fg(Color::Green)),
            Span::raw(success),
        ]));
    }

    let lock_status = if app.state.is_vault_locked {
        Line::from(vec![Span::styled(
            "Vault: Locked",
            Style::default().fg(Color::Red),
        )])
    } else {
        Line::from(vec![Span::styled(
            "Vault: Unlocked",
            Style::default().fg(Color::Green),
        )])
    };

    if status_text.is_empty() {
        status_text.push(lock_status);
    } else {
        status_text.push(Line::from(vec![Span::raw("")]));
        status_text.push(lock_status);
    }

    let status =
        Paragraph::new(status_text).block(Block::default().borders(Borders::ALL).title("Status"));

    f.render_widget(status, chunks[2]);
}
