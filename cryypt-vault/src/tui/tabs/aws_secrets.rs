use zeroize::Zeroizing;
use crate::app::App;
use crate::types::{AppMode, AppTab, InputField, AwsSecretsStateMode};
use crate::aws_interface::{AwsSecretManager, SecretSummary, AwsError};
use ratatui::backend::Backend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

/// Renders the AWS Secrets Manager tab
pub fn render_aws_secrets_tab<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // Render the header with AWS region and profile information
    let title = format!("AWS Secrets Manager (Region: {}, Profile: {})", app.state.aws.region, app.state.aws.profile);
    let header = Paragraph::new(title)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(header, chunks[0]);

    // Render the appropriate content based on the current AWS secrets state mode
    match &app.state.aws.mode {
        AwsSecretsStateMode::List => render_aws_secrets_list(f, app, chunks[1]),
        AwsSecretsStateMode::View => render_aws_secrets_view(f, app, chunks[1]),
        AwsSecretsStateMode::Search => render_aws_secrets_search(f, app, chunks[1]),
        AwsSecretsStateMode::Create => render_aws_secrets_create(f, app, chunks[1]),
        AwsSecretsStateMode::Update => render_aws_secrets_update(f, app, chunks[1]),
    }

    // Render the status bar at the bottom
    let status_text = if app.state.aws.status_message.contains("Error") {
        Span::styled(&app.state.aws.status_message, Style::default().fg(Color::Red))
    } else if app.state.aws.status_message.contains("Connected") {
        Span::styled(&app.state.aws.status_message, Style::default().fg(Color::Green))
    } else {
        Span::styled(&app.state.aws.status_message, Style::default().fg(Color::Yellow))
    };

    let status = Paragraph::new(Line::from(vec![status_text]))
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default());
    f.render_widget(status, chunks[2]);
}

/// Render the AWS Secrets list view
fn render_aws_secrets_list<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
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
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    // Create list state with selection
    let mut list_state = ListState::default();
    list_state.select(Some(app.state.aws.selected_index.min(secrets.len().saturating_sub(1))));
    
    // Render the list widget
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    // Render help text
    render_aws_help_text(f, chunks[1]);
}

/// Render the AWS Secrets view mode
fn render_aws_secrets_view<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
    // Split area into content and help sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);
    
    // Get the current secret content
    let content = app.state.aws.current_secret.clone();
    
    // Create paragraph for the content
    let content_widget = Paragraph::new(content)
        .block(Block::default().title("Secret Content").borders(Borders::ALL))
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true });
    
    // Render the content
    f.render_widget(content_widget, chunks[0]);
    
    // Render help text
    render_aws_help_text(f, chunks[1]);
}

/// Render the AWS Secrets search view
fn render_aws_secrets_search<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
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
        .style(if let AppMode::Input(InputField::AwsSearchPattern) = app.mode {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        });
    
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
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");
    
    // Create list state with selection
    let mut list_state = ListState::default();
    list_state.select(Some(app.state.aws.selected_index.min(results.len().saturating_sub(1))));
    
    // Render the results list
    f.render_stateful_widget(results_list, chunks[1], &mut list_state);
    
    // Render help text
    render_aws_help_text(f, chunks[2]);
}

/// Render the AWS Secrets create view
fn render_aws_secrets_create<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
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
        .style(Style::default().fg(if app.state.aws.create_field_index == 0 {
            Color::Yellow
        } else {
            Color::White
        }));
    
    // Create the value input widget
    let value_input = Paragraph::new(app.state.aws.new_secret_value.clone())
        .block(Block::default().title("Secret Value").borders(Borders::ALL))
        .style(Style::default().fg(if app.state.aws.create_field_index == 1 {
            Color::Yellow
        } else {
            Color::White
        }));
    
    // Create the description input widget
    let description_input = Paragraph::new(app.state.aws.new_secret_description.clone())
        .block(Block::default().title("Description (Optional)").borders(Borders::ALL))
        .style(Style::default().fg(if app.state.aws.create_field_index == 2 {
            Color::Yellow
        } else {
            Color::White
        }));
    
    // Render the form inputs
    f.render_widget(name_input, chunks[0]);
    f.render_widget(value_input, chunks[1]);
    f.render_widget(description_input, chunks[2]);
    
    // Render help text
    render_aws_create_help_text(f, chunks[4]);
}

/// Render the AWS Secrets update view
fn render_aws_secrets_update<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
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
    let info = Paragraph::new(format!("Updating secret: {}", current_secret))
        .block(Block::default().title("Secret Info").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));
    
    // Create the value input widget
    let value_input = Paragraph::new(app.state.aws.update_secret_value.clone())
        .block(Block::default().title("New Secret Value").borders(Borders::ALL))
        .style(Style::default().fg(Color::Yellow));
    
    // Render the info and input
    f.render_widget(info, chunks[0]);
    f.render_widget(value_input, chunks[1]);
    
    // Render help text
    render_aws_update_help_text(f, chunks[3]);
}

/// Render standard AWS help text
fn render_aws_help_text<B: Backend>(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Span::raw("↑/↓: Navigate | "),
        Span::raw("p: Set profile | "),
        Span::raw("r: Set region | "),
        Span::raw("s: Search | "),
        Span::raw("c: Connect | "),
        Span::raw("Enter: View | "),
        Span::raw("n: New | "),
        Span::raw("u: Update | "),
        Span::raw("Esc: Back")
    ];
    
    let help = Paragraph::new(Line::from(help_text))
        .block(Block::default().title("Help").borders(Borders::ALL))
        .style(Style::default().fg(Color::Blue));
    
    f.render_widget(help, area);
}

/// Render AWS create mode help text
fn render_aws_create_help_text<B: Backend>(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Span::raw("Tab: Next field | "),
        Span::raw("Enter: Submit | "),
        Span::raw("Esc: Cancel")
    ];
    
    let help = Paragraph::new(Line::from(help_text))
        .block(Block::default().title("Help").borders(Borders::ALL))
        .style(Style::default().fg(Color::Blue));
    
    f.render_widget(help, area);
}

/// Render AWS update mode help text
fn render_aws_update_help_text<B: Backend>(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Span::raw("Enter: Submit | "),
        Span::raw("Esc: Cancel")
    ];
    
    let help = Paragraph::new(Line::from(help_text))
        .block(Block::default().title("Help").borders(Borders::ALL))
        .style(Style::default().fg(Color::Blue));
    
    f.render_widget(help, area);
}
