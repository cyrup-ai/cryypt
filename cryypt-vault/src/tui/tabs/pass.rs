use ratatui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use super::super::app::App;
use super::super::types::{AppMode, InputField};

pub fn render_pass_tab<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Store path input
            Constraint::Min(0),     // List/content area
            Constraint::Length(3),  // Help text
        ])
        .split(area);

    // Pass store path input
    let pass_store_path_input = Paragraph::new(app.state.pass_store_path.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Password Store Path")
                .style(match app.mode {

    f.render_widget(title, chunks[0]);

    match app.state.pass.mode {
        PassState::List => render_pass_list(f, app, chunks[1]),
        PassState::View => render_pass_view(f, app, chunks[1]),
        PassState::Search => render_pass_search(f, app, chunks[1]),
    }
}

fn render_pass_list<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
    let passwords = app.state.pass.passwords.clone();
    let list_items: Vec<ListItem> = passwords
        .iter()
        .map(|p| ListItem::new(Span::raw(p.clone())))
        .collect();

    let list = List::new(list_items)
        .block(Block::default().title("Passwords").borders(Borders::ALL))
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

    let mut list_state = ListState::default();
    list_state.select(app.state.pass.selected_index);

    f.render_stateful_widget(list, area, &mut list_state);
}

fn render_pass_view<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
    let selected = app.state.pass.selected_index;
    let password_name = if selected < app.state.pass.passwords.len() {
        app.state.pass.passwords[selected].clone()
    } else {
        String::new()
    };

    let content = app.state.pass.current_password.clone();
    let lines = vec![
        Line::from(Span::styled(
            format!("Password: {}", password_name),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::raw(content)),
    ];

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Password Details").borders(Borders::ALL))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

fn render_pass_search<B: Backend>(f: &mut Frame, app: &mut App, area: Rect) {
    let input = app.state.pass.search_query.clone();

    let text = vec![
        Line::from(Span::styled(
            "Search for passwords:",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::raw(input)),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

/// Load passwords from the Pass store
pub async fn load_passwords(app: &mut App) {
    let pass = PassInterface::default();
    
    match pass.get_all_entries() {
        Ok(entries) => {
            app.state.pass.passwords = entries;
            if !app.state.pass.passwords.is_empty() && app.state.pass.selected_index == 0 {
                app.state.pass.selected_index = 0;
            }
        }
        Err(e) => {
            app.state.pass.status_message = format!("Error loading passwords: {}", e);
        }
    }
}

/// Load a password content
pub async fn load_password_content(app: &mut App) {
    if app.state.pass.selected_index >= app.state.pass.passwords.len() {
        return;
    }
    
    let password_name = app.state.pass.passwords[app.state.pass.selected_index].clone();
    let pass = PassInterface::default();
    
    match pass.get_password(&password_name) {
        Ok(content) => {
            app.state.pass.current_password = content.to_string();
        }
        Err(e) => {
            app.state.pass.status_message = format!("Error loading password: {}", e);
        }
    }
}

/// Search for passwords
pub async fn search_passwords(app: &mut App) {
    let query = app.state.pass.search_query.clone();
    let pass = PassInterface::default();
    
    match pass.search_entries(&query) {
        Ok(entries) => {
            app.state.pass.passwords = entries;
            app.state.pass.selected_index = 0;
            app.state.pass.mode = PassState::List;
        }
        Err(e) => {
            app.state.pass.status_message = format!("Error searching passwords: {}", e);
        }
    }
}

/// Process keyboard input for the Pass tab
pub async fn handle_input(app: &mut App, key: crossterm::event::KeyEvent) {
    match app.state.pass.mode {
        PassState::List => {
            match key.code {
                crossterm::event::KeyCode::Down => {
                    if !app.state.pass.passwords.is_empty() {
                        app.state.pass.selected_index = (app.state.pass.selected_index + 1) % app.state.pass.passwords.len();
                    }
                }
                crossterm::event::KeyCode::Up => {
                    if !app.state.pass.passwords.is_empty() {
                        app.state.pass.selected_index = app.state.pass.selected_index.checked_sub(1)
                            .unwrap_or(app.state.pass.passwords.len() - 1);
                    }
                }
                crossterm::event::KeyCode::Enter => {
                    if !app.state.pass.passwords.is_empty() {
                        app.state.pass.mode = PassState::View;
                        load_password_content(app).await;
                    }
                }
                crossterm::event::KeyCode::Char('/') => {
                    app.state.pass.mode = PassState::Search;
                    app.state.pass.search_query.clear();
                }
                _ => {}
            }
        }
        PassState::View => {
            match key.code {
                crossterm::event::KeyCode::Esc => {
                    app.state.pass.mode = PassState::List;
                    app.state.pass.current_password.clear();
                }
                _ => {}
            }
        }
        PassState::Search => {
            match key.code {
                crossterm::event::KeyCode::Enter => {
                    search_passwords(app).await;
                }
                crossterm::event::KeyCode::Esc => {
                    app.state.pass.mode = PassState::List;
                    app.state.pass.search_query.clear();
                }
                crossterm::event::KeyCode::Char(c) => {
                    app.state.pass.search_query.push(c);
                }
                crossterm::event::KeyCode::Backspace => {
                    app.state.pass.search_query.pop();
                }
                _ => {}
            }
        }
    }
}
