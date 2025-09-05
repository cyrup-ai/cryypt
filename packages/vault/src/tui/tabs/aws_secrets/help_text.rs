//! AWS Secrets help text rendering functions

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

/// Render standard AWS help text
pub fn render_aws_help_text(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Span::raw("↑/↓: Navigate | "),
        Span::raw("p: Set profile | "),
        Span::raw("r: Set region | "),
        Span::raw("s: Search | "),
        Span::raw("c: Connect | "),
        Span::raw("Enter: View | "),
        Span::raw("n: New | "),
        Span::raw("u: Update | "),
        Span::raw("Esc: Back"),
    ];

    let help = Paragraph::new(Line::from(help_text))
        .block(Block::default().title("Help").borders(Borders::ALL))
        .style(Style::default().fg(Color::Blue));

    f.render_widget(help, area);
}

/// Render AWS create mode help text
pub fn render_aws_create_help_text(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Span::raw("Tab: Next field | "),
        Span::raw("Enter: Submit | "),
        Span::raw("Esc: Cancel"),
    ];

    let help = Paragraph::new(Line::from(help_text))
        .block(Block::default().title("Help").borders(Borders::ALL))
        .style(Style::default().fg(Color::Blue));

    f.render_widget(help, area);
}

/// Render AWS update mode help text
pub fn render_aws_update_help_text(f: &mut Frame, area: Rect) {
    let help_text = vec![Span::raw("Enter: Submit | "), Span::raw("Esc: Cancel")];

    let help = Paragraph::new(Line::from(help_text))
        .block(Block::default().title("Help").borders(Borders::ALL))
        .style(Style::default().fg(Color::Blue));

    f.render_widget(help, area);
}
