//! Main event loop for TUI

use super::super::app::App;
use super::super::types::AppMode;
use super::super::ui::ui;
use super::input_mode::handle_input_mode_key;
use super::normal_mode::handle_normal_mode_key;
use crate::logging::log_security_event;
use crossterm::event::{self, Event, KeyEventKind};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;
use std::time::Duration;

pub async fn run_event_loop(
    mut terminal: Terminal<CrosstermBackend<io::Stdout>>,
    mut app: App,
) -> Result<(), Box<dyn std::error::Error>> {
    let tick_rate = Duration::from_millis(250);
    let mut last_tick = std::time::Instant::now();

    // Main loop
    loop {
        terminal.draw(|f| ui::<CrosstermBackend<std::io::Stdout>>(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        // Check for session timeout
        let timeout_duration = Duration::from_secs(300); // 5 minutes
        if !app.state.is_vault_locked && app.state.last_activity.elapsed() > timeout_duration {
            app.lock().await.ok();
            app.state.error_message = Some("Session timed out due to inactivity".to_string());
            log_security_event(
                "SESSION_TIMEOUT",
                "Session timed out due to inactivity",
                true,
            );
        }

        if crossterm::event::poll(timeout)? {
            // Update last activity timestamp on any event
            app.state.last_activity = std::time::Instant::now();
            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                let should_exit = match app.mode.clone() {
                    AppMode::Normal => {
                        handle_normal_mode_key(&mut app, key.code, key.modifiers).await
                    }
                    AppMode::Input(field) => {
                        handle_input_mode_key(&mut app, &field, key.code, key.modifiers).await
                    }
                };

                if should_exit {
                    break;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();

            // Clear messages after some time
            app.state.success_message = None;
        }
    }

    Ok(())
}
