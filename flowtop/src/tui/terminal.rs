use std::io::{self, Stdout};

use anyhow::{Context, Result};
use crossterm::{
    cursor::Show,
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

pub type FlowtopTerminal = Terminal<CrosstermBackend<Stdout>>;

pub struct TerminalSession {
    terminal: FlowtopTerminal,
}

impl TerminalSession {
    pub fn enter() -> Result<Self> {
        install_recovery_panic_hook();
        enable_raw_mode().context("enable terminal raw mode")?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error).context("enter alternate screen");
        }
        let terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
                return Err(error).context("create terminal");
            }
        };
        Ok(Self { terminal })
    }

    pub fn terminal_mut(&mut self) -> &mut FlowtopTerminal {
        &mut self.terminal
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen, Show);
        let _ = self.terminal.show_cursor();
    }
}

fn install_recovery_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
        previous(info);
    }));
}
