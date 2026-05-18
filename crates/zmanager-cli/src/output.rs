use std::fmt::{self, Write as _};
use std::io::{self, Write as _};

use anstream::{AutoStream, ColorChoice};
use anstyle::{AnsiColor, Effects, Style};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub(crate) enum OutputMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum StyleRole {
    Heading,
    Command,
    Option,
    Placeholder,
    Success,
    Warning,
    Error,
    Progress,
    Label,
    Path,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Styled<'a> {
    role: StyleRole,
    value: fmt::Arguments<'a>,
}

impl OutputMode {
    #[must_use]
    fn color_choice(self) -> ColorChoice {
        match self {
            Self::Auto => ColorChoice::Auto,
            Self::Always => ColorChoice::Always,
            Self::Never => ColorChoice::Never,
        }
    }
}

impl fmt::Display for Styled<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let style = style_for(self.role);
        write!(
            formatter,
            "{}{}{}",
            style.render(),
            self.value,
            style.render_reset()
        )
    }
}

#[must_use]
pub(crate) fn styled(role: StyleRole, value: fmt::Arguments<'_>) -> Styled<'_> {
    Styled { role, value }
}

pub(crate) fn stdout_write(mode: OutputMode, value: fmt::Arguments<'_>) {
    let mut stream = AutoStream::new(io::stdout(), mode.color_choice());
    let _ = write!(stream, "{value}");
}

pub(crate) fn stdout_line(mode: OutputMode, value: fmt::Arguments<'_>) {
    let mut stream = AutoStream::new(io::stdout(), mode.color_choice());
    let _ = writeln!(stream, "{value}");
}

pub(crate) fn stderr_write(mode: OutputMode, value: fmt::Arguments<'_>) {
    let mut stream = AutoStream::new(io::stderr(), mode.color_choice());
    let _ = write!(stream, "{value}");
}

pub(crate) fn stderr_line(mode: OutputMode, value: fmt::Arguments<'_>) {
    let mut stream = AutoStream::new(io::stderr(), mode.color_choice());
    let _ = writeln!(stream, "{value}");
}

#[must_use]
pub(crate) fn render_help(help: &str) -> String {
    let mut rendered = String::with_capacity(help.len() + help.len() / 8);
    let mut section = HelpSection::Other;

    for (index, raw_line) in help.split_inclusive('\n').enumerate() {
        let (line, newline) = raw_line
            .strip_suffix('\n')
            .map_or((raw_line, ""), |line| (line, "\n"));
        push_help_line(&mut rendered, line, index, &mut section);
        rendered.push_str(newline);
    }

    rendered
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HelpSection {
    Commands,
    Other,
}

fn push_help_line(rendered: &mut String, line: &str, index: usize, section: &mut HelpSection) {
    if line.trim().is_empty() {
        rendered.push_str(line);
        return;
    }

    if index == 0 || is_help_heading(line) {
        *section = if line == "Commands:" {
            HelpSection::Commands
        } else {
            HelpSection::Other
        };
        push_styled(rendered, StyleRole::Heading, line);
        return;
    }

    if *section == HelpSection::Commands && line.starts_with("  ") {
        push_command_line(rendered, line);
        return;
    }

    push_styled_tokens(rendered, line);
}

fn is_help_heading(line: &str) -> bool {
    !line.starts_with(' ') && line.ends_with(':')
}

fn push_command_line(rendered: &mut String, line: &str) {
    let command_start = line
        .find(|ch: char| !ch.is_whitespace())
        .unwrap_or(line.len());
    let command_end = line[command_start..]
        .find(char::is_whitespace)
        .map_or(line.len(), |offset| command_start + offset);

    rendered.push_str(&line[..command_start]);
    push_styled(
        rendered,
        StyleRole::Command,
        &line[command_start..command_end],
    );
    push_styled_tokens(rendered, &line[command_end..]);
}

fn push_styled_tokens(rendered: &mut String, line: &str) {
    let mut index = 0usize;
    while index < line.len() {
        let Some(token_start_offset) = line[index..]
            .char_indices()
            .find_map(|(offset, ch)| (!ch.is_whitespace()).then_some(offset))
        else {
            rendered.push_str(&line[index..]);
            break;
        };

        let token_start = index + token_start_offset;
        rendered.push_str(&line[index..token_start]);

        let token_end = line[token_start..]
            .char_indices()
            .find_map(|(offset, ch)| ch.is_whitespace().then_some(token_start + offset))
            .unwrap_or(line.len());
        let token = &line[token_start..token_end];
        push_styled_token(rendered, token);
        index = token_end;
    }
}

fn push_styled_token(rendered: &mut String, token: &str) {
    let trimmed = token.trim_matches(|ch: char| matches!(ch, ',' | '.' | ';' | ':'));
    if trimmed.starts_with('-') && trimmed != "-" {
        push_styled(rendered, StyleRole::Option, token);
    } else if trimmed.starts_with('<') && trimmed.ends_with('>') {
        push_styled(rendered, StyleRole::Placeholder, token);
    } else {
        rendered.push_str(token);
    }
}

fn push_styled(rendered: &mut String, role: StyleRole, value: &str) {
    let style = style_for(role);
    let _ = write!(
        rendered,
        "{}{}{}",
        style.render(),
        value,
        style.render_reset()
    );
}

fn style_for(role: StyleRole) -> Style {
    match role {
        StyleRole::Heading => AnsiColor::Cyan.on_default().effects(Effects::BOLD),
        StyleRole::Command | StyleRole::Success => {
            AnsiColor::Green.on_default().effects(Effects::BOLD)
        }
        StyleRole::Option => AnsiColor::Yellow.on_default(),
        StyleRole::Placeholder => AnsiColor::Magenta.on_default(),
        StyleRole::Warning => AnsiColor::Yellow.on_default().effects(Effects::BOLD),
        StyleRole::Error => AnsiColor::Red.on_default().effects(Effects::BOLD),
        StyleRole::Progress | StyleRole::Label => AnsiColor::Cyan.on_default(),
        StyleRole::Path => AnsiColor::Blue.on_default(),
    }
}
