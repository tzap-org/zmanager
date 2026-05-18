# Shell Completions

These files are maintained with the public `zm` command surface in
`crates/zmanager-cli/src/app.rs`.

Keep legacy development commands out of these files. Public release packages
include this directory so users can install completions for their shell.

The CLI also embeds these files for
`zm completions <bash|zsh|fish|powershell>`. Keep the embedded command output
and packaged files identical by updating this directory first.

Completion behavior should keep `zm help <TAB>` focused on command help topics,
`zm <command> --<TAB>` focused on command options, and plain positional
archive/path arguments focused on filesystem completion.
