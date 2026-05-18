# Completion UX Plan

This plan records the 1.0.1 completion polish scope. It keeps navigation
predictable for archive commands while adding Windows PowerShell parity.

## Current Scope

- Keep help navigation canonical:
  - `zm --help`
  - `zm help <TAB>`
  - `zm help list`
  - `zm list --help`
  - `zm list --<TAB>`
- Keep positional archive commands file-oriented. Plain Tab after
  `zm list `, `zm extract `, or `zm test ` should complete files, because the
  next argument is an archive path.
- Complete help topics only after `zm help `. The topic list should include
  public command topics such as `create`, `extract`, `list`, `test`, `plan`,
  `formats`, `doctor`, and `completions`.
- Complete command flags only after a command plus a dash prefix, for example
  `zm list --<TAB>` and `zm create --<TAB>`.
- Complete completion script shells after `zm completions <TAB>`.
- Add a PowerShell completion script with the same static behavior as bash,
  zsh, and fish.
- On Windows PowerShell 5.1, native argument completers are not invoked for a
  bare `-` or `--`. PowerShell users should type the first option character,
  for example `zm list --t<TAB>` for `--tree`.

## Deferred Scope

- Do not add a hidden dynamic completion command in 1.0.1.
- Do not add Cobra/Helm-style Active Help in 1.0.1.
- Do not add `cmd.exe` completion beyond normal executable and path behavior.
- Do not mutate user shell profile files automatically.

## Test Expectations

- Bash completion behavior should be executable-tested when bash is present.
- Static completion files should be checked for public command coverage,
  hidden legacy command coverage, command-specific options, shell values, and
  package inclusion.
- PowerShell coverage should verify the script registers an argument completer,
  carries the same candidate sets, and is packaged with Windows release
  archives.
