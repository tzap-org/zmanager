# bash completion for zm

_zm()
{
    local cur prev words cword command
    words=("${COMP_WORDS[@]}")
    cword=$COMP_CWORD
    cur="${words[cword]}"
    if (( cword > 0 )); then
        prev="${words[cword - 1]}"
    else
        prev=""
    fi

    local commands="create extract list test plan formats doctor completions help"
    local help_topics="create extract list test plan formats doctor completions"
    local global_opts="-h --help -V --version -q --quiet -v --verbose --json --color --no-color --progress --no-progress --no-password-prompt -c --create -x --extract -t --list -T --test -f --file"
    local create_opts="-h --help -r --recursive -C --directory -@ --files-from --null --clean --no-ignore --hidden --no-hidden -i --include --exclude --exclude-from --format --method --level -0 -1 -2 -3 -4 -5 -6 -7 -8 -9 --store --solid --no-solid -j --junk-paths -y --preserve-symlinks --follow-symlinks --preserve-metadata -X --no-metadata -f --file --force --dry-run -T --test-after --encrypt --password-stdin"
    local extract_opts="-h --help -C -d --directory --here --overwrite -i --include --exclude --strip-components --to-stdout --extract-nested --password-stdin"
    local list_opts="-h --help -f --file -l --long --name-only --tree -i --include --exclude --password-stdin --json"
    local test_opts="-h --help -f --file -i --include --exclude --password-stdin --json"
    local plan_opts="-h --help --format -C --directory -@ --files-from --null --clean --no-ignore -i --include --exclude --exclude-from --json"
    local format_values="zip tar.zst 7z"
    local progress_values="auto always never"
    local color_values="auto always never"
    local overwrite_values="never always ask rename"
    local shell_values="bash zsh fish powershell"

    command=""
    for word in "${words[@]:1:cword-1}"; do
        case "$word" in
            create|extract|list|test|plan|formats|doctor|completions|help)
                command="$word"
                break
                ;;
        esac
    done

    case "$prev" in
        --color)
            COMPREPLY=($(compgen -W "$color_values" -- "$cur"))
            return
            ;;
        --progress)
            COMPREPLY=($(compgen -W "$progress_values" -- "$cur"))
            return
            ;;
        --format)
            COMPREPLY=($(compgen -W "$format_values" -- "$cur"))
            return
            ;;
        --overwrite)
            COMPREPLY=($(compgen -W "$overwrite_values" -- "$cur"))
            return
            ;;
        completions)
            COMPREPLY=($(compgen -W "$shell_values" -- "$cur"))
            return
            ;;
        -C|-d|--directory|--files-from|--exclude-from)
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
        -f|--file)
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        case "$command" in
            create) COMPREPLY=($(compgen -W "$create_opts" -- "$cur")) ;;
            extract) COMPREPLY=($(compgen -W "$extract_opts" -- "$cur")) ;;
            list) COMPREPLY=($(compgen -W "$list_opts" -- "$cur")) ;;
            test) COMPREPLY=($(compgen -W "$test_opts" -- "$cur")) ;;
            plan) COMPREPLY=($(compgen -W "$plan_opts" -- "$cur")) ;;
            formats|doctor) COMPREPLY=($(compgen -W "-h --help --json" -- "$cur")) ;;
            completions) COMPREPLY=($(compgen -W "-h --help" -- "$cur")) ;;
            *) COMPREPLY=($(compgen -W "$global_opts" -- "$cur")) ;;
        esac
        return
    fi

    case "$command" in
        "")
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            ;;
        help)
            COMPREPLY=($(compgen -W "$help_topics" -- "$cur"))
            ;;
        completions)
            COMPREPLY=($(compgen -W "$shell_values" -- "$cur"))
            ;;
        *)
            COMPREPLY=($(compgen -f -- "$cur"))
            ;;
    esac
}

complete -F _zm zm
