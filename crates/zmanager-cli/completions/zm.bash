# bash completion for zm

_zm()
{
    local cur prev words cword command subcommand
    words=("${COMP_WORDS[@]}")
    cword=$COMP_CWORD
    cur="${words[cword]}"
    if (( cword > 0 )); then
        prev="${words[cword - 1]}"
    else
        prev=""
    fi

    local commands="create extract list test plan formats auth me cert device sign verify contact share doctor completions help"
    local help_topics="create extract list test plan formats auth me cert device sign verify contact share doctor completions"
    local auth_commands="login callback status forget account"
    local cert_commands="list enroll renew revoke"
    local device_commands="retire"
    local contact_commands="export import list remove"
    local global_opts="-h --help -V --version -q --quiet -v --verbose --json --color --no-color --progress --no-progress --no-password-prompt -c --create -x --extract -t --list -T --test -f --file"
    local create_opts="-h --help -r --recursive -C --directory -@ --files-from --null --clean --no-ignore --hidden --no-hidden -i --include --exclude --exclude-from --format --method --level -0 -1 -2 -3 -4 -5 -6 -7 -8 -9 --store --solid --no-solid --volume-size --recipient-cert --signing-cert --signing-private-key --signing-chain -j --junk-paths -y --preserve-symlinks --follow-symlinks --preserve-metadata -X --no-metadata -f --file --force --dry-run -T --test-after --encrypt --password-stdin"
    local extract_opts="-h --help -C -d --directory --here --overwrite -i --include --exclude --strip-components --to-stdout --extract-nested --password-stdin --recipient-key"
    local list_opts="-h --help -f --file -l --long --name-only --tree -i --include --exclude --password-stdin --recipient-key --json"
    local test_opts="-h --help -f --file -i --include --exclude --password-stdin --recipient-key --public-no-key --trusted-ca-cert --trusted-system-roots --json"
    local plan_opts="-h --help --format -C --directory -@ --files-from --null --clean --no-ignore -i --include --exclude --exclude-from --json"
    local auth_opts="-h --help --print-url --state-dir --account-key --environment --auth-base-url --account-base-url --client-id --redirect-uri --provider --org-id --state --callback-url --handoff-code --relay-body --json"
    local identity_opts="-h --help --state-dir --account-key --json"
    local cert_opts="$identity_opts --certificate-id --service-base-url --trusted-root-cert --org-id --requested-validity-seconds"
    local sign_opts="$identity_opts --certificate-id --output --claimed-signing-time"
    local verify_opts="-h --help --custom-trust-root --custom-trust-root-cert --status-response --time --json"
    local contact_opts="$identity_opts --recipient-key-id --certificate-id --display-name --device-label --output --accept --custom-trust-root --custom-trust-root-cert"
    local share_opts="$identity_opts --contact --force"
    local format_values="zip tar.zst tzap aar 7z"
    local progress_values="auto always never"
    local color_values="auto always never"
    local overwrite_values="never always ask rename"
    local volume_size_values="64k 100m 500m 1g 2g 4g"
    local shell_values="bash zsh fish powershell"

    command=""
    subcommand=""
    for word in "${words[@]:1:cword-1}"; do
        case "$word" in
            create|extract|list|test|plan|formats|auth|me|cert|device|sign|verify|contact|share|doctor|completions|help)
                command="$word"
                break
                ;;
        esac
    done
    if [[ -n "$command" ]]; then
        local seen_command=false
        for word in "${words[@]:1:cword-1}"; do
            if [[ "$seen_command" == false ]]; then
                [[ "$word" == "$command" ]] && seen_command=true
                continue
            fi
            case "$command:$word" in
                auth:login|auth:callback|auth:status|auth:forget|auth:account|cert:list|cert:enroll|cert:renew|cert:revoke|device:retire|contact:export|contact:import|contact:list|contact:remove)
                    subcommand="$word"
                    break
                    ;;
            esac
        done
    fi

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
        --volume-size)
            COMPREPLY=($(compgen -W "$volume_size_values" -- "$cur"))
            return
            ;;
        --environment)
            COMPREPLY=($(compgen -W "local dev prod" -- "$cur"))
            return
            ;;
        completions)
            COMPREPLY=($(compgen -W "$shell_values" -- "$cur"))
            return
            ;;
        -C|-d|--directory|--files-from|--exclude-from|--recipient-cert|--signing-cert|--signing-private-key|--signing-chain|--recipient-key|--trusted-ca-cert|--relay-body|--trusted-root-cert|--output|--custom-trust-root-cert|--status-response)
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
            auth) COMPREPLY=($(compgen -W "$auth_opts" -- "$cur")) ;;
            me|device) COMPREPLY=($(compgen -W "$identity_opts" -- "$cur")) ;;
            cert) COMPREPLY=($(compgen -W "$cert_opts" -- "$cur")) ;;
            sign) COMPREPLY=($(compgen -W "$sign_opts" -- "$cur")) ;;
            verify) COMPREPLY=($(compgen -W "$verify_opts" -- "$cur")) ;;
            contact) COMPREPLY=($(compgen -W "$contact_opts" -- "$cur")) ;;
            share) COMPREPLY=($(compgen -W "$share_opts" -- "$cur")) ;;
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
        auth)
            if [[ -z "$subcommand" ]]; then
                COMPREPLY=($(compgen -W "$auth_commands" -- "$cur"))
            else
                COMPREPLY=($(compgen -f -- "$cur"))
            fi
            ;;
        cert)
            if [[ -z "$subcommand" ]]; then
                COMPREPLY=($(compgen -W "$cert_commands" -- "$cur"))
            else
                COMPREPLY=($(compgen -f -- "$cur"))
            fi
            ;;
        device)
            if [[ -z "$subcommand" ]]; then
                COMPREPLY=($(compgen -W "$device_commands" -- "$cur"))
            else
                COMPREPLY=($(compgen -f -- "$cur"))
            fi
            ;;
        contact)
            if [[ -z "$subcommand" ]]; then
                COMPREPLY=($(compgen -W "$contact_commands" -- "$cur"))
            else
                COMPREPLY=($(compgen -f -- "$cur"))
            fi
            ;;
        *)
            COMPREPLY=($(compgen -f -- "$cur"))
            ;;
    esac
}

complete -F _zm zm
