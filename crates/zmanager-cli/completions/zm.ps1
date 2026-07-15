# PowerShell completion for zm
#
# Windows PowerShell 5.1 does not invoke native argument completers for a bare
# "-" or "--". Complete command options after the first option character, such
# as "zm list --t<TAB>".

Register-ArgumentCompleter -Native -CommandName zm -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    if ($null -eq $wordToComplete) {
        $wordToComplete = ""
    }

    $commands = @("create", "extract", "list", "test", "plan", "formats", "auth", "me", "cert", "device", "sign", "verify", "contact", "share", "doctor", "completions", "help")
    $helpTopics = @("create", "extract", "list", "test", "plan", "formats", "auth", "me", "cert", "device", "sign", "verify", "contact", "share", "doctor", "completions")
    $shellValues = @("bash", "zsh", "fish", "powershell")
    $formatValues = @("zip", "tar.zst", "tzap", "aar", "7z")
    $colorValues = @("auto", "always", "never")
    $progressValues = @("auto", "always", "never")
    $overwriteValues = @("never", "always", "ask", "rename")
    $volumeSizeValues = @("64k", "100m", "500m", "1g", "2g", "4g")
    $authCommands = @("login", "callback", "status", "forget", "account")
    $certCommands = @("list", "enroll", "renew", "revoke")
    $deviceCommands = @("retire")
    $contactCommands = @("export", "import", "list", "remove")

    $globalOptions = @(
        "-h", "--help", "-V", "--version", "-q", "--quiet", "-v", "--verbose",
        "--json", "--color", "--no-color", "--progress", "--no-progress",
        "--no-password-prompt", "-c", "--create", "-x", "--extract", "-t",
        "--list", "-T", "--test", "-f", "--file"
    )
    $createOptions = @(
        "-h", "--help", "-r", "--recursive", "-C", "--directory", "-@",
        "--files-from", "--null", "--clean", "--no-ignore", "--hidden",
        "--no-hidden", "-i", "--include", "--exclude", "--exclude-from",
        "--format", "--method", "--level", "-0", "-1", "-2", "-3", "-4",
        "-5", "-6", "-7", "-8", "-9", "--store", "--solid", "--no-solid",
        "--volume-size", "--recipient-cert", "--signing-cert", "--signing-private-key", "--signing-chain",
        "-j", "--junk-paths", "-y", "--preserve-symlinks",
        "--follow-symlinks", "--preserve-metadata", "-X", "--no-metadata",
        "-f", "--file", "--force", "--dry-run", "-T", "--test-after", "--encrypt",
        "--password-stdin"
    )
    $extractOptions = @(
        "-h", "--help", "-C", "-d", "--directory", "--here", "--overwrite",
        "-i", "--include", "--exclude", "--strip-components", "--to-stdout",
        "--extract-nested", "--password-stdin", "--recipient-key"
    )
    $listOptions = @(
        "-h", "--help", "-f", "--file", "-l", "--long", "--name-only",
        "--tree", "-i", "--include", "--exclude", "--password-stdin", "--recipient-key", "--json"
    )
    $testOptions = @(
        "-h", "--help", "-f", "--file", "-i", "--include", "--exclude",
        "--password-stdin", "--recipient-key", "--public-no-key", "--trusted-ca-cert",
        "--trusted-system-roots", "--json"
    )
    $planOptions = @(
        "-h", "--help", "--format", "-C", "--directory", "-@",
        "--files-from", "--null", "--clean", "--no-ignore", "-i", "--include",
        "--exclude", "--exclude-from", "--json"
    )
    $commandOptions = @{
        create = $createOptions
        extract = $extractOptions
        list = $listOptions
        test = $testOptions
        plan = $planOptions
        auth = @("-h", "--help", "--print-url", "--state-dir", "--account-key", "--environment", "--auth-base-url", "--account-base-url", "--client-id", "--redirect-uri", "--provider", "--org-id", "--state", "--callback-url", "--handoff-code", "--relay-body", "--json")
        me = @("-h", "--help", "--state-dir", "--account-key", "--json")
        cert = @("-h", "--help", "--state-dir", "--account-key", "--certificate-id", "--service-base-url", "--trusted-root-cert", "--org-id", "--requested-validity-seconds", "--json")
        device = @("-h", "--help", "--state-dir", "--account-key", "--json")
        sign = @("-h", "--help", "--state-dir", "--account-key", "--certificate-id", "--output", "--claimed-signing-time", "--json")
        verify = @("-h", "--help", "--custom-trust-root", "--custom-trust-root-cert", "--status-response", "--time", "--json")
        contact = @("-h", "--help", "--state-dir", "--account-key", "--recipient-key-id", "--certificate-id", "--display-name", "--device-label", "--output", "--accept", "--custom-trust-root", "--custom-trust-root-cert", "--json")
        share = @("-h", "--help", "--state-dir", "--account-key", "--contact", "--force", "--json")
        formats = @("-h", "--help", "--json")
        doctor = @("-h", "--help", "--json")
        completions = @("-h", "--help")
    }

    function New-ZmCompletionResult {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Value,

            [string]$ToolTip = $Value,

            [System.Management.Automation.CompletionResultType]$ResultType =
                [System.Management.Automation.CompletionResultType]::ParameterValue
        )

        [System.Management.Automation.CompletionResult]::new(
            $Value,
            $Value,
            $ResultType,
            $ToolTip
        )
    }

    function Complete-ZmValues {
        param(
            [string[]]$Values,
            [string]$Prefix,
            [System.Management.Automation.CompletionResultType]$ResultType =
                [System.Management.Automation.CompletionResultType]::ParameterValue
        )

        foreach ($value in $Values) {
            if ($value.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                New-ZmCompletionResult -Value $value -ResultType $ResultType
            }
        }
    }

    function Format-ZmPathCompletion {
        param([string]$Value)

        if ($Value -match "[\s'`"]") {
            return "'" + $Value.Replace("'", "''") + "'"
        }
        $Value
    }

    function Complete-ZmFiles {
        param([string]$Prefix)

        $parent = Split-Path -Path $Prefix -Parent
        $leaf = Split-Path -Path $Prefix -Leaf
        if ([string]::IsNullOrEmpty($parent)) {
            $searchRoot = "."
            $displayPrefix = ""
        } else {
            $searchRoot = $parent
            $displayPrefix = $parent + [System.IO.Path]::DirectorySeparatorChar
        }

        $filter = if ([string]::IsNullOrEmpty($leaf)) { "*" } else { "$leaf*" }
        Get-ChildItem -LiteralPath $searchRoot -Filter $filter -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $suffix = if ($_.PSIsContainer) { [System.IO.Path]::DirectorySeparatorChar } else { "" }
                $completion = $displayPrefix + $_.Name + $suffix
                New-ZmCompletionResult `
                    -Value (Format-ZmPathCompletion $completion) `
                    -ToolTip $_.FullName `
                    -ResultType ([System.Management.Automation.CompletionResultType]::ProviderItem)
            }
    }

    $elements = @($commandAst.CommandElements | ForEach-Object { $_.Extent.Text })
    if ($elements.Count -gt 1) {
        $words = @($elements[1..($elements.Count - 1)])
    } else {
        $words = @()
    }

    if ($words.Count -gt 0 -and $words[-1] -eq $wordToComplete) {
        if ($words.Count -gt 1) {
            $completedWords = @($words[0..($words.Count - 2)])
        } else {
            $completedWords = @()
        }
    } else {
        $completedWords = $words
    }

    $previousWord = if ($completedWords.Count -gt 0) { $completedWords[-1] } else { "" }
    $command = ""
    foreach ($word in $completedWords) {
        if ($commands -contains $word) {
            $command = $word
            break
        }
    }

    switch ($previousWord) {
        "--color" {
            Complete-ZmValues -Values $colorValues -Prefix $wordToComplete
            return
        }
        "--progress" {
            Complete-ZmValues -Values $progressValues -Prefix $wordToComplete
            return
        }
        "--format" {
            Complete-ZmValues -Values $formatValues -Prefix $wordToComplete
            return
        }
        "--overwrite" {
            Complete-ZmValues -Values $overwriteValues -Prefix $wordToComplete
            return
        }
        "--volume-size" {
            Complete-ZmValues -Values $volumeSizeValues -Prefix $wordToComplete
            return
        }
        "--environment" {
            Complete-ZmValues -Values @("local", "dev", "prod") -Prefix $wordToComplete
            return
        }
        "-C" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "-d" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--directory" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--files-from" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--exclude-from" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--recipient-cert" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--signing-cert" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--signing-private-key" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--signing-chain" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--recipient-key" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--trusted-ca-cert" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "-f" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
        "--file" {
            Complete-ZmFiles -Prefix $wordToComplete
            return
        }
    }

    if ($wordToComplete.StartsWith("-", [System.StringComparison]::Ordinal)) {
        if ($commandOptions.ContainsKey($command)) {
            Complete-ZmValues `
                -Values $commandOptions[$command] `
                -Prefix $wordToComplete `
                -ResultType ([System.Management.Automation.CompletionResultType]::ParameterName)
        } else {
            Complete-ZmValues `
                -Values $globalOptions `
                -Prefix $wordToComplete `
                -ResultType ([System.Management.Automation.CompletionResultType]::ParameterName)
        }
        return
    }

    switch ($command) {
        "" {
            Complete-ZmValues -Values $commands -Prefix $wordToComplete
        }
        "help" {
            Complete-ZmValues -Values $helpTopics -Prefix $wordToComplete
        }
        "completions" {
            Complete-ZmValues -Values $shellValues -Prefix $wordToComplete
        }
        "auth" {
            Complete-ZmValues -Values $authCommands -Prefix $wordToComplete
        }
        "cert" {
            Complete-ZmValues -Values $certCommands -Prefix $wordToComplete
        }
        "device" {
            Complete-ZmValues -Values $deviceCommands -Prefix $wordToComplete
        }
        "contact" {
            Complete-ZmValues -Values $contactCommands -Prefix $wordToComplete
        }
        "formats" {}
        "doctor" {}
        default {
            Complete-ZmFiles -Prefix $wordToComplete
        }
    }
}
