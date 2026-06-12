# ================================================================
#  Bingo Installer for Windows (PowerShell 5.1+)
#
#  Usage:
#    irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
#
#  Or with execution policy fix:
#    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
#    irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
# ================================================================

# ANSI 코드 없이 색상 출력 (구버전 PowerShell 호환)
function Write-Color {
    param([string]$Text, [string]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

function Write-Banner {
    Write-Host ""
    Write-Color "  ██████╗ ██╗███╗   ██╗ ██████╗  ██████╗ " "Green"
    Write-Color "  ██╔══██╗██║████╗  ██║██╔════╝ ██╔═══██╗" "Green"
    Write-Color "  ██████╔╝██║██╔██╗ ██║██║  ███╗██║   ██║" "Green"
    Write-Color "  ██╔══██╗██║██║╚██╗██║██║   ██║██║   ██║" "Green"
    Write-Color "  ██████╔╝██║██║ ╚████║╚██████╔╝╚██████╔╝" "Green"
    Write-Color "  ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝" "Green"
    Write-Host ""
    Write-Color "  AI Pentest Agent  v2.0  Multi-Model" "Cyan"
    Write-Host ""
}

function Write-Step { param($msg) Write-Color ">> $msg" "Cyan" }
function Write-Ok   { param($msg) Write-Color "  [OK] $msg" "Green" }
function Write-Warn { param($msg) Write-Color "  [WARN] $msg" "Yellow" }
function Write-Fail { param($msg) Write-Color "  [ERROR] $msg" "Red"; exit 1 }

# ── Python 확인 ───────────────────────────────────────────────────
function Check-Python {
    Write-Step "Checking Python 3.10+..."
    $pyCmd = $null
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match "Python (\d+)\.(\d+)") {
                $major = [int]$Matches[1]; $minor = [int]$Matches[2]
                if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 10)) {
                    $pyCmd = $cmd
                    Write-Ok "Found: $ver (using '$cmd')"
                    break
                } else {
                    Write-Warn "Found $ver but need 3.10+, trying next..."
                }
            }
        } catch { continue }
    }
    if (-not $pyCmd) {
        Write-Fail "Python 3.10+ not found. Download from https://python.org/downloads/"
    }
    return $pyCmd
}

# ── pip 명령 탐색 ─────────────────────────────────────────────────
function Get-PipCmd { param($pyCmd)
    foreach ($pip in @("pip", "pip3")) {
        if (Get-Command $pip -ErrorAction SilentlyContinue) { return $pip }
    }
    return "$pyCmd -m pip"
}

# ── 의존성 설치 ───────────────────────────────────────────────────
function Install-Deps { param($pipCmd)
    Write-Step "Installing dependencies..."
    $deps = @("rich", "prompt_toolkit", "httpx[http2]", "pydantic",
              "openai", "anthropic", "hatchling")
    foreach ($dep in $deps) {
        Write-Host "  Installing $dep..." -NoNewline
        Invoke-Expression "$pipCmd install --quiet $dep" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Color " OK" "Green"
        } else {
            Write-Color " WARN (continuing)" "Yellow"
        }
    }
}

# ── bingo 설치 ────────────────────────────────────────────────────
function Install-Bingo { param($pipCmd, $scriptDir)
    Write-Step "Installing bingo..."

    # scriptDir 안전 검증
    if ([string]::IsNullOrWhiteSpace($scriptDir) -or -not (Test-Path $scriptDir)) {
        Write-Fail "Install directory not found: '$scriptDir'"
        return
    }

    # editable 설치 시도
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c $pipCmd install --quiet -e `"$scriptDir`" 2>&1" `
        -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        Write-Warn "editable install failed, trying regular install..."
        $proc2 = Start-Process -FilePath "cmd.exe" `
            -ArgumentList "/c $pipCmd install --quiet `"$scriptDir`" 2>&1" `
            -Wait -PassThru -NoNewWindow
        if ($proc2.ExitCode -ne 0) {
            Write-Warn "pip install had issues — trying pip install with explicit python..."
            & python -m pip install --quiet -e "$scriptDir" 2>&1 | Out-Null
        }
    }
    Write-Ok "bingo installed"
}

# ── PATH 설정 ─────────────────────────────────────────────────────
function Setup-Path { param($pyCmd)
    Write-Step "Setting up PATH..."
    try {
        $scripts = & $pyCmd -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>&1
        $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        if ($userPath -notlike "*$scripts*") {
            [Environment]::SetEnvironmentVariable("PATH", "$userPath;$scripts", "User")
            $env:PATH += ";$scripts"
            Write-Ok "Added to PATH: $scripts"
            Write-Warn "Restart terminal to apply PATH changes"
        } else {
            Write-Ok "PATH already configured"
        }
    } catch {
        Write-Warn "Could not auto-configure PATH. Add Python Scripts folder manually."
    }
}

# ── 메인 ─────────────────────────────────────────────────────────
Clear-Host
Write-Banner

# 설치 디렉터리 결정
# irm | iex 방식: $PSScriptRoot 가 비어있음 → GitHub clone
# 로컬 실행: $PSScriptRoot 에 pyproject.toml 있음
$cloneDir = Join-Path $env:USERPROFILE "bingo"

$ScriptDir = ""
if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot) -and (Test-Path (Join-Path $PSScriptRoot "pyproject.toml"))) {
    $ScriptDir = $PSScriptRoot
    Write-Ok "Local install detected: $ScriptDir"
} else {
    # irm | iex 방식 — GitHub에서 clone
    Write-Step "Downloading bingo from GitHub..."
    if (Test-Path $cloneDir) {
        Write-Warn "$cloneDir already exists, updating..."
        try { & git -C $cloneDir pull --quiet 2>&1 | Out-Null } catch {}
    } else {
        $gitOk = $false
        try {
            & git clone --quiet https://github.com/bingook/bingo.git $cloneDir 2>&1 | Out-Null
            $gitOk = ($LASTEXITCODE -eq 0)
        } catch {}

        if (-not $gitOk) {
            # git 없으면 zip 다운로드
            Write-Warn "git not found — downloading zip..."
            $zip = Join-Path $env:TEMP "bingo.zip"
            try {
                Invoke-WebRequest "https://github.com/bingook/bingo/archive/refs/heads/main.zip" `
                    -OutFile $zip -UseBasicParsing
                Expand-Archive -Path $zip -DestinationPath $env:USERPROFILE -Force
                $extracted = Join-Path $env:USERPROFILE "bingo-main"
                if (Test-Path $extracted) {
                    if (Test-Path $cloneDir) { Remove-Item $cloneDir -Recurse -Force }
                    Rename-Item $extracted $cloneDir
                }
                Write-Ok "Downloaded to $cloneDir"
            } catch {
                Write-Fail "Download failed: $_"
            }
        }
    }
    $ScriptDir = $cloneDir
}

# 최종 경로 검증
if ([string]::IsNullOrWhiteSpace($ScriptDir) -or -not (Test-Path $ScriptDir)) {
    Write-Fail "Could not locate bingo source at: $ScriptDir"
}

$pyCmd  = Check-Python
$pipCmd = Get-PipCmd $pyCmd

Install-Deps $pipCmd
Install-Bingo $pipCmd $ScriptDir
Setup-Path $pyCmd

# ── 완료 ─────────────────────────────────────────────────────────
Write-Host ""
Write-Color "  ============================================" "Green"
Write-Color "  Installation complete!" "Green"
Write-Host ""
Write-Color "  Run: bingo" "Cyan"
Write-Color "  Or:  python -m bingo" "Cyan"
Write-Host ""
Write-Color "  ============================================" "Green"
Write-Host ""
Write-Warn "If 'bingo' command not found, restart PowerShell and try again."
Write-Host ""
