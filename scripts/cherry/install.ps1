# Cherry Agent source installer for Windows PowerShell 5.1+
#
# This installer deliberately clones the Cherry fork rather than the upstream
# Hermes repository. Runtime data still defaults to the inherited Hermes home
# for compatibility; set CHERRY_HOME before running to choose an isolated home.

[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [string]$Branch = "main",
    [switch]$SkipSetup,
    [switch]$SkipUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RepoUrlHttps = "https://github.com/paddman/hermes-agent-x-cherry.git"
$RepoUrlSsh = "git@github.com:paddman/hermes-agent-x-cherry.git"

function Write-Step {
    param([string]$Message)
    Write-Host "[Cherry] $Message" -ForegroundColor Cyan
}

function Write-Done {
    param([string]$Message)
    Write-Host "[Cherry] $Message" -ForegroundColor Green
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE: $FilePath $($Arguments -join ' ')"
    }
}

function Resolve-PythonCommand {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        foreach ($version in @("3.11", "3.12", "3.13")) {
            & $py.Source "-$version" -c "import sys; print(sys.executable)" *> $null
            if ($LASTEXITCODE -eq 0) {
                return @($py.Source, "-$version")
            }
        }
    }

    foreach ($name in @("python3.11", "python3.12", "python3.13", "python")) {
        $candidate = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $candidate) { continue }
        & $candidate.Source -c "import sys; raise SystemExit(0 if (3, 11) <= sys.version_info[:2] < (3, 14) else 1)" *> $null
        if ($LASTEXITCODE -eq 0) {
            return @($candidate.Source)
        }
    }

    throw "Python 3.11, 3.12, or 3.13 was not found. Install Python, then run this script again."
}

$cherryHomeIsSet = -not [string]::IsNullOrWhiteSpace($env:CHERRY_HOME)
$hermesHomeIsSet = -not [string]::IsNullOrWhiteSpace($env:HERMES_HOME)
if ($cherryHomeIsSet -and -not $hermesHomeIsSet) {
    $env:HERMES_HOME = $env:CHERRY_HOME.Trim()
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $runtimeHome = if (-not [string]::IsNullOrWhiteSpace($env:HERMES_HOME)) {
        $env:HERMES_HOME.Trim()
    } else {
        Join-Path $env:LOCALAPPDATA "hermes"
    }
    $InstallDir = Join-Path $runtimeHome "cherry-agent"
}

$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    throw "Git was not found. Install Git for Windows, then run this script again."
}

Write-Step "Installing Cherry Agent into $InstallDir"

if (Test-Path $InstallDir) {
    if (-not (Test-Path (Join-Path $InstallDir ".git"))) {
        throw "InstallDir exists but is not a Git repository: $InstallDir"
    }

    $origin = (& $git.Source -C $InstallDir remote get-url origin).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read the Git origin for $InstallDir"
    }
    if ($origin -ne $RepoUrlHttps -and $origin -ne $RepoUrlSsh) {
        throw "Refusing to update an unrelated repository. Origin is: $origin"
    }

    $dirty = & $git.Source -C $InstallDir status --porcelain
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect the existing Cherry checkout."
    }
    if ($dirty) {
        throw "The existing Cherry checkout has uncommitted changes. Commit or stash them before updating."
    }

    if (-not $SkipUpdate) {
        Write-Step "Updating branch $Branch with a fast-forward-only merge"
        Invoke-Checked $git.Source @("-C", $InstallDir, "fetch", "origin", $Branch)
        Invoke-Checked $git.Source @("-C", $InstallDir, "checkout", $Branch)
        Invoke-Checked $git.Source @("-C", $InstallDir, "merge", "--ff-only", "origin/$Branch")
    }
} else {
    Write-Step "Cloning the Cherry fork"
    $parent = Split-Path $InstallDir -Parent
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Invoke-Checked $git.Source @("clone", "--branch", $Branch, "--single-branch", $RepoUrlHttps, $InstallDir)
}

# Wrap the function call so a single returned string is still treated as an
# array. Without @(...), PowerShell unwraps one-element arrays and [0] becomes
# the first character of the executable path. Charming language feature.
$pythonCommand = @(Resolve-PythonCommand)
$pythonExe = $pythonCommand[0]
$pythonPrefix = @()
if ($pythonCommand.Count -gt 1) {
    $pythonPrefix = @($pythonCommand[1])
}

$venvDir = Join-Path $InstallDir ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$uvExe = Join-Path $venvDir "Scripts\uv.exe"
$cherryExe = Join-Path $venvDir "Scripts\cherry.exe"

if (-not (Test-Path $venvPython)) {
    Write-Step "Creating the Python virtual environment"
    Invoke-Checked $pythonExe (@($pythonPrefix) + @("-m", "venv", $venvDir))
}

Write-Step "Installing pinned project dependencies"
Invoke-Checked $venvPython @("-m", "pip", "install", "--upgrade", "pip", "uv")

Push-Location $InstallDir
try {
    Invoke-Checked $uvExe @("pip", "install", "--python", $venvPython, "-e", ".[all]")
} finally {
    Pop-Location
}

if (-not (Test-Path $cherryExe)) {
    throw "Installation finished without creating the Cherry launcher: $cherryExe"
}

Write-Done "Cherry Agent installed successfully."
Write-Host ""
Write-Host "Activate the environment:" -ForegroundColor White
Write-Host "  & `"$venvDir\Scripts\Activate.ps1`"" -ForegroundColor Yellow
Write-Host ""
Write-Host "Start Cherry Agent:" -ForegroundColor White
Write-Host "  cherry" -ForegroundColor Yellow
Write-Host ""

if (-not $SkipSetup) {
    Write-Step "Starting Cherry setup"
    Invoke-Checked $cherryExe @("setup")
}
