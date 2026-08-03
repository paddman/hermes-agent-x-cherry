param(
    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Configuration = "Release",
    [string]$BuildDirectory = "",
    [string]$PcapRoot = $env:PCAP_ROOT
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
    $BuildDirectory = Join-Path $Root "build"
}

$CmakeArgs = @(
    "-S", $Root,
    "-B", $BuildDirectory,
    "-DCMAKE_BUILD_TYPE=$Configuration"
)
if (-not [string]::IsNullOrWhiteSpace($PcapRoot)) {
    $CmakeArgs += "-DPCAP_ROOT=$PcapRoot"
}

& cmake @CmakeArgs
& cmake --build $BuildDirectory --config $Configuration --parallel
& ctest --test-dir $BuildDirectory -C $Configuration --output-on-failure

$Candidates = @(
    (Join-Path $BuildDirectory "cherry-pcap.exe"),
    (Join-Path $BuildDirectory "$Configuration/cherry-pcap.exe")
)
$Binary = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($Binary) {
    Write-Host "Built: $Binary"
} else {
    Write-Host "Build completed. Binary is under $BuildDirectory."
}
