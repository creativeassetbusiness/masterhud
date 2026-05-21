param(
  [string]$ConfigPath = "C:\apps\example-website\Caddyfile",
  [string]$ServiceName = "CaddyProxy"
)

$ErrorActionPreference = "Stop"

$candidates = @()
$command = Get-Command caddy.exe -ErrorAction SilentlyContinue
if ($command -and $command.Source) {
  $candidates += $command.Source
}

$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if ($service -and $service.PathName) {
  $pathName = $service.PathName.Trim()
  if ($pathName -match '^"([^"]+)"') {
    $candidates += $matches[1]
  } else {
    $candidates += ($pathName -split "\s+")[0]
  }
}

$candidates += @(
  (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\caddy.exe"),
  "C:\Program Files\Caddy\caddy.exe",
  "C:\caddy\caddy.exe"
)

$exe = $candidates |
  Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
  Select-Object -First 1

if (-not $exe) {
  throw "caddy.exe not found"
}

& $exe validate --config $ConfigPath --adapter caddyfile
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

[pscustomobject]@{
  ok = $true
  exe = $exe
  config = $ConfigPath
} | ConvertTo-Json -Compress
