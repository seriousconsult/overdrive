param(
  [Parameter(Mandatory=$true)]
  [string]$Script,

  [Parameter(ValueFromRemainingArguments=$true)]
  [string[]]$Args
)

$Distro = "FedoraLinux-43"
$RepoDir = "/mnt/c/code/overdrive"

function To-SingleQuoteBash([string]$s) {
  # Wrap in single quotes, and escape embedded single quotes safely for bash:
  # 'foo'"'"'bar'
  return "'" + ($s -replace "'", "'\\''") + "'"
}

# Quote each argument so vpn/... doesn't get treated specially by bash
$scriptQ = To-SingleQuoteBash $Script
$argQs = @()
foreach ($a in $Args) {
  $argQs += (To-SingleQuoteBash $a)
}

# Build the bash command we will run under WSL
$bashCmd = "cd " + (To-SingleQuoteBash $RepoDir) + "; ./wsl_run.sh " + $scriptQ
if ($argQs.Count -gt 0) {
  $bashCmd += " " + ($argQs -join " ")
}

Write-Host "About to run inside WSL:" -ForegroundColor Cyan
Write-Host "wsl -d $Distro -- bash -lc $bashCmd" -ForegroundColor Yellow
$resp = Read-Host "Proceed? (y/N)"

if ($resp -ne "y" -and $resp -ne "Y") {
  Write-Host "Cancelled." -ForegroundColor Green
  exit 0
}

& wsl.exe -d $Distro -- bash -lc $bashCmd
exit $LASTEXITCODE
