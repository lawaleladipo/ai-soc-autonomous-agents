# run_ai_soc_agents.ps1
# PowerShell end-to-end smoke test for AI SOC Autonomous Agents FastAPI Gateway
Set-StrictMode -Version Latest

$ApiKey = if ($env:API_KEY) { $env:API_KEY } else { "dev-local-soc-key" }
$BaseUrl = if ($env:SOC_API_URL) { $env:SOC_API_URL } else { "http://127.0.0.1:8000" }
$Headers = @{ "X-API-Key" = $ApiKey }

function Invoke-SocEndpoint {
    param ([string]$Path, [string]$Body = "{}")
    $Url = "$BaseUrl$Path"
    Write-Host "`n=== POST $Url ==="
    $Resp = Invoke-RestMethod -Uri $Url -Method POST -Headers $Headers -Body $Body -ContentType "application/json"
    $Resp | ConvertTo-Json -Depth 6
}

Write-Host "=== Checking /health ==="
Invoke-RestMethod -Uri "$BaseUrl/health" -Method GET | ConvertTo-Json -Depth 4

Invoke-SocEndpoint -Path "/cve/run"
Invoke-SocEndpoint -Path "/threat/run"
Invoke-SocEndpoint -Path "/triage/run"
Invoke-SocEndpoint -Path "/hunt/run" -Body '{"hypothesis_key":"credential_dumping"}'
Invoke-SocEndpoint -Path "/doc/run" -Body '{"document_type":"EXECUTIVE_SUMMARY","persist_files":false}'
Invoke-SocEndpoint -Path "/pipeline/investigate"
