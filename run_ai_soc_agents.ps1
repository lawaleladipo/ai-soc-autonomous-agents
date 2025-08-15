# run_ai_soc_agents.ps1
# PowerShell end-to-end test for AI SOC Agent Ecosystem
# Author: Olawale Oladipo
# Date: 2025-08-14
# Purpose: Test ingestion, detection, triage, hunting, and documentation endpoints

# Activate strict mode for safety
Set-StrictMode -Version Latest

# -------------------------------
# 1. Set API headers correctly
# -------------------------------
$headers = @{}
$headers.Add("api-key", "supersecret1")

# -------------------------------
# 2. Prepare sample CVE/Event body
# -------------------------------
$sampleEvent = @{
    eventName = "ConsoleLogin"
    userIdentity = @{ type = "Root" }
    additionalEventData = @{ MFAUsed = "No" }
}

$ingestBody = @{
    records = @($sampleEvent)
    source  = "aws-cloudtrail"
} | ConvertTo-Json -Depth 10

# -------------------------------
# 3. Prepare Threat Detection body
# -------------------------------
$threatBody = @{
    records = @($sampleEvent)
} | ConvertTo-Json -Depth 10

# -------------------------------
# 4. Prepare Triage body
# -------------------------------
$triageBody = @{
    alerts = @(
        @{
            id = "alert-001"
            description = "Root login without MFA"
            severity = "high"
            event = $sampleEvent
        }
    )
} | ConvertTo-Json -Depth 10

# -------------------------------
# 5. Prepare Threat Hunt body
# -------------------------------
$huntBody = @{
    query = "search for failed root login attempts"
} | ConvertTo-Json -Depth 10

# -------------------------------
# 6. Prepare Incident Documentation body
# -------------------------------
$docBody = @{
    incidents = @(
        @{
            id = "incident-001"
            alerts = @(
                @{
                    id = "alert-001"
                    description = "Root login without MFA"
                }
            )
            timeline = @("Event detected", "Alert triaged", "Incident documented")
        }
    )
} | ConvertTo-Json -Depth 10

# -------------------------------
# Helper function: POST request
# -------------------------------
function Post-Endpoint {
    param (
        [string]$url,
        [hashtable]$headers,
        [string]$body
    )
    try {
        $response = Invoke-RestMethod -Uri $url -Method POST -Headers $headers -Body $body -ContentType "application/json"
        Write-Host "✅ Success: $url"
        Write-Output $response
    }
    catch {
        Write-Host "❌ Error calling $url"
        Write-Host $_.Exception.Response.Content
    }
}

# -------------------------------
# 7. Execute End-to-End Test
# -------------------------------
Write-Host "=== Ingesting CVE/Event ==="
Post-Endpoint -url "http://localhost:8000/agents/cve/ingest" -headers $headers -body $ingestBody

Write-Host "`n=== Running Threat Detection ==="
Post-Endpoint -url "http://localhost:8000/agents/threat/detect" -headers $headers -body $threatBody

Write-Host "`n=== Triage Alerts ==="
Post-Endpoint -url "http://localhost:8000/agents/triage" -headers $headers -body $triageBody

Write-Host "`n=== Running Threat Hunting ==="
Post-Endpoint -url "http://localhost:8000/agents/hunt" -headers $headers -body $huntBody

Write-Host "`n=== Documenting Incidents ==="
Post-Endpoint -url "http://localhost:8000/agents/document" -headers $headers -body $docBody

Write-Host "`n=== Checking API Health ==="
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method GET
    Write-Host "API Health Response:"
    Write-Output $health
}
catch {
    Write-Host "❌ Error checking API health"
    Write-Host $_.Exception.Response.Content
}

Write-Host "`n=== AI SOC Agent End-to-End Test Completed ==="
