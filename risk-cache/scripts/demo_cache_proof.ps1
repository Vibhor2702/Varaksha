$ErrorActionPreference = 'Stop'

$headersApi = @{ 'X-Varaksha-Api-Key' = 'judge-demo-api-key' }
$m1 = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/metrics' -Headers $headersApi -Method Get

$inferObj = @{
    transaction_id = 'txn-001'
    raw_device_id  = 'device-A'
    amount         = 123.45
}
$body = $inferObj | ConvertTo-Json -Compress
$i1 = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/inference' -Headers $headersApi -Method Post -Body $body -ContentType 'application/json'

$sha = [System.Security.Cryptography.SHA256]::Create()
$vpaHash = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes('device-A')) | ForEach-Object { $_.ToString('x2') })

$graphObj = @{
    vpa_hash  = $vpaHash
    risk_delta = 0.8
    reason    = 'demo_ring_pattern'
    _timestamp = 1711843200
}
$graphBody = $graphObj | ConvertTo-Json -Compress

$keyBytes = [System.Text.Encoding]::UTF8.GetBytes('judge-demo-graph-secret')
$hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
$sig = -join ($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($graphBody)) | ForEach-Object { $_.ToString('x2') })
$headersGraph = @{ 'X-Varaksha-Signature' = ('sha256=' + $sig) }

$null = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/graph_update' -Headers $headersGraph -Method Post -Body $graphBody -ContentType 'application/json'
$i2 = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/inference' -Headers $headersApi -Method Post -Body $body -ContentType 'application/json'

$m2 = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/metrics' -Headers $headersApi -Method Get

[ordered]@{
    before_risk         = [double]$i1.risk_score
    after_risk          = [double]$i2.risk_score
    graph_reason_after  = $i2.graph_reason
    cache_size_before   = [int]$m1.risk_delta_cache.size
    cache_size_after    = [int]$m2.risk_delta_cache.size
    cache_hits_before   = [int]$m1.risk_delta_cache.hits
    cache_hits_after    = [int]$m2.risk_delta_cache.hits
    cache_misses_before = [int]$m1.risk_delta_cache.misses
    cache_misses_after  = [int]$m2.risk_delta_cache.misses
} | ConvertTo-Json -Compress
