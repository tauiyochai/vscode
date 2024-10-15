# Function to check if the log query job is finished
function Get-JobStatus {
    param (
        [string]$panoramaIp,
        [string]$apiKey,
        [string]$jobId
    )
    
    # Correct API call with proper job query
    $url = "https://$panoramaIp/api/?type=op&cmd=<show><query><jobid>$jobId</jobid></query></show>"
    $response = Invoke-RestMethod -Uri $url -Method Get -SkipCertificateCheck -Headers @{'X-PAN-KEY' = $apiKey}

    # Parse the job status from the result using regex or string split
    $result = $response.response.result

    # Extract the state (e.g., "DONE") from the response
    $stateRegex = [regex]"\s+(\d+)\s+(\w+)\s+"  # Regex to capture the state (DONE/PENDING/etc.)
    $match = $stateRegex.Match($result)

    if ($match.Success) {
        $jobState = $match.Groups[2].Value
        return @{ Status = $jobState }
    } else {
        throw "Failed to parse job status from the response."
    }
}

# Function to get logs with pagination
function Get-Logs {
    param (
        [string]$panoramaIp,
        [string]$apiKey,
        [string]$jobId,
        [int]$nlogs = 1000
    )
    
    $allLogs = @()
    $skip = 0
    
    while ($true) {
        $url = "https://$panoramaIp/api/?type=log&log-type=traffic&action=get&job-id=$jobId&nlogs=$nlogs&skip=$skip"
        $response = Invoke-RestMethod -Uri $url -Method Get -SkipCertificateCheck -Headers @{'X-PAN-KEY' = $apiKey}
        
        # Check if logs are present in the response
        $entries = $response.response.result.log.entry
        
        if (-not $entries) {
            # No more logs, exit the loop
            break
        }
        
        # Add logs to the collection
        $allLogs += $entries
        
        # Increment skip for next batch
        $skip += $nlogs
        
        Write-Host "Fetched $($allLogs.Count) logs so far..."
    }
    
    return $allLogs
}

# Function to filter specific fields from logs
function Filter-Logs {
    param (
        [array]$logs
    )
    
    $filteredLogs = @()
    
    foreach ($log in $logs) {
        $filteredLog = @{
            Source        = $log.source
            Destination   = $log.destination
            #ReceiveTime   = $log.receive_time
            Rule          = $log.rule
            Application   = $log.app
            Port          = $log.dport
            Username      = $log.dstuser
            Action        = $log.action
        }
        $filteredLogs += $filteredLog
    }
    
    return $filteredLogs
}

# Main script
$panoramaIp = "pam600.tau.ac.il"
$apiKey = "LUFRPT02MlFQelMyeDltVVZIUFBMNDAzcTBxNmswMDQ9NG9uM2FGUnpFeEIwdms1c2tKRWxsd0pNMkNkdWM5R0ZvYkFyMlJsbFJta0lZekNVZ1VtUEg0Q09WSkxHMlo3Mg=="  # Replace with your actual API key
$nlogs = 1000          # Number of logs to fetch per request
$queryType = "Outbound"

# Define the query parameters
$sourceIp = "132.66.66.22"
#$destinationIp = "10.0.0.5"
#$port = "28674"
#$rule = "Allow-Web-Traffic"
$startTime = "2024/10/10 10:45:00"  # Adjust the time format as needed

# Construct the query to filter logs
if ($queryType = "Outbound") {
    $query = "(addr.src in $sourceIp) and (receive_time geq '$startTime')"
}
else {
    $query = "(addr.dst in $sourceIp) and (receive_time geq '$startTime')"
}

# Submit the query and get the job ID
$jobId = Submit-LogQuery -panoramaIp $panoramaIp -apiKey $apiKey -query $query
Write-Host "Submitted query. Job ID: $jobId"

# Check if the job is finished
while ($true) {
    $jobStatus = Get-JobStatus -panoramaIp $panoramaIp -apiKey $apiKey -jobId $jobId
    
    if ($jobStatus.Status -eq "DONE") {
        Write-Host "Job $jobId is finished."
        break
    } else {
        Write-Host "Job $jobId is still in progress. Waiting for completion..."
        Start-Sleep -Seconds 10  # Wait for 10 seconds before checking again
    }
}

# Once the job is finished, retrieve logs
$logs = Get-Logs -panoramaIp $panoramaIp -apiKey $apiKey -jobId $jobId -nlogs $nlogs

# Filter the logs to keep only specific fields
$filteredLogs = Filter-Logs -logs $logs

# Print total number of logs fetched
Write-Host "Total logs fetched: $($filteredLogs.Count)"

# Example: output filtered logs
$filteredLogs | ForEach-Object {
    Write-Host "Log entry - Source: $($_.Source), Destination: $($_.Destination), Time: $($_.ReceiveTime), Rule: $($_.Rule), App: $($_.Application), Port: $($_.Port)"
}