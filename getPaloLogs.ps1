# Function to submit the log query and retrieve logs immediately after job completion
function Submit-LogQuery {
    param (
        [string]$panoramaIp,
        [string]$apiKey,
        [string]$query,
        [int]$nlogs = 1000  # Number of logs to fetch per request
    )
    
    $skip = 0  # For pagination, we start with skipping 0 logs
    $allLogs = @()  # To store all collected logs

    while ($true) {
        # Construct the API call with pagination (nlogs and skip parameters)
        $url = "https://$panoramaIp/api/?type=log&log-type=traffic&query=$query&nlogs=$nlogs&skip=$skip"
        
        # Make the API request to submit logs for the current batch
        $response = Invoke-RestMethod -Uri $url -Headers @{'X-PAN-KEY' = $apiKey} -SkipCertificateCheck

        # Get the job ID from the response
        $jobId = $response.response.result.job
        
        if (-not $jobId) {
            Write-Host "No more job IDs found or query failed."
            break
        }

        Write-Host "Submitted query with Job ID: $jobId"
        
        # Check the job status and wait until it is done
        while ($true) {
            $jobStatus = Get-JobStatus -panoramaIp $panoramaIp -apiKey $apiKey -jobId $jobId
            
            if ($jobStatus.Status -eq "DONE") {
                Write-Host "Job $jobId is finished."
                break
            } else {
                Write-Host "Job $jobId is still in progress. Waiting for completion..."
                Start-Sleep -Seconds 1  # Wait for 1 seconds before checking again
            }
        }

        # Once the job is finished, retrieve logs using the job ID
        $logs = Get-Logs -panoramaIp $panoramaIp -apiKey $apiKey -jobId $jobId
        $allLogs += $logs  # Collect logs from this job
        
        # Increment the skip count for the next batch in the next iteration
        $skip += $nlogs

        # If there are no more logs, exit the loop
        if (-not $logs) {
            Write-Host "No more logs to retrieve."
            break
        }
    }
    
    # Return all collected logs after all jobs are completed
    return $allLogs
}

# Function to check if the log query job is finished
function Get-JobStatus {
    param (
        [string]$panoramaIp,
        [string]$apiKey,
        [string]$jobId
    )
    
    # API call to check the job status
    $url = "https://$panoramaIp/api/?type=op&cmd=<show><query><jobid>$jobId</jobid></query></show>"
    $response = Invoke-RestMethod -Uri $url -Method Get -SkipCertificateCheck -Headers @{'X-PAN-KEY' = $apiKey}

    # Parse the job status from the result
    $result = $response.response.result

    # Extract the state (e.g., "DONE") from the response
    $stateRegex = [regex]'(?m)^\S+\s+(\d+)\s+([A-Za-z]+)'  # Regex to capture the state (DONE/PENDING/etc.)
    $match = $stateRegex.Match($result)

    if ($match.Success) {
        $jobState = $match.Groups[2].Value
        return @{ Status = $jobState }
    } else {
        throw "Failed to parse job status from the response."
    }
}

# Function to get logs using the job-id after the query has completed
function Get-Logs {
    param (
        [string]$panoramaIp,
        [string]$apiKey,
        [string]$jobId
    )
    
    $allLogs = @()

    # API call to retrieve the logs using the job ID
    $url = "https://$panoramaIp/api/?type=log&log-type=traffic&action=get&jobid=$jobId"
    $response = Invoke-RestMethod -Uri $url -Method Get -SkipCertificateCheck -Headers @{'X-PAN-KEY' = $apiKey}
    
    # Check if logs are present in the response
    $entries = $response.response.result.log.logs.entry
    
    if ($entries) {
        # Add logs to the collection
        $allLogs += $entries
    }

    return $allLogs  # Return the collected logs
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
            ReceiveTime   = $log.receive_time
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
$apiKey = "LUFRPT02MlFQelMyeDltVVZIUFBMNDAzcTBxNmswMDQ9NG9uM2FGUnpFeEIwdms1c2tKRWxsd0pNMkNkdWM5R0ZvYkFyMlJsbFJta0lZekNVZ1VtUEg0Q09WSkxHMlo3Mg=="  # Store your API key securely
$nlogs = 5000  # Number of logs to fetch per request
$queryType = "Outbound"

# Define the query parameters
$sourceIp = "132.66.66.22"
$startTime = "2024/10/10 10:45:00"  # Adjust the time format as needed

# Construct the query to filter logs based on query type
if ($queryType -eq "Outbound") {
    $query = "(addr.src in $sourceIp) and (receive_time geq '$startTime')"
}
else {
    $query = "(addr.dst in $sourceIp) and (receive_time geq '$startTime')"
}

# Submit the query and retrieve logs immediately after job completion
$allLogs = Submit-LogQuery -panoramaIp $panoramaIp -apiKey $apiKey -query $query -nlogs $nlogs
Write-Host "Query completed and logs retrieved."

# Filter the logs to keep only specific fields
$filteredLogs = Filter-Logs -logs $allLogs

# Print total number of logs fetched
Write-Host "Total logs fetched: $($filteredLogs.Count)"

# Example: output filtered logs
$filteredLogs | ForEach-Object {
    Write-Host "Log entry - Source: $($_.Source), Destination: $($_.Destination), Time: $($_.ReceiveTime), Rule: $($_.Rule), App: $($_.Application), Port: $($_.Port)"
}
$filteredLogs.Count