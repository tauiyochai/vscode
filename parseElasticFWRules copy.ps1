##Script using Elastic API.
param(
    [Parameter()]
    [Validateset("SingleServer","CSVFile")]
    [String]$Mode="CSVFile",

    [Parameter()]
    [String]$ServerName="zilumatic",
    
    [Parameter()]
    [String]$ReqIPAddress="10.14.34.3",

    [Parameter()]
    [Validateset("IPAddress","ServerName")]
    [String]$ResolveType="IPAddress",
 
    [Parameter()]
    [String]$InputCSVFilePath="C:\temp\ServersForNetMig.Csv",

    [Parameter()]
    [Switch]$CSVOutPutExport=$True,

    [Parameter()]
    [String]$CSVReportFolderPath="C:\temp",

    [Parameter()]
    [String]$HTMLReportFolderPath="C:\temp",

    [Parameter()]
    [Validateset("Outbound","Inbound")]
    [String]$Direction="Inbound"
)

$ElasticToken=@{'Authorization'= "ApiKey MTBncFQ1QUJLcl9TUU1HY2EtZnI6LWNhbEJyc01UYi1yalEzTUV4aUx2QQ=="}
$Elastic1URL="https://elasticsearch01.tau.ac.il:9200/"
$Elastic2URL="https://elasticsearch02.tau.ac.il:9200/"
$Elastic3URL="https://elasticsearch03.tau.ac.il:9200/"
If($ResolveType -eq "IPAddress"){$ReqInfo= $ReqIPAddress}
ElseIf($ResolveType -eq "ServerName"){$ReqInfo= $ServerName}
$ElBodyOutbound='
{
  "size": 0,
  "timeout": "240s",
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "rule.name": "JokersOutbound"
          }
        },
        {
          "bool": {
            "should": [
              {
                "term": {
                  "source.ip": "<ReqIP>"
                }
              },
              {
                "term": {
                  "destination.ip": "<ReqIP>"
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": {
        "field": "source.ip"
      },
      "aggs": {
        "by_destination": {
          "terms": {
            "field": "destination.ip"
          },
          "aggs": {
            "by_port": {
              "terms": {
                "field": "destination.port"
              },
              "aggs": {
                "hits_count": {
                  "value_count": {
                    "field": "destination.port"
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
  '
$ElBodyInBound='
{
  "size": 0,
  "timeout": "240s",
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "rule.name": "JokersInbound"
          }
        },
        {
          "bool": {
            "should": [
              {
                "term": {
                  "source.ip": "<ReqIP>"
                }
              },
              {
                "term": {
                  "destination.ip": "<ReqIP>"
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": {
        "field": "source.ip"
      },
      "aggs": {
        "by_destination": {
          "terms": {
            "field": "destination.ip"
          },
          "aggs": {
            "by_port": {
              "terms": {
                "field": "destination.port"
              },
              "aggs": {
                "hits_count": {
                  "value_count": {
                    "field": "destination.port"
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
'

if ($Direction -eq "Inbound") {
  $ElBody=$ElBodyInBound -replace '<ReqIP>',$ReqIPAddress
}
else {
  $ElBody=$ElBodyOutbound -replace '<ReqIP>',$ReqIPAddress
}

$FullURL=$Elastic1URL+"filebeat-palo-alto-*/_search"
$Result=Invoke-WebRequest -Method POST -Headers $ElasticToken -Uri $FullURL -ContentType 'application/json' -body $ElBody

$jsonObject = $result.Content | ConvertFrom-Json
$results = @()
foreach ($source in $jsonObject.aggregations.by_source.buckets) {
    try {
      $sourceHost=$source.key
    }
    catch {
      $sourceHost=$source.key
    }
      foreach ($destination in $source.by_destination.buckets) {
        try {
          $destinationHost=$destination.key
        }
        catch {
          $destinationHost=$destination.key
        }
        foreach ($port in $destination.by_port.buckets) {
            $portNumber = $port.key
            $hitCount = $port.hits_count.value
            if ($portNumber -ne 0) {
            $result = "From: $sourceHost to: $destinationHost using Port $portNumber has a hit count of $hitCount."
            $results += $result
          }
        }
    }
}

if (-not $results) {
  if ($Direction -eq "Outbound") { Write-Host "No relevant outbound connections found" }
    else { Write-Host "No relevant Inbound connections found"}
}
else { $results }