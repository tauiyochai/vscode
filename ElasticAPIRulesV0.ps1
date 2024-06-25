##Script using Elastic API.
param(
    [Parameter()]
    [Validateset("SingleServer","CSVFile")]
    [String]$Mode="CSVFile",

    [Parameter()]
    [String]$ServerName="msgilboa-webt",
    
    [Parameter()]
    [String]$ReqIPAddress="132.66.254.7",

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
    [String]$HTMLReportFolderPath="C:\temp"
)

$ElasticToken=@{'Authorization'= "ApiKey dGtoUFNwQUJLcl9TUU1HY1ppN1A6dUwyaTdFVlZSMXU0OHdsRE5WdGRtQQ=="}
$Elastic1URL="https://elasticsearch01.tau.ac.il:9200/"
$Elastic2URL="https://elasticsearch02.tau.ac.il:9200/"
$Elastic3URL="https://elasticsearch02.tau.ac.il:9200/"
If($ResolveType -eq "IPAddress"){$ReqInfo= $ReqIPAddress}
ElseIf($ResolveType -eq "ServerName"){$ReqInfo= $ServerName}
#$TelnetResult=Test-NetConnection $ReqInfo -port 443
#$ReqIPAddress=$TelnetResult.RemoteAddress

#$DNSName=Resolve-DnsName -Name $ServerName
#$ServerIP=$DNSName.IPAddress
#Region Json
$ElBodyA='{
    "size": 0,
    "query": {
      "bool": {
        "must": [
          {
            "term": {
              "destination.ip": "<ReqIP>"
            }
          },
          {
            "term": {
              "source.ip": "132.66.110.96"
            }
          }
        ]
      }
    },
    "aggs": {
      "hosts": {
        "terms": {
          "field": "rule.name",
          "size": 10
        },
        "aggs": {
          "sourceip": {
            "terms": {
              "field": "source.ip",
              "size": 10
            }
          }
        }
      }
    }
  }'
$ElBody='
{
    "size": 0,
    "query": {
      "bool": {
        "must": [
          {
            "term": {
              "destination.ip": "132.66.254.11"
            }
          },
          {
            "term": {
              "source.ip": "132.66.110.96"
            }
          }
        ]
      }
    },
    "aggs": {
      "rule": {
        "terms": {
          "field": "rule.name",
          "size": 10
        },
        "aggs": {
          "user": {
            "terms": {
              "field": "source.ip",
              "size": 10
            }
          }
        }
      }
    }
  }
'
#EndRegion Json
<#
$Data=@()
$CustomObject =[pscustomobject]@{
  size=10
  'Destination.ip'="132.66.254.11"
};
$Data+=$CustomObject
$MyJson=ConvertTo-Json -InputObject $data
#>
$MyJson='{
  "query": {
    "bool": {
    "must": [
      { 
        "term": {
          "destination.ip": "<ReqIPToChange>"
        }
      },
      {
        "term":{
          "source.ip":"132.66.110.96"
        }
      }
      ]
    }
  }
}'
$MyJson1=$MyJson -replace '<ReqIPToChange>',$ReqIPAddress
$ElBody1=$ElBodyA -replace '<ReqIP>',$ReqIPAddress
$FullURL=$Elastic1URL+"filebeat-palo-alto-*/_search"
$Result=Invoke-RestMethod -Method POST -Headers $ElasticToken -Uri $FullURL -ContentType 'application/json' -body $$ElBody1 # -ResponseHeadersVariable Results
$FinalResults=$Result.hits.hits._source
$FinalResults| Format-Table source,rule,panw,destination -AutoSize
If($FinalResults.rule.name -contains "JokersInbound"){Write-Host -ForegroundColor Green " Jokersinbound rule exist"}
Else{Write-Host -ForegroundColor Red " No JokersInbound Rule"}
#$Result.hits.hits._source