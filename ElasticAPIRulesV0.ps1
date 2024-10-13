##Script using Elastic API.
param(
    [Parameter()]
    [Validateset("SingleServer","CSVFile")]
    [String]$Mode="SingleServer",

    [Parameter()]
    [String]$ServerName="mizug2",
    
    [Parameter()]
    [String]$ReqIPAddress="132.66.66.19",

    [Parameter()]
    [Validateset("IPAddress","ServerName")]
    [String]$ResolveType="ServerName",

    [Parameter()]
    [Validateset("JokerExist","Inbound","OutBound","f5")]
    [String]$RuleMode="inbound",

    [Parameter()]
    [String]$InputCSVFilePath="C:\temp\ServersForNetMig.Csv",

    [Parameter()]
    [Switch]$CSVOutPutExport=$true,

    [Parameter()]
    [Switch]$NoResolve=$true,

    [Parameter()]
    [String]$CSVReportFolderPath="C:\temp",

    [Parameter()]
    [String]$HTMLReportFolderPath="C:\temp"
)

$JokersRuleExist=$null
$ReqInfo=$null
$ElastResult=$null
$ElasticToken=@{'Authorization'= "ApiKey MTBncFQ1QUJLcl9TUU1HY2EtZnI6LWNhbEJyc01UYi1yalEzTUV4aUx2QQ=="}
$Elastic1URL="https://elasticsearch01.tau.ac.il:9200/"
$Elastic2URL="https://elasticsearch02.tau.ac.il:9200/"
$Elastic3URL="https://elasticsearch03.tau.ac.il:9200/"
$ElasticURL=$Elastic2URL

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
#Region InboundRule
$InboundRule='{
  "size": 100,
  "timeout": "240s",
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "event.type": "allowed"
          }
        },
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
                  "source.ip": "<ReqIPToChange>"
                }
              },
              {
                "term": {
                  "destination.ip": "<ReqIPToChange>"
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
#EndRegion InboundRule
#Region InboundRule2
$InboundRule2='{
  "size":10000,
  "query": {
      "bool":{
          "must":[
              {
                  "term":{
                      "destination.ip" :"<ReqIPToChange>"
                  }
              },
              {
                "term":{
                  "event.type": "allowed"
                }
            }               
          ],
          "must_not":[
            {
              "term":{
                "destination.port" : "0"
              }
            }
          ]
      }
  },
  "aggs":{
      "rule":{
          "terms":{
              "field":"rule.name",
              "size":10
          },
          "aggs":{
            "source":{
              "terms":{
                "field":"source.ip"
              },
              "aggs":{
                "port":{
                  "terms":{
                "field":"destination.port"
                  }
                }
              }
            }
          }

      }
  }
}'
#EndRegion InboundRule2
#Region InboundRule3
$InboundRule3='{
"size": 10000,
"timeout": "240s",
  "query": {
  "bool":{
    "must":[
    ],
    "filter": [
      {
        "match_phrase": {
          "destination.ip": "<ReqIPToChange>"
        }
      }
    ],   
    "must_not":[
      {
        "term":{
          "destination.port" : "0"
        }
      },
      {
        "term":{
          "destination.port" : "10050"
        }
      }

    ]
  }
}
}'
#EndRegion InboundRule3
#Region F5
$F5Rule='{
  "size": 100,
  "timeout": "240s",
    "query": {
    "bool":{
      "must":[
      ],
      "filter": [
        {
          "match_phrase": {
            "destination.ip": "<ReqIPToChange>"
          }
        },
        {
          "match_phrase": {
            "source.ip": "132.66.1.18"
          }
        }
      ]
    }
  }
  }'
#EndRegion F5
#Region F5Bis
$F5Rulebis='{
  "size": 100,
  "timeout": "240s",
    "query": {
    "bool":{
      "must":[],
      "filter": [
        {
          "bool": {
            "must": [],
            "filter": [
              {
                "match_phrase": {
                  "destination.ip": "<ReqIPToChange>"
                }
              },
              {
                "bool": {
                  "should": [
                    {
                      "bool": {
                        "must": [],
                        "filter": [
                          {
                            "match_phrase": {
                              "source.ip": "132.66.1.18"
                            }
                          }
                        ],
                        "should": [],
                        "must_not": []
                      }
                    },
                    {
                      "bool": {
                        "must": [],
                        "filter": [
                          {
                            "match_phrase": {
                              "source.ip": "132.66.1.36"
                            }
                          }
                        ],
                        "should": [],
                        "must_not": []
                      }
                    }
                  ],
                  "minimum_should_match": 1
                }
              }
            ],
            "should": [],
            "must_not": []
          }
        }
      ]
    }
  }
  }'
#EndRegion F5Bis
#Region F5Virt
$F5VirtRule='
{
  "size": 100,
  "timeout": "240s",
    "query": {
  "bool": {
    "should": [
      {
        "bool": {
          "must": [],
          "filter": [
            {
              "match_phrase": {
                "destination.ip": "<ReqIPToChange>"
              }
            },
            {
              "bool": {
                "should": [
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.1.12"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.1.13"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.1.18"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.1.20"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.1.26"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.1.28"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.1.34"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.1.36"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.11.159"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.12.229"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.18.31"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.3.248"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.251.195"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.118.67"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.117.14"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.225.131"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.7.21"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.7.229"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.3.188"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.251.3"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.225.195"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.251.67"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.251.131"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.251.196"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.21.4"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.118.68"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.118.196"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.21.196"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.21.132"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.225.132"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.67.4"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.117.15"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.11.1"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.12.1"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.18.1"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.3.249"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.118.195"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.67.3"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.21.131"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.7.228"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.7.22"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.21.195"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.3.189"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.251.4"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.225.196"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "match_phrase": {
                            "source.ip": "132.66.251.68"
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  },
                  {
                    "bool": {
                      "must": [],
                      "filter": [
                        {
                          "bool": {
                            "should": [
                              {
                                "bool": {
                                  "must": [],
                                  "filter": [
                                    {
                                      "match_phrase": {
                                        "source.ip": "132.66.21.3"
                                      }
                                    }
                                  ],
                                  "should": [],
                                  "must_not": []
                                }
                              },
                              {
                                "bool": {
                                  "must": [],
                                  "filter": [
                                    {
                                      "match_phrase": {
                                        "source.ip": "132.66.251.132"
                                      }
                                    }
                                  ],
                                  "should": [],
                                  "must_not": []
                                }
                              }
                            ],
                            "minimum_should_match": 1
                          }
                        }
                      ],
                      "should": [],
                      "must_not": []
                    }
                  }
                ],
                "minimum_should_match": 1
              }
            }
          ],
          "should": [],
          "must_not": []
        }
      }
    ]
  }
}
}
'
#EndRegion F5Virt
<#
,
      {
        "term":{
          "panw.panos.action" :"allow"
          }
      }
#>
#Region OutboundRule
$OutboundRule='
{
"size": 0,
"timeout": "240s",
"query": {
  "bool": {
    "filter": [
      {
        "term": {
          "event.type": "allowed"
        }
      },
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
                "source.ip": "<ReqIPToChange>"
              }
            },
            {
              "term": {
                "destination.ip": "<ReqIPToChange>"
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
#EndRegion OutboundRule
#Region OutboundRule2
$OutboundRule2='
{
  "size": 10000,
  "timeout": "240s",
  "query": {
  "bool": {
  "must": [],
  "filter":[
    {
      "term": {
        "event.type": "allowed"
      }
    },
    { 
      "term": {
        "source.ip": "<ReqIPToChange>"
      }
    }
    ]
  }
}
}
'
#EndRegion OutboundRule2
#Region MyJson
$MyJson='{
  "size": 100,
  "timeout": "240s",
  "query": {
  "bool": {
  "must": [
    { 
      "term": {
        "destination.ip": "<ReqIPToChange>"
      }
    },
    {
      "term": {
        "rule.name": "JokersInbound"
      }
    }
    ],
    "must_not":[
      {
        "term":{
          "destination.port" : "0"
        }
      },
      {
        "term":{
          "destination.port" : "10050"
        }
      }

    ]

  }
}
}'
#EndRegion MyJson
<#
$Data=@()
$CustomObject =[pscustomobject]@{
  size=10
  'Destination.ip'="132.66.254.11"
};
$Data+=$CustomObject
$MyJson=ConvertTo-Json -InputObject $data
#>

Write-Host -foregroundcolor Magenta "***Script beggin using URL:-$($ElasticURL)- with RuleMode:$($RuleMode)***"
If($ResolveType -eq "IPAddress"){$ReqInfo=$ReqIPAddress<#;$DNSName=Resolve -DnsName $ReqIPAddress#>}
ElseIf($ResolveType -eq "ServerName"){$ReqInfo= $ServerName}
Write-Host " ResolveType is:$($ResolveType), Use info:-$($ReqInfo)-"
$TelnetResult=Test-NetConnection $ReqInfo -port 1 -ErrorAction Continue
$ReqIPAddress=$TelnetResult.RemoteAddress
$ReqServerName=$TelnetResult.Computername
If([String]::IsNullOrEmpty($ReqIPAddress)){Write-Host -ForegroundColor Red " No IP Addresse for Server";Exit}
#$DNSName=Resolve-DnsName -Name $ServerName
#$ServerIP=$DNSName.IPAddress
Write-Host -ForegroundColor Cyan " Checking in rule mode:$RuleMode"
If($RuleMode -eq "JokerExist"){$JsonBody=$MyJSon -replace '<ReqIPToChange>',$ReqIPAddress}
ElseIf($RuleMode -eq "Inbound"){$JsonBody=$InboundRule3 -replace '<ReqIPToChange>',$ReqIPAddress}
ElseIf($RuleMode -eq "Outbound"){$JsonBody=$OutboundRule2 -replace '<ReqIPToChange>',$ReqIPAddress}
ElseIf($RuleMode -eq "f5"){$JsonBody=$F5VirtRule -replace '<ReqIPToChange>',$ReqIPAddress}
Else{$JsonBody=$MyJSon -replace '<ReqIPToChange>',$ReqIPAddress}
$ElBody1
$FullURL=$ElasticURL+"filebeat-palo-alto-*/_search"
Write-Host " Gathering Information from URL:-$FullURL-"
$ElastResult=Invoke-RestMethod -Method POST -Headers $ElasticToken -Uri $FullURL -ContentType 'application/json' -body $JsonBody # -ResponseHeadersVariable Results
If(![String]::IsNullOrEmpty($ElastResult.aggregations)){
  $FinalResults2=$ElastResult.aggregations.rule.buckets<#.source.buckets.port.buckets#>
  $FinalResults2.count
  If($FinalResults2.key -contains "JokersInbound"){Write-Host -ForegroundColor Green " Jokersinbound rule exist";$JokersRuleExist=$true}
  ElseIf($FinalResults2.key -contains "JokersOutbound"){Write-Host -ForegroundColor Green " Jokersoutbound rule exist";$JokersRuleExist=$true}
  Else{Write-Host -ForegroundColor Red " No JokersInbound Rule";$JokersRuleExist=$False}
  $FinalResults2 | Format-table @{Name="rule";Expression={($_.key)}},@{Name="source";Expression={($_.source.buckets.key)}},@{Name="port";Expression={($_.source.buckets.port.buckets.key)}} -Wrap <#-AutoSize source,rule,panw,destination -AutoSize#>
  $FinalResults2.source.buckets
  $FinalResults2.source.buckets.port.buckets

}
Else{
  $FinalResults=$ElastResult.hits.hits._source
  $FinalResults.count
  $DNSDestResIPResults=@()
  $DNSSrcResIPResults=@()
  $AllSourceIPs=$FinalResults.source.Ip | Select-Object -Unique | Sort-Object
  Write-Host " There are $($AllSourceIPs.Count) source ip addresses"
  $AllDestIPs=$FinalResults.destination.Ip | Select-Object -Unique | Sort-Object
  Write-Host " There are $($AllDestIPs.Count) destination ip addresses"
  If(!$Noresolve){
    $c=1
    ForEach($SourceIP in $AllSourceIPs){
      Write-Host " $c\$($AllSourceIPs.count) Source ip is:$($SourceIP)"
      If($SourceIP -eq $ReqIPAddress){$ResolveSourceName = $ReqServerName}
      ElseIf($SourceIP -in $DNSSrcResIPResults.IPAddress){Write-Host " -$($SourceIP)- dns name already resolved"}
      Else{
        $DNSSrcRes=Resolve-DnsName $SourceIP -ErrorAction SilentlyContinue -QuickTimeout
        If([string]::IsNullOrEmpty($DNSSrcRes)){$DNSSrcRes = New-Object PSObject
          $DNSSrcRes | Add-Member -NotePropertyName IPAddress -NotePropertyValue $SourceIP
          $DNSSrcRes | Add-Member -NotePropertyName Type -NotePropertyValue $null
          $DNSSrcRes | Add-Member -NotePropertyName Name -NotePropertyValue $null
          $DNSSrcRes | Add-Member -NotePropertyName NameHost -NotePropertyValue $null
          $DNSSrcRes | Add-Member -NotePropertyName Section -NotePropertyValue $null
          $DNSSrcRes | Add-Member -NotePropertyName TTL -NotePropertyValue $null
        }
        ElseIf([string]::IsNullOrEmpty($DNSSrcRes.IPAddress)){$DNSSrcRes | Add-Member -NotePropertyName IPAddress -NotePropertyValue $SourceIP}
        $DNSSrcResIPResults+=$DNSSrcRes
      }
      $c++
    }
  If(!$Noresolve){
    $d=1
    ForEach($DestIP in $AllDestIPs){
      $DNSDestRes=$null
      Write-Host " $d\$($AllDestIPs.count) Destination ip is:$($DestIP)"
      If($DestIP -eq $ReqIPAddress){$ResolveDestName = $ReqServerName}
      ElseIf($DestIP -in $DNSSrcResIPResults.IPAddress){Write-Host " -$($DestIP)- dns name already resolved"}
      Else{
        $DNSDestRes=Resolve-DnsName $DestIP -ErrorAction SilentlyContinue -QuickTimeout
        #$DNSDestRes
        If([string]::IsNullOrEmpty($DNSDestRes.Name)){<#Write-Host "  Dest name empty";#>$DNSDestRes = New-Object PSObject;$DNSDestRes | Add-Member -NotePropertyName IPAddress -NotePropertyValue $DestIP}
        ElseIf([string]::IsNullOrEmpty($DNSDestRes.IPAddress)){
          #Write-Host "  Dest IPAddress empty";
          #$DNSDestRes = New-Object PSObject
          $DNSDestRes | Add-Member -NotePropertyName IPAddress -NotePropertyValue $DestIP
          #$DNSDestRes | Add-Member -NotePropertyName Type -NotePropertyValue $null
          #$DNSDestRes | Add-Member -NotePropertyName Name -NotePropertyValue $null
          #$DNSDestRes | Add-Member -NotePropertyName NameHost -NotePropertyValue $Null
          #$DNSDestRes | Add-Member -NotePropertyName Section -NotePropertyValue $Null
          #$DNSDestRes | Add-Member -NotePropertyName TTL -NotePropertyValue $Null
        }
        $DNSDestResIPResults+=$DNSDestRes
      }
      $d++
    }
  }
}

  #$DNSSrcResIPResults | format-table *
  #$DNSDestResIPResults | format-table *
  #Pause
  #$FinalResults[0].destination.ip
  $F5Exist=$null
  If($RuleMode -ne "f5" -and $FinalResults.rule.name -contains "JokersInbound"){Write-Host -ForegroundColor Green " Jokersinbound rule exist";$JokersRuleExist=$true}
  ElseIf($RuleMode -ne "f5" -and $FinalResults.rule.name -contains "JokersOutbound"){Write-Host -ForegroundColor Green " Jokersoutbound rule exist";$JokersRuleExist=$true}
  Else{Write-Host -ForegroundColor Red " No JokersInbound or JokersOutBound Rule";$JokersRuleExist=$False}
  If($RuleMode -eq "f5" -and $FinalResults.source.ip.count -ne 0){Write-Host -ForegroundColor Green " F5 rule exist";$F5Exist="F5"}

  $FinalResultsTab=@()
  $i=1
  $DNSDestResolvesIP=@()
  $DNSDestResolvesIPResults=@()
  $DNSSourceResolvesIP=@()
  $DNSSourceResolvesIPResults=@()
  foreach($FinalResult in $FinalResults){
    #$FinalResult
    $ResolveDestName=$null
    $ResolveSourceName=$null
    $DNSDestResolvesIPResults
    If($FinalResult.destination.ip -eq $ReqIPAddress){$ResolveDestName = $ReqServerName}
    #ElseIf($FinalResult.destination.ip -in $DNSDestResolvesIP){<#Write-Host " -$($FinalResult.destination.ip)- dns name already resolved";#>$ResolveDestName = ($DNSDestResolvesIPResults|Where-object {$_.IPAddress -eq $FinalResult.destination.ip}).NameHost}
    Else{
      $ResolveDestName=($DNSDestResIPResults | Where-object {$_.IPAddress -eq $FinalResult.destination.ip}).NameHost
      #Write-Host " Resolve Destination Hostname is:$($ResolveDestName) for ip:$($FinalResult.destination.ip)"
    }
    If($FinalResult.source.ip -eq $ReqIPAddress){$ResolveSourceName = $ReqServerName}
    ElseIf($FinalResult.source.ip -in $DNSSourceResolvesIP){<#Write-Host " -$($FinalResult.source.ip)- dns name already resolved";#>$ResolveSourceName = ($DNSSourceResolvesIPResults|Where-object {$_.IPAddress -eq $FinalResult.source.ip}).NameHost}
    Else{
      $ResolveSourceName=($DNSSrcResIPResults | Where-object {$_.IPAddress -eq $FinalResult.source.ip}).NameHost
    }
    #$DNSSourceResolvesIPResults| fl *
    #$ResolveDest.NameHost
    #$ResolveSource=Resolve-DnsName $FinalResult.source.ip
    #Write-Host " $i ,Source: $($FinalResult.source.ip) ,rule: $($FinalResult.rule.name) ,Destination: $($FinalResult.destination.ip) ,port: $($FinalResult.destination.port) "
    $ObjFR = New-Object PSObject
    $ObjFR | Add-Member NoteProperty -Name "SourceIp" -Value $FinalResult.source.ip
        #If($RuleMode -eq "InboundRules"){$ObjFR | Add-Member NoteProperty -Name "SourceName" -Value $ServerName}
    #Else{$ResolveSource=Resolve-DnsName $FinalResult.source.ip
    #  $ObjFR | Add-Member NoteProperty -Name "SourceName" -Value $ResolveSource.NameHost}
    #$ResolveSource=Resolve-DnsName $FinalResult.source.ip -ErrorAction SilentlyContinue
    #$ObjFR | Add-Member NoteProperty -Name "Number" -Value $i
    $ObjFR | Add-Member NoteProperty -Name "SourceName" -Value $ResolveSourceName
    $ObjFR | Add-Member NoteProperty -Name "RuleName" -Value $FinalResult.rule.name
    $ObjFR | Add-Member NoteProperty -Name "RuleAction" -Value $FinalResult.event.type
    $ObjFR | Add-Member NoteProperty -Name "DestinationIP" -Value $FinalResult.destination.ip
    $ObjFR | Add-Member NoteProperty -Name "DestinationName" -Value $ResolveDestName
    $ObjFR | Add-Member NoteProperty -Name "DestinationPort" -Value $FinalResult.destination.port
    $ObjFR | Add-Member NoteProperty -Name "Timestamp" -Value $FinalResult.'@Timestamp'
    $ObjFR | Add-Member NoteProperty -Name "SourceUserName" -Value $FinalResult.source.user.name
    #$ObjFR
    
    If($ObjFR.RuleName -like "*joker*"){
      #Write-Host " Joker rule:"
      #If(){}
    }
    $FinalResultsTab+=$ObjFR
    #ForEach($FinalResult
    $i++
  }
  If($RuleMode -eq "OutBound"){
    $FinalResultsTab| Where-Object {$_.RuleAction -eq "allowed"} | Sort-Object RuleName,DestinationPort,DestinationIp,Timestamp | get-Unique -AsString | Format-Table
    $FinalResultsTab | Where-Object {$_.RuleAction -eq "allowed"}| Group-Object DestinationIp,DestinationName,DestinationPort,RuleName, SourceUse | Sort-Object Count -Descending | Format-Table -AutoSize
  }
  Else{
    $FinalResultsTab| Where-Object {$_.RuleAction -eq "allowed"} | Sort-Object RuleName,SourceIp,DestinationPort,Timestamp | get-Unique -AsString | Format-Table
    $FinalResultsTab | Where-Object {$_.RuleAction -eq "allowed"}| Group-Object SourceIp,SourceName,DestinationPort,RuleName,SourceUserName | Sort-Object Count -Descending | Format-Table -AutoSize
    #$FinalResultsTab| Where-Object {$_.RuleAction -eq "allow" -and $_.Timestamp -ge (Get-Date).AddDays(-3)} | Sort-Object RuleName,SourceIp,DestinationPort,Timestamp | get-Unique -AsString | Format-Table

  }
  #($FinalResults| Format-table @{Name="sourceIP";Expression={($_.source.ip)}},@{Name="ruleName";Expression={($_.rule.name)}},@{Name="destinationIP";Expression={($_.destination.ip)}},@{Name="destinationPort";Expression={($_.destination.port)}} | Group ruleName)
  #$FinalResults.rule.name | Select-Object -unique 
}
#$FinalResults=$ElastResult.aggregations.by_source.buckets.by_destination.buckets.by_port.buckets
<#If($FinalResults2.rule.name -contains "JokersInbound"){Write-Host -ForegroundColor Green " Jokersinbound rule exist";$JokersRuleExist=$true}
ElseIf($FinalResults.rule.name -contains "JokersOutbound"){Write-Host -ForegroundColor Green " Jokersoutbound rule exist";$JokersRuleExist=$true}
Else{Write-Host -ForegroundColor Red " No JokersInbound Rule";$JokersRuleExist=$False}
#>
if($RuleMode -eq "f5"){Return $F5Exist}
Else{Return $JokersRuleExist}
#$Result.hits.hits._source