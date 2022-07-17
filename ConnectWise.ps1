
function Get-CWConnections{
<#
    .SYNOPSIS
        Parses the the offline Windows Application log for ConnectWise connections. 

    .PARAMETER logFile
        Location to offline Windows Application log.

    .EXAMPLE
        Get-CWConnections -logfile c:\windows_application.evtx

        Parses C:windows_application.evtx log and returns applicable data.
#>
    
    [CmdletBinding()]
    param(
        $logfile
    )   

    $logs = Get-WinEvent -FilterHashtable @{path="$logfile"; id='0'; providername ='ScreenConnect Client*'} 
    $obj = @()
    $obj = foreach($log in $logs){
        if($log.message -match "connected" -and $log.message -notmatch "party did not"){
            [pscustomobject]@{
                Timestamp = $log.timecreated
                Action = $log.Message
            }
        }
    }
    $obj
}

function Get-CWFileTransfer{
<#
    .SYNOPSIS
        Parses the the offline Windows Application log for Connectwise file transfers to the system. 

    .PARAMETER logFile
        Location to offline Windows Application log.

    .EXAMPLE
        Get-CWConnections -logfile c:\windows_application.evtx

        Parses C:windows_application.evtx log and returns applicable data.
#>
    
    [CmdletBinding()]
    param(
        $logfile
    )  
   
    $logs = Get-WinEvent -FilterHashtable @{path="$logfile"; id='0'; providername ='ScreenConnect Client*'} 
    $obj = @()
    $obj = foreach($log in $logs){
        if($log.message -match "transferred files"){
            [pscustomobject]@{
                Timestamp = $log.timecreated
                Action = $log.Message
            }
        }
    }
    $obj
}

function Get-CWExecutedCommands{
<#
    .SYNOPSIS
        Parses the the offline Windows Application log for executed command via ConnectWise. 

    .PARAMETER logFile
        Location to offline Windows Application log.

    .EXAMPLE
        Get-CWConnections -logfile c:\windows_application.evtx

        Parses C:windows_application.evtx log and returns applicable data.
#>
    
    [CmdletBinding()]
    param(
        $logfile
    )  

    $logs = Get-WinEvent -FilterHashtable @{path="$logfile"; id='0'; providername ='ScreenConnect Client*'} 
    $obj = @()
    $obj = foreach($log in $logs){
        $potentialAction =''
        if($log.message -match "executed command of length: 657"){
            $potentialAction = "Process list"
        }
        elseif($log.message -match "executed command of length: 861"){
            $potentialAction = "Software list"
        }
        elseif($log.message -match "executed command of length: 492"){
            $potentialAction = "Event log list"
        }
        elseif($log.message -match "executed command of length: 460"){
            $potentialAction = "Service list"
        }
        elseif($log.message -match "executed command of length: 725"){
            $potentialAction = "Updates list"
        }
        elseif($log.message -match "executed command"){
            $potentialAction = "-"
        }
        if($potentialAction.Length -ne 0){
            [pscustomobject]@{
                Timestamp = $log.timecreated
                Action = $log.Message
                PotentialAction = $potentialAction
            }
        }
        if($log.message -match "transferred files"){
            [pscustomobject]@{
                Timestamp = $log.timecreated
                Action = $log.Message
            }
        }
    }
    $obj
}

function Get-CWTimeline{
<#
    .SYNOPSIS
        Parses the the offline Windows Application log and builds a timeline of ConnectWise activity. 

    .PARAMETER logFile
        Location to offline Windows Application log.

    .EXAMPLE
        Get-CWConnections -logfile c:\windows_application.evtx

        Parses C:windows_application.evtx log and returns applicable data.
#>
    
    [CmdletBinding()]
    param(
        $logfile
    )  

    $logs = Get-WinEvent -FilterHashtable @{path="$logfile"; id='0'; providername ='ScreenConnect Client*'} 
    $obj = @()
    $obj = foreach($log in $logs){
        $potentialAction = ''
        if($log.message -match "executed command of length: 657"){
            $potentialAction = "Process list"
        }
        elseif($log.message -match "executed command of length: 861"){
            $potentialAction = "Software list"
        }
        elseif($log.message -match "executed command of length: 492"){
            $potentialAction = "Event log list"
        }
        elseif($log.message -match "executed command of length: 460"){
            $potentialAction = "Service list"
        }
        elseif($log.message -match "executed command of length: 725"){
            $potentialAction = "Updates list"
        }
        elseif(($log.message -match "connected" -or $log.message -match "executed command" -or $log.message -match "transferred files") -and $log.message -notmatch "party did not"){
            $potentialAction = "-"
        }
        if($potentialAction.Length -ne 0){
            [pscustomobject]@{
                Timestamp = $log.timecreated
                Action = $log.Message
                PotentialAction = $potentialAction
            }
        }
    }
    $obj
}

function Get-CWConnectDurations{
<#
    .SYNOPSIS
        Parses the the offline Windows Application log and returns connections to the system via ConnectWise and the duration. 

    .PARAMETER logFile
        Location to offline Windows Application log.

    .EXAMPLE
        Get-CWConnections -logfile c:\windows_application.evtx

        Parses C:windows_application.evtx log and returns applicable data.
#>
    
    [CmdletBinding()]
    param(
        $logfile
    )  

    $logs = Get-WinEvent -FilterHashtable @{path="$logfile"; id='0'; providername ='ScreenConnect Client*'} | where-object{$_.message -match "connected" -and $_.message -notmatch "party did not"}
    $obj = @()
    if($logs[0] -notmatch " connected"){
        $obj = foreach($log in $logs){
            if($logs.IndexOf($log) % 2 -eq 0){
                $span = New-TimeSpan -Start $logs[($logs.IndexOf($log) + 1)].timecreated -End $log.TimeCreated
                [pscustomobject]@{
                    Connection = $logs[($logs.IndexOf($log) + 1)].timecreated 
                    Disconnection = $log.TimeCreated
                    Duration = [string]$span.days + "D" + [string]$span.hours + "H" + [string]$span.Minutes + "M" + [string]$span.Seconds + "S"
                }  
            }
        }
    }
    elseif($logs[0] -match " connected"){
        $obj = foreach($log in $logs){
            if($logs.IndexOf($log) % 2 -eq 0){
                $span = New-TimeSpan -Start $log.TimeCreated -End $logs[($logs.IndexOf($log) + 1)].timecreated 
                [pscustomobject]@{
                    Connection = $log.TimeCreated 
                    Disconnection = $logs[($logs.IndexOf($log) + 1)].timecreated 
                    Duration = [string]$span.days + "D" + [string]$span.hours + "H" + [string]$span.Minutes + "M" + [string]$span.Seconds + "S"
                }  
            }
        }
    }
    $obj | Sort-Object connection
}
