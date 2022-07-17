function Get-RemoteAccessServiceCreation{
<#
    .SYNOPSIS
        Parses the the offline Windows System log for the service installations of TeamViewer, AnyDesk, and ConnectWise. The returned data will include the timestamp, 
        name of service, and executable associated with it.

    .PARAMETER logFile
        Location to offline Windows System log.

    .EXAMPLE
        Get-RemoteAccessServiceCreation -logfile c:\windows_system.evtx

        Parses C:windows_system.evtx log and returns applicable data.
#>
    
    [CmdletBinding()]
    param(
        $logfile
    )    
    
    Get-WinEvent -FilterHashtable @{path="$logfile"; id='7045'} | 
        where-object{$_.message -match "anydesk" -or $_.message -match "teamviewer" -or $_.message -match "screenconnect"} | 
            Select-Object timecreated, 
                ProcessID,
                @{Label="ServiceName";Expression={$_.properties.value[0]}}, 
                @{Label="ServiceFileName";Expression={$_.properties.value[1]}}, 
                @{Label="ServiceType";Expression={$_.properties.value[2]}}, 
                @{Label="ServiceStartupType";Expression={$_.properties.value[3]}}, 
                @{Label="ServiceAccount";Expression={$_.properties.value[4]}} | format-table
}