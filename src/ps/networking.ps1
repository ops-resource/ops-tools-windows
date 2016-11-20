<#
    .SYNOPSIS

    Gets the IP addresses of the DNS servers that are registered with the current machine.


    .DESCRIPTION

    The Get-DnsServerIPAddressesFromCurrentMachine function gets the IP addresses of the DNS servers that are registered with the current machine


    .OUTPUTS

    An array containing the IP addresses for the DNS servers as registered with the current machine.
#>
function Get-DnsServerIPAddressesFromCurrentMachine
{
    [CmdletBinding()]
    param(
    )

    $ErrorActionPreference = 'Stop'

    $commonParameterSwitches =
        @{
            Verbose = $PSBoundParameters.ContainsKey('Verbose');
            Debug = $false;
            ErrorAction = 'Stop'
        }

    # Find the IP addresses for the DNS of the current machine
    $params = @{
        "Class" = "Win32_NetworkAdapterConfiguration"
        "Filter" = "IPEnabled=True"
    }

    $dnsIPAddresses = Get-WmiObject @params @commonParameterSwitches |
        Where-Object { $_.IPAddress -match '(\d{1,3}\.){3}\d{1,3}' } |
        Select-Object -ExpandProperty DNSServerSearchOrder

    return $dnsIPAddresses
}
