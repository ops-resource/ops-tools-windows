<#
    .SYNOPSIS

    Copies a file to the given remote path on the machine that the session is connected to.


    .DESCRIPTION

    The Copy-ItemToRemoteMachine function copies a local file to the given remote path on the machine that the session is connected to.


    .PARAMETER localPath

    The full path of the file that should be copied.


    .PARAMETER remotePath

    The full file path to which the local file should be copied


    .PARAMETER session

    The PSSession that provides the connection between the local machine and the remote machine.


    .EXAMPLE

    Copy-ItemToRemoteMachine -localPath 'c:\temp\myfile.txt' -remotePath 'c:\remote\myfile.txt' -session $session
#>
function Copy-ItemToRemoteMachine
{
    [CmdletBinding()]
    param(
        [string] $localPath,
        [string] $remotePath,
        [System.Management.Automation.Runspaces.PSSession] $session
    )

    Write-Verbose "Copy-ItemToRemoteMachine - localPath: $localPath"
    Write-Verbose "Copy-ItemToRemoteMachine - remotePath: $remotePath"
    Write-Verbose "Copy-ItemToRemoteMachine - session: $($session.Name)"

    # Use .NET file handling for speed
    $content = [Io.File]::ReadAllBytes( $localPath )
    $contentsizeMB = $content.Count / 1MB + 1MB

    Write-Output "Copying $fileName from $localPath to $remotePath on $($session.Name) ..."

    # Open local file
    $wasSuccessful = $true
    try
    {
        try
        {
            [IO.FileStream]$filestream = [IO.File]::OpenRead( $localPath )
            Write-Output "Opened local file for reading"
        }
        catch
        {
            Write-Error "Could not open local file $localPath because: $($_.Exception.ToString())"
            Return $false
        }

        # Open remote file
        try
        {
            Invoke-Command `
                -Session $Session `
                -ScriptBlock {
                    param(
                        $remFile
                    )

                    $dir = Split-Path -Parent $remFile
                    if (-not (Test-Path $dir))
                    {
                        New-Item -Path $dir -ItemType Directory
                    }

                    [IO.FileStream]$filestream = [IO.File]::OpenWrite( $remFile )
                } `
                -ArgumentList $remotePath
            Write-Output "Opened remote file for writing"
        }
        catch
        {
            Write-Error "Could not open remote file $remotePath because: $($_.Exception.ToString())"
            Return $false
        }

        # Copy file in chunks
        $chunksize = 1MB
        [byte[]]$contentchunk = New-Object byte[] $chunksize
        $bytesread = 0
        while (($bytesread = $filestream.Read( $contentchunk, 0, $chunksize )) -ne 0)
        {
            try
            {
                $percent = $filestream.Position / $filestream.Length
                Write-Output ("Copying {0}, {1:P2} complete, sending {2} bytes" -f $fileName, $percent, $bytesread)
                Invoke-Command -Session $Session -ScriptBlock {
                    Param($data, $bytes)
                    $filestream.Write( $data, 0, $bytes )
                } -ArgumentList $contentchunk,$bytesread
            }
            catch
            {
                Write-Error "Could not copy $fileName to $($Connection.Name) because: $($_.Exception.ToString())"
                return $false
            }
            finally
            {
            }
        }
    }
    finally
    {
        # Close remote file
        try
        {
            Invoke-Command -Session $Session -ScriptBlock {
                if ($fileStream -ne $null)
                {
                    $filestream.Close()
                }
            }
            Write-Output "Closed remote file, copy complete"
        }
        catch
        {
            Write-Error "Could not close remote file $remotePath because: $($_.Exception.ToString())"
            $wasSuccessful = $false
        }

        # Close local file
        try
        {
            if ($fileStream -ne $null)
            {
                $filestream.Close()
            }
            Write-Output "Closed local file, copy complete"
        }
        catch
        {
            Write-Error "Could not close local file $localPath because: $($_.Exception.ToString())"
            $wasSuccessful = $false
        }
    }

    return $wasSuccessful
}

function Read-FromRemoteStream
{
    param(
        [System.Management.Automation.Runspaces.PSSession] $session,
        [int] $chunkSize
    )

    try
    {
        $data = Invoke-Command `
            -Session $Session `
            -ScriptBlock {
                Param(
                    $size
                )

                [byte[]]$contentchunk = New-Object byte[] $size
                $bytesread = $filestream.Read( $contentchunk, 0, $size )

                $result = New-Object PSObject
                Add-Member -InputObject $result -MemberType NoteProperty -Name BytesRead -Value $BytesRead
                Add-Member -InputObject $result -MemberType NoteProperty -Name Chunk -Value $contentchunk

                return $result
            } `
            -ArgumentList $chunkSize

        return $data
    }
    catch
    {
        Write-Error "Could not copy $fileName to $($Connection.Name) because: $($_.Exception.ToString())"
        return -1
    }
}

<#
    .SYNOPSIS

    Copies a file from the given remote path on the machine that the session is connected to.


    .DESCRIPTION

    The Copy-ItemFromRemoteMachine function copies a remote file to the given local path on the machine that the session is connected to.


    .PARAMETER remotePath

    The full file path from which the local file should be copied


    .PARAMETER localPath

    The full path of the file to which the file should be copied.


    .PARAMETER session

    The PSSession that provides the connection between the local machine and the remote machine.


    .EXAMPLE

    Copy-ItemFromRemoteMachine -remotePath 'c:\remote\myfile.txt' -localPath 'c:\temp\myfile.txt' -session $session
#>
function Copy-ItemFromRemoteMachine
{
    [CmdletBinding()]
    param(
        [string] $remotePath,
        [string] $localPath,
        [System.Management.Automation.Runspaces.PSSession] $session
    )

    Write-Verbose "Copy-ItemFromRemoteMachine - remotePath: $remotePath"
    Write-Verbose "Copy-ItemFromRemoteMachine - localPath: $localPath"
    Write-Verbose "Copy-ItemFromRemoteMachine - session: $($session.Name)"
    Write-Output "Copying $fileName from $remotePath to $localPath on $($session.Name) ..."

    # Open local file
    $wasSuccessful = $true
    try
    {
        try
        {
            $localDir = Split-Path -Parent $localPath
            if (-not (Test-Path $localDir))
            {
                New-Item -Path $localDir -ItemType Directory | Out-Null
            }

            [IO.FileStream]$filestream = [IO.File]::OpenWrite( $localPath )
            Write-Output "Opened local file for writing"
        }
        catch
        {
            Write-Error "Could not open local file $localPath because: $($_.Exception.ToString())"
            Return $false
        }

        # Open remote file
        try
        {
            Invoke-Command -Session $Session -ScriptBlock {
                Param($remFile)
                [IO.FileStream]$filestream = [IO.File]::OpenRead( $remFile )
            } -ArgumentList $remotePath
            Write-Output "Opened remote file for reading"
        }
        catch
        {
            Write-Error "Could not open remote file $remotePath because: $($_.Exception.ToString())"
            Return $false
        }

        # Copy file in chunks
        $chunksize = 1MB
        $data = $null
        while (($data = Read-FromRemoteStream $session $chunksize ).BytesRead -ne 0)
        {
            try
            {
                Write-Output ("Copying {0}, receiving {1} bytes" -f $fileName, $data.BytesRead)
                $fileStream.Write( $data.Chunk, 0, $data.BytesRead)
            }
            catch
            {
                Write-Error "Could not copy $fileName from $($Connection.Name) because: $($_.Exception.ToString())"
                return $false
            }
            finally
            {
            }
        }
    }
    finally
    {
        # Close local file
        try
        {
            if ($fileStream -ne $null)
            {
                $filestream.Close()
            }
            Write-Output "Closed local file, copy complete"
        }
        catch
        {
            Write-Error "Could not close local file $localPath because: $($_.Exception.ToString())"
            $wasSuccessful = $false
        }

        # Close remote file
        try
        {
            Invoke-Command -Session $Session -ScriptBlock {
                if ($fileStream -ne $null)
                {
                    $filestream.Close()
                }
            }
            Write-Output "Closed remote file, copy complete"
        }
        catch
        {
            Write-Error "Could not close remote file $remotePath because: $($_.Exception.ToString())"
            $wasSuccessful = $false
        }
    }

    return $wasSuccessful
}

<#
    .SYNOPSIS

    Copies a set of files to a remote directory on a given remote machine.


    .DESCRIPTION

    The Copy-FilesToRemoteMachine function copies a set of files to a remote directory on a given remote machine.


    .PARAMETER session

    The PSSession that provides the connection between the local machine and the remote machine.


    .PARAMETER remoteDirectory

    The full path to the remote directory into which the files should be copied. Defaults to 'c:\installers'


    .PARAMETER filesToCopy

    The collection of local files that should be copied.


    .EXAMPLE

    Copy-FilesToRemoteMachine -session $session -remoteDirectory 'c:\temp' -filesToCopy (Get-ChildItem c:\temp -recurse)
#>
function Copy-FilesToRemoteMachine
{
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession] $session,
        [string] $remoteDirectory = "c:\installers",
        [string] $localDirectory
    )

    Write-Verbose "Copy-FilesToRemoteMachine - session: $($session.Name)"
    Write-Verbose "Copy-FilesToRemoteMachine - remoteDirectory: $remoteDirectory"
    Write-Verbose "Copy-FilesToRemoteMachine - localDirectory: $localDirectory"

    # Stop everything if there are errors
    $ErrorActionPreference = 'Stop'

    $commonParameterSwitches =
        @{
            Verbose = $PSBoundParameters.ContainsKey('Verbose');
            Debug = $false;
            ErrorAction = "Stop"
        }

    $filesToCopy = Get-ChildItem -Path $localDirectory -Recurse -Force @commonParameterSwitches |
        Where-Object { -not $_.PsIsContainer } |
        Select-Object -ExpandProperty FullName

    # Push binaries to the new VM
    Write-Verbose "Copying files to remote resource: $filesToCopy"
    foreach($fileToCopy in $filesToCopy)
    {
        $relativePath = $fileToCopy.SubString($localDirectory.Length)
        $remotePath = Join-Path $remoteDirectory $relativePath

        Write-Verbose "Copying $fileToCopy to $remotePath"
        Copy-ItemToRemoteMachine -localPath $fileToCopy -remotePath $remotePath -session $session @commonParameterSwitches
    }
}

<#
    .SYNOPSIS

    Copies a set of files from a remote directory on a given remote machine.


    .DESCRIPTION

    The Copy-FilesFromRemoteMachine function copies a set of files from a remote directory on a given remote machine.


    .PARAMETER session

    The PSSession that provides the connection between the local machine and the remote machine.


    .PARAMETER remoteDirectory

    The full path to the remote directory from which the files should be copied. Defaults to 'c:\logs'


    .PARAMETER localDirectory

    The full path to the local directory into which the files should be copied.


    .EXAMPLE

    Copy-FilesFromRemoteMachine -session $session -remoteDirectory 'c:\temp' -localDirectory 'c:\temp'
#>
function Copy-FilesFromRemoteMachine
{
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession] $session,
        [string] $remoteDirectory = "c:\logs",
        [string] $localDirectory
    )

    Write-Verbose "Copy-FilesFromRemoteMachine: session: $($session.Name)"
    Write-Verbose "Copy-FilesFromRemoteMachine: remoteDirectory: $remoteDirectory"
    Write-Verbose "Copy-FilesFromRemoteMachine: localDirectory: $localDirectory"

    # Stop everything if there are errors
    $ErrorActionPreference = 'Stop'

    $commonParameterSwitches =
        @{
            Verbose = $PSBoundParameters.ContainsKey('Verbose');
            Debug = $false;
            ErrorAction = "Stop"
        }

    # Create the directory on the local machine
    if (-not (Test-Path $localDirectory))
    {
        New-Item -Path $localDirectory -ItemType Directory
    }

    # Create the installer directory on the virtual machine
    $remoteFiles = Invoke-Command `
        -Session $session `
        -ArgumentList @( $remoteDirectory ) `
        -ScriptBlock {
            param(
                [string] $dir
            )

            Write-Verbose "Searching for files to copy in: $dir"
            return Get-ChildItem -Path $dir -Recurse -Force |
                Where-Object { -not $_.PsIsContainer } |
                Select-Object -ExpandProperty FullName
        } `
         @commonParameterSwitches

    # Push binaries to the new VM
    Write-Verbose "Copying files from the remote resource: $remoteFiles"
    foreach($fileToCopy in $remoteFiles)
    {
        $relativePath = $fileToCopy.SubString($remoteDirectory.Length)
        $localPath = Join-Path $localDirectory $relativePath

        Write-Verbose "Copying $fileToCopy to $localPath"
        Copy-ItemFromRemoteMachine -localPath $localPath -remotePath $fileToCopy -Session $session @commonParameterSwitches
    }
}

<#
    .SYNOPSIS

    Removes a directory on the given remote machine.


    .DESCRIPTION

    The Remove-FilesFromRemoteMachine function removes a directory on the given remote machine.


    .PARAMETER session

    The PSSession that provides the connection between the local machine and the remote machine.


    .PARAMETER remoteDirectory

    The full path to the remote directory that should be removed


    .EXAMPLE

    Remove-FilesFromRemoteMachine -session $session -remoteDirectory 'c:\temp'
#>
function Remove-FilesFromRemoteMachine
{
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession] $session,
        [string] $remoteDirectory = "c:\logs"
    )

    Write-Verbose "Remove-FilesFromRemoteMachine: session: $($session.Name)"
    Write-Verbose "Remove-FilesFromRemoteMachine: remoteDirectory: $remoteDirectory"

    # Stop everything if there are errors
    $ErrorActionPreference = 'Stop'

    $commonParameterSwitches =
        @{
            Verbose = $PSBoundParameters.ContainsKey('Verbose');
            Debug = $false;
            ErrorAction = "Stop"
        }

    # Create the installer directory on the virtual machine
    Invoke-Command `
        -Session $session `
        -ArgumentList @( $remoteDirectory ) `
        -ScriptBlock {
            param(
                [string] $dir
            )

            if (Test-Path $dir)
            {
                Remove-Item -Path $dir -Force -Recurse
            }
        } `
         @commonParameterSwitches
}

<#
    .SYNOPSIS

    Waits for the WinRM service on a remote computer to start.


    .DESCRIPTION

    The Wait-WinRM function waits for the WinRM service on a remote computer to start.


    .PARAMETER computerName

    The name of the remote computer.


    .PARAMETER credential

    The credential required to connect to the remote computer.


    .PARAMETER timeOutInSeconds

    The maximum amount of time in seconds that this function will wait for the WinRM service
    on the remote computer to start.


    .EXAMPLE

    Remove-FilesFromRemoteMachine -session $session -remoteDirectory 'c:\temp'
#>
function Wait-WinRM
{
    [cmdletbinding()]
    param
    (
        [Parameter(ParameterSetName = 'FromName')]
        [string] $computerName,

        [Parameter(ParameterSetName = 'FromIP')]
        [string] $ipAddress,

        [Parameter()]
        [System.Management.Automation.PSCredential] $credential = $null,

        [Parameter()]
        [ValidateScript({$_ -ge 1 -and $_ -le [system.int64]::maxvalue})]
        [int] $timeOutInSeconds = 900 #seconds
    )

    Write-Verbose "Wait-WinRM - computerName = $computerName"
    Write-Verbose "Wait-WinRM - ipAddress = $ipAddress"
    Write-Verbose "Wait-WinRM - credential = $credential"
    Write-Verbose "Wait-WinRM - timeOutInSeconds = $timeOutInSeconds"

    $ErrorActionPreference = 'Stop'

    $commonParameterSwitches =
        @{
            Verbose = $PSBoundParameters.ContainsKey('Verbose');
            Debug = $false;
        }

    $name = ''
    switch ($psCmdlet.ParameterSetName)
    {
        'FromName' {
            $name = $computerName
        }

        'FromIP' {
            $name = $ipAddress
        }
    }

    process
    {
        $startTime = Get-Date
        $endTime = ($startTime) + (New-TimeSpan -Seconds $timeOutInSeconds)

        # Ignore all errors because we're expecting a fair few of them if we connect to a machine
        # that isn't ready for the connection
        $originalErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        try
        {
            while ($true)
            {
                if ((Get-Date) -ge $endTime)
                {
                    Write-Verbose "Failed to connect to $name in the alotted time of $timeOutInSeconds"
                    return $false
                }

                Write-Verbose "Trying to connect to $name [total wait time so far: $((Get-Date) - $startTime)] ..."
                $inverr = $null
                try
                {
                    if ($credential)
                    {
                        Invoke-Command `
                            -ComputerName $name `
                            -ScriptBlock { Get-Process } `
                            -Credential $credential `
                            -ErrorAction SilentlyContinue `
                            -ErrorVariable inverr `
                            @commonParameterSwitches | Out-Null
                    }
                    else
                    {
                        Invoke-Command `
                            -ComputerName $name `
                            -ScriptBlock { Get-Process } `
                            -ErrorAction SilentlyContinue `
                            -ErrorVariable inverr `
                            @commonParameterSwitches | Out-Null
                    }

                    if ($inverr -eq $null)
                    {
                        Write-Verbose "Connection to $name successful."
                        return $true
                    }
                }
                catch
                {
                    # Ignore everything ...
                    Write-Verbose "Could not connect to $name. Error was $($_.Exception.Message)"
                }

                Start-Sleep -seconds 5
            }
        }
        finally
        {
            $ErrorActionPreference = $originalErrorActionPreference
        }

        Write-Error "Waiting for $name failed outside the normal failure paths."
    }
}