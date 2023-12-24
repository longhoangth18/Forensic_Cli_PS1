function Get-ProcessDlls {
    param (
        [Parameter(Mandatory=$true)]
        [int]$ProcessId,
        [Parameter(Mandatory=$true)]
        [string]$OutputCSV,
        [Parameter(Mandatory=$true)]
        [string]$OutputJSON
    )

    # Use WMI to get information about the specified process and its associated DLLs
    $query = "SELECT * FROM Win32_Process WHERE ProcessId = $ProcessId"
    $process = Get-WmiObject -Query $query

    if ($process -ne $null) {
        # Retrieve associated DLLs using WMI
        $query = "ASSOCIATORS OF {$($process.__RELPATH)} WHERE ResultClass = CIM_DataFile"
        $dlls = Get-WmiObject -Query $query

        # Create an array to store DLL information
        $dllInfoArray = @()

        if ($dlls -ne $null) {
            foreach ($dll in $dlls) {
                # Extract information about the DLL
                $dllPath = $dll.Name
                $dllSizeKB = [math]::Round(($dll.FileSize / 1KB), 2)
                $dllHashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
                $dllFileStream = [System.IO.File]::OpenRead($dllPath)
                $dllHashBytes = $dllHashAlgorithm.ComputeHash($dllFileStream)
                $dllHash = [System.BitConverter]::ToString($dllHashBytes) -replace '-'
                $dllFileStream.Close()

                # Construct an object with DLL information
                $dllInfo = [PSCustomObject]@{
                    "DLLPath"   = $dllPath
                    "DLLSizeKB" = $dllSizeKB
                    "DLLHash"   = $dllHash
                }

                # Add DLL information to the array
                $dllInfoArray += $dllInfo
            }
        }

        # Construct an object with detailed information for JSON
        $jsonInfo = [PSCustomObject]@{
            "Process" = @{
                "Name"            = $process.Name
                "ID"              = $ProcessId
                "CreationDate"    = $process.CreationDate
                "CommandLine"     = $process.CommandLine
                "Executable"      = @{
                    "Path"   = if ($process.ExecutablePath -ne $null) { $process.ExecutablePath } else { "N/A" }
                    "SizeKB" = if ($process.ExecutablePath -ne $null) {
                        $fileStream = [System.IO.File]::OpenRead($process.ExecutablePath)
                        [math]::Round(($fileStream.Length / 1KB), 2)
                    } else { 0 }
                    "Hash"   = if ($process.ExecutablePath -ne $null) {
                        (Get-FileHash -Path $process.ExecutablePath -Algorithm SHA256).Hash
                    } else { "N/A" }
                }
                "WorkingSetSizeKB" = [math]::Round(($process.WorkingSetSize / 1KB), 2)
                "Description"     = $process.Description
                "Parent"          = @{
                    "Name" = $null
                    "ID"   = $null
                }
                "Hash"            = $null
                "DLLs"            = $dllInfoArray  # Include DLL information
            }
        }

        # If there's a parent process, include its information
        $parentProcessId = $process.ParentProcessId
        if ($parentProcessId -ne $null) {
            $parentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $parentProcessId"
            if ($parentProcess -ne $null) {
                $jsonInfo.Process.Parent.Name = $parentProcess.Name
                $jsonInfo.Process.Parent.ID   = $parentProcessId
            }
        }

        # Calculate and include the hash of the entire process
        $processBytes = [System.Text.Encoding]::UTF8.GetBytes($process.Name)
        $processHashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
        $processHashBytes = $processHashAlgorithm.ComputeHash($processBytes)
        $jsonInfo.Process.Hash = [System.BitConverter]::ToString($processHashBytes) -replace '-'

        # Write information to CSV
        $csvInfo = [PSCustomObject]@{
            "Process Name"        = $process.Name
            "Process ID"          = $ProcessId
            "Creation Date"       = $process.CreationDate
            "Command Line"        = $process.CommandLine
            "Executable Path"     = if ($process.ExecutablePath -ne $null) { $process.ExecutablePath } else { "N/A" }
            "Executable Size (KB)"= if ($process.ExecutablePath -ne $null) {
                $fileStream = [System.IO.File]::OpenRead($process.ExecutablePath)
                [math]::Round(($fileStream.Length / 1KB), 2)
            } else { 0 }
            "Executable Hash"     = if ($process.ExecutablePath -ne $null) {
                (Get-FileHash -Path $process.ExecutablePath -Algorithm SHA256).Hash
            } else { "N/A" }
            "Working Set Size (KB)"= [math]::Round(($process.WorkingSetSize / 1KB), 2)
            "Description"         = $process.Description
            "Parent Process Name" = $jsonInfo.Process.Parent.Name
            "Parent Process ID"   = $jsonInfo.Process.Parent.ID
            "Process Hash"        = $jsonInfo.Process.Hash
            "DLL Path"            = $dllInfoArray.DLLPath -join ";"
            "DLL Size (KB)"       = $dllInfoArray.DLLSizeKB -join ";"
            "DLL Hash"            = $dllInfoArray.DLLHash -join ";"
        }
        $csvInfo | Export-Csv -Path $OutputCSV -Append -Force -NoTypeInformation

        # Write information to JSON
        $jsonInfo | ConvertTo-Json | Out-File -Append -FilePath $OutputJSON -Encoding UTF8

        # Display information about the loaded DLLs
        $dllInfoArray | ForEach-Object {
            $dllInfoString = "Process: $($process.Name) Load DLLPath: $($_.DLLPath)"
            Write-Host $dllInfoString -ForegroundColor Cyan
        }
    }
}

function Monitor-Processes {
    param (
        [string]$OutputCSV = "ProcessInfo.csv",
        [string]$OutputJSON = "ProcessInfo.json"
    )

    # Hashtable to track processed IDs
    $trackedProcesses = @{}

    while ($true) {
        try {
            # Get information about all running processes
            $newProcesses = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $null }

            foreach ($process in $newProcesses) {
                $processId = $process.ProcessId

                if (-not $trackedProcesses.ContainsKey($processId)) {
                    # Mark the process as tracked
                    $trackedProcesses[$processId] = $true

                    # Display separator and basic process information
                    $separator = "=" * 30
                    Write-Host ("$separator [!] Cli Powershell Live  Forensic By:Longhoangth18 $separator") -ForegroundColor Yellow
                    Write-Host ("{0,-20} : {1}" -f "Process Name", $process.Name)
                    Write-Host ("{0,-20} : {1}" -f "Process ID", $processId)
                    Write-Host ("{0,-20} : {1}" -f "Creation Date", $process.CreationDate)
                    Write-Host ("{0,-20} : {1}" -f "Command Line", $process.CommandLine)
                    Write-Host ("{0,-20} : {1}" -f "Working Set Size", $process.WorkingSetSize)
                    Write-Host ("{0,-20} : {1}" -f "Description", $process.Description)

                    # Get the full path of the process executable
                    $executablePath = $process.ExecutablePath
                    if ($executablePath -ne $null) {
                        Write-Host ("{0,-20} : {1}" -f "Executable Path", $executablePath)

                        # Calculate and display the hash of the executable file
                        $hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
                        $fileStream = [System.IO.File]::OpenRead($executablePath)
                        $hashBytes = $hashAlgorithm.ComputeHash($fileStream)
                        $hash = [System.BitConverter]::ToString($hashBytes) -replace '-'
                        $fileStream.Close()
                        Write-Host ("{0,-20} : {1}" -f "Executable Hash", $hash) -ForegroundColor Green

                        # Calculate and display the size of the executable file
                        $exeSizeKB = [math]::Round(($fileStream.Length / 1KB), 2)
                        Write-Host ("{0,-20} : {1} KB" -f "Executable Size", $exeSizeKB) -ForegroundColor Magenta
                    }

                    # Calculate and display the hash of the command line
                    $commandLine = $process.CommandLine
                    if ($commandLine -ne $null) {
                        $commandLineBytes = [System.Text.Encoding]::UTF8.GetBytes($commandLine)
                        $hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
                        $hashBytes = $hashAlgorithm.ComputeHash($commandLineBytes)
                        $hash = [System.BitConverter]::ToString($hashBytes) -replace '-'
                        Write-Host ("{0,-20} : {1}" -f "Command Line Hash", $hash) -ForegroundColor Green

                        # Calculate and display the size of the command line
                        $commandLineSizeKB = [math]::Round(($commandLineBytes.Length / 1KB), 2)
                        Write-Host ("{0,-20} : {1} KB" -f "Command Line Size", $commandLineSizeKB) -ForegroundColor Magenta
                    }

                    # Calculate and display the size of the Working Set Size
                    $workingSetSizeKB = [math]::Round(($process.WorkingSetSize / 1KB), 2)
                    Write-Host ("{0,-20} : {1} KB" -f "Working Set Size", $workingSetSizeKB) -ForegroundColor Magenta

                    # Get information about the parent process
                    $parentProcessId = $process.ParentProcessId
                    if ($parentProcessId -ne $null) {
                        $parentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $parentProcessId"
                        if ($parentProcess -ne $null) {
                            Write-Host ("{0,-20} : {1}" -f "Parent Process Name", $parentProcess.Name)
                            Write-Host ("{0,-20} : {1}" -f "Parent Process ID", $parentProcessId)
                        }
                    }

                    # Calculate and display the hash of the process
                    $processBytes = [System.Text.Encoding]::UTF8.GetBytes($process.Name)
                    $processHashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
                    $processHashBytes = $processHashAlgorithm.ComputeHash($processBytes)
                    $processHash = [System.BitConverter]::ToString($processHashBytes) -replace '-'
                    Write-Host ("{0,-20} : {1}" -f "Process Hash", $processHash) -ForegroundColor Green

                    # Get DLLs loaded by the process
                    Get-ProcessDlls -ProcessId $processId -OutputCSV $OutputCSV -OutputJSON $OutputJSON
                }
            }
        }
        catch {
            Write-Host "Error retrieving process information: $_" -ForegroundColor Red
        }
    }
}

# Start monitoring processes and log information to CSV and JSON
$global:trackedProcesses = @{}
Monitor-Processes -OutputCSV "Log_CLI_Forensic.csv" -OutputJSON "Log_CLI_Forensic.json"
