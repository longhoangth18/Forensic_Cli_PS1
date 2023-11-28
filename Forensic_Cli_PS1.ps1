function Get-ProcessDlls {
    param (
        [Parameter(Mandatory=$true)]
        [int]$ProcessId,
        [Parameter(Mandatory=$true)]
        [string]$OutputCSV
    )

    # Sử dụng WMI để lấy danh sách DLL được load bởi tiến trình
    $query = "SELECT * FROM Win32_Process WHERE ProcessId = $ProcessId"
    $process = Get-WmiObject -Query $query

    if ($process -ne $null) {
        $query = "ASSOCIATORS OF {$($process.__RELPATH)} WHERE ResultClass = CIM_DataFile"
        $dlls = Get-WmiObject -Query $query

        if ($dlls -ne $null) {
            foreach ($dll in $dlls) {
                $dllPath = $dll.Name
                $dllSizeKB = [math]::Round(($dll.FileSize / 1KB), 2)
                $dllHashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
                $dllFileStream = [System.IO.File]::OpenRead($dllPath)
                $dllHashBytes = $dllHashAlgorithm.ComputeHash($dllFileStream)
                $dllHash = [System.BitConverter]::ToString($dllHashBytes) -replace '-'
                $dllFileStream.Close()
                
                # Write DLL information to CSV
                $dllInfo = [PSCustomObject]@{
                	"TimeCreate"	   = $process.CreationDate
                    "ProcessName"      = $process.Name
                    "ProcessPath"      = $process.ExecutablePath
                    "ProcessID"        = $ProcessId
                    "ProcessSizeKB"    = $fileStream.Length
                    "CommandLine"      = $CommandLine
                    "ProcessPathHash"  = (Get-FileHash -Path $process.ExecutablePath -Algorithm SHA256).Hash
                    "DLLPath"          = $dllPath
                    "DLLSizeKB"        = $dllSizeKB
                    "DLLHash"          = $dllHash
                }
                $dllInfo | Export-Csv -Path $OutputCSV -Append -Force -NoTypeInformation
                
                # Display DLL information
                $dllInfoString = "Process: $($process.Name) Load DLLPath: $($dllInfo.DLLPath) "
                Write-Host $dllInfoString -ForegroundColor Cyan
            }
        }
    }
}

function Monitor-Processes {
    param (
        [string]$OutputCSV = "ProcessInfo.csv"
    )

    $trackedProcesses = @{}

    while ($true) {
        try {
            $newProcesses = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $null }

            foreach ($process in $newProcesses) {
                $processId = $process.ProcessId

                if (-not $trackedProcesses.ContainsKey($processId)) {
                    $trackedProcesses[$processId] = $true

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
                    Get-ProcessDlls -ProcessId $processId -OutputCSV $OutputCSV
                }
            }
        }
        catch {
            Write-Host "Error retrieving process information: $_" -ForegroundColor Red
        }
    }
}

$global:trackedProcesses = @{}
Monitor-Processes -OutputCSV "Log_CLI_Forensic_Cli.csv"
