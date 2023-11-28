# PowerShell CLI Forensic Tool

Ahoy there! Welcome to the PowerShell CLI Forensic Tool - your trusty companion for sailing through the seas of command line forensics. This tool is designed to monitor and gather detailed information about processes running on your system, including the DLLs they load.

## Features

### 1. Process Monitoring

The `Monitor-Processes` function keeps a vigilant eye on the running processes aboard your ship. Every time a new process sets sail, detailed information is displayed, including:

- Process Name
- Process ID
- Creation Date
- Command Line
- Working Set Size
- Description
- Executable Path
- Executable Hash
- Executable Size
- Command Line Hash
- Command Line Size
- Parent Process Information
- Process Hash

### 2. DLL Tracking

The `Get-ProcessDlls` function digs into the depths of a specified process to uncover the DLLs it carries. For each DLL, the tool extracts and logs information such as:

- DLL Path
- DLL Size
- DLL Hash

All the gathered information is exported to a CSV file, creating a log of your cyber expedition.

## How to Set Sail

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/longhoangth18/Forensic_Cli_PS1.git
    ```

2. **Run the CLI Forensic Tool:**
    ```powershell
    .\Forensic_Cli_PS1.ps1
    ```

3. **View the Log:**
    Open the generated CSV file (`Log_CLI_Forensic_Cli.csv`) to view a detailed record of your command line adventures.

4. **Adjust the Course:**
    Feel free to customize the script according to your needs and explore new territories.

## Contributions

Sailors and buccaneers alike, contributions are always welcome! If you spot a bug or have an enhancement in mind, raise the Jolly Roger by opening an issue or submit a pull request. Together, we'll keep our cyber seas safe and secure.

## ⚓ Fair Winds and Happy Sailing! ⚓
