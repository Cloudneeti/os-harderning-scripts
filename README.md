# OS Hardening Scripts
This repository contains a collection of scripts that will help to harden operating system baseline configuration supported by Cloudneeti.

## Supported Benchmark
* CIS Microsoft Windows Server 2016 benchmark v1.0.0
* CIS Microsoft Windows Server 2012 R2 benchmark v1.0.0
* CIS RHEL 7 benchmark v2.1.0
* CIS CentOS 7 benchmark v2.2.0

## Pre-requisites

### For Windows Server
* Windows PowerShell version 5 and above

    1. To check PowerShell version type "$PSVersionTable.PSVersion" in PowerShell and you will find PowerShell version,
    2. To Install PowerShell follow link https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell?view=powershell-6

* Below DSC modules should be installed
    1. AuditPolicyDsc
    2. SecurityPolicyDsc
    3. NetworkingDsc
    4. PSDesiredStateConfiguration
    
    To check module present or not
    ````powershell
    Get-InstalledModule -Name <ModuleName>
    ````

    Install the required modules by executing the below command
    ````powershell
    Install-Module -Name <ModuleName>
    ````

## How to Use

### For Windows Servers

Example 1: CIS Benchmark Windows Server 2016 v1.0.0

1. Login to VM using RDP
2. Download/copy PowerShell script to VM
3. Run PowerShell script to compile DSC

    ````powershell
    .\CIS_Benchmark_WindowsServer2016_v100.ps1
    ````
    Script will generate MOF files in the directory.

4. Run below command to apply baseline configuration

    ````powershell
    Start-DscConfiguration -Path .\CIS_Benchmark_WindowsServer2016_v1_0_0  -Force -Verbose -Wait
    ````
### For Linux machines

Example 1: CIS CentOS Linux7 Benchmark v2.2.0

1. Login to VM/EC2 Instance using SSH
2. Switch user(su) to root.
3. Download/copy bash script to VM/EC2 Instance
4. Run bash script to apply baseline configuration

    ````bash
    bash CIS_CentOS_Linux7_Benchmark_v2_2_0_Remediation.sh
    ````

## Caution
The scripts are designed to harden the operating system baseline configurations, Please test it on the test/staging system before applying to the production system.

## Disclaimer

Copyright (c) Cloudneeti - All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
