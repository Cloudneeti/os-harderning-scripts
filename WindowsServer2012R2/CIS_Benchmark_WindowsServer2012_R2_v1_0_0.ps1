<#
.SYNOPSIS
    DSC script to harden Windows Server 2012 R2 VM baseline policies.
.DESCRIPTION
    This script aims to harden Windows Server 2012 R2 VM baseline policies using Desired State Configurations (DSC) for CIS Benchmark Windows Server 2012 R2 Version 1.0.0 supported by ZCSPM.
.NOTE
    Copyright (c) ZCSPM. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    # PREREQUISITE
    * Windows PowerShell version 5 and above
        1. To check PowerShell version type "$PSVersionTable.PSVersion" in PowerShell and you will find PowerShell version,
        2. To Install powershell follow link https://docs.microsoft.com/en-us/powershell/scripting/install/installing-windows-powershell?view=powershell-6
    * DSC modules should be installed
        1. AuditPolicyDsc
        2. SecurityPolicyDsc
        3. NetworkingDsc
        4. PSDesiredStateConfiguration
        
        To check Azure AD version type "Get-InstalledModule -Name <ModuleName>" in PowerShell window
        You can Install the required modules by executing below command.
            Install-Module -Name <ModuleName> -MinimumVersion <Version>
.EXAMPLE
    
    .\CIS_Benchmark_WindowsServer2012_R2_v1_0_0.ps1 [Script will generate MOF files in directory]
    Start-DscConfiguration -Path .\CIS_Benchmark_WindowsServer2012_R2_v1_0_0 -Force -Verbose -Wait
#>

# Configuration Definition
Configuration CIS_Benchmark_WindowsServer2012_R2_v1_0_0 {
    param (
        [string[]]$ComputerName ='localhost'
        )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
	Import-DscResource -ModuleName 'NetworkingDsc'
 
    Node $ComputerName {
      # 1. ACCOUNT POLICIES
      AccountPolicy AccountPolicies
        {
            # 1.1 Password Policy
            Name                                        = 'PasswordPolicies'

            # 1.1.1 Ensure 'Enforce password history' is set to '24 or more password'
            Enforce_password_history                    = 24

            # 1.1.2 Ensure 'Maximum password age' is set to '70 or fewer days, but not 0'
            Maximum_Password_Age                        = 70

            # 1.1.3 Ensure 'Minimum password age' is set to '1 or more day'
            Minimum_Password_Age                        = 1

            # 1.1.4 Ensure 'Minimum password length' is set to '14 or more character'
            Minimum_Password_Length                     = 14

            # 1.1.5 Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'

            # 1.1.6 Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }

        # User Rights Assignment
        # 2.3.10.24 Configure 'Access this computer from the network'
        UserRightsAssignment Accessthiscomputerfromthenetwork {
            Policy       = 'Access_this_computer_from_the_network'
            Identity     = 'Administrators, Authenticated Users, Backup Operators'
        }

        # 2.3.10.27 Configure 'Allow log on through Remote Desktop Services'
        UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
        Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
        Identity     = 'Administrators, Remote Desktop Users' 
        }
        
        # 2.3.10.26 Ensure 'Allow log on locally' is set to 'Administrators'
        UserRightsAssignment Allowlogonlocally {
        Policy       = 'Allow_log_on_locally'
        Identity     = 'Administrators' 
        }

        # 2.3.10.35 Configure 'Create symbolic links'
        UserRightsAssignment Createsymboliclinks {
        Policy       = 'Create_symbolic_links'
        Identity     = 'Administrators'
        }
        
        # 2.3.10.36 Configure 'Deny access to this computer from the network'
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests'
         }

        # 2.3.10.41 Configure 'Enable computer and user accounts to be trusted for delegation'
        UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity     = ''
         }

        # 2.3.10.47 Configure 'Manage auditing and security log'
        UserRightsAssignment Manageauditingandsecuritylog {
            Policy       = 'Manage_auditing_and_security_log'
            Identity     = 'Administrators'
         }

        # 2.3.10.23 Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
        UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity     = ''
         }

        # 2.3.10.25 Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy       = 'Act_as_part_of_the_operating_system'
            Identity     = ''
         }

        # 2.3.10.28 Ensure 'Back up files and directories' is set to 'Administrators'
        UserRightsAssignment Backupfilesanddirectories {
            Policy       = 'Back_up_files_and_directories'
            Identity     = 'Administrators,Backup Operators'
         }

        # 2.3.10.29 Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethesystemtime {
            Policy       = 'Change_the_system_time'
            Identity     = 'Administrators, LOCAL SERVICE'
         }
       
        # 2.3.10.30 Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethetimezone {
            Policy       = 'Change_the_time_zone'
            Identity     = 'Administrators, LOCAL SERVICE'
         }

        # 2.3.10.31 Ensure 'Create a pagefile' is set to 'Administrators'
        UserRightsAssignment Createapagefile {
            Policy       = 'Create_a_pagefile'
            Identity     = 'Administrators'
         }

        # 2.3.10.32 Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment Createatokenobject {
            Policy       = 'Create_a_token_object'
            Identity     = ''
         }

        # 2.3.10.33 Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Createglobalobjects {
            Policy       = 'Create_global_objects'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
         }

        # 2.3.10.34 Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment Createpermanentsharedobjects {
            Policy       = 'Create_permanent_shared_objects'
            Identity     = ''
         }

        # 2.3.10.37 Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
         }

        # 2.3.10.38 Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
         }

        # 2.3.10.39 Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
         }

        # 2.3.10.40 Ensure 'Deny log on through Remote Desktop Services' to include 'Guests'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests'
         }

        # 2.3.10.42 Ensure 'Force shutdown from a remote system' is set to 'Administrators'
        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy       = 'Force_shutdown_from_a_remote_system'
            Identity     = 'Administrators'
         }

        # 2.3.10.43 Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Generatesecurityaudits {
            Policy       = 'Generate_security_audits'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
         }

        # 2.3.10.44 Ensure 'Increase scheduling priority' is set to 'Administrators'
        UserRightsAssignment Increaseschedulingpriority {
            Policy       = 'Increase_scheduling_priority'
            Identity     = 'Administrators'
         }

        # 2.3.10.45 Ensure 'Load and unload device drivers' is set to 'Administrators'
        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy       = 'Load_and_unload_device_drivers'
            Identity     = 'Administrators'
         }

        # 2.3.10.46 Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment Lockpagesinmemory {
            Policy       = 'Lock_pages_in_memory'
            Identity     = ''
         }

        # 2.3.10.48 Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment Modifyanobjectlabel {
            Policy       = 'Modify_an_object_label'
            Identity     = ''
         }

        # 2.3.10.49 Ensure 'Modify firmware environment values' is set to 'Administrators'
        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy       = 'Modify_firmware_environment_values'
            Identity     = 'Administrators'
         }

        # 2.3.10.50 Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
        UserRightsAssignment Performvolumemaintenancetasks {
            Policy       = 'Perform_volume_maintenance_tasks'
            Identity     = 'Administrators'
         }

        # 2.3.10.51 Ensure 'Profile single process' is set to 'Administrators'
        UserRightsAssignment Profilesingleprocess {
            Policy       = 'Profile_single_process'
            Identity     = 'Administrators'
         }

        # 2.3.10.52 Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
        UserRightsAssignment Profilesystemperformance {
            Policy       = 'Profile_system_performance'
            Identity     = 'Administrators,WdiServiceHost'
         }

        # 2.3.10.53 Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Replaceaprocessleveltoken {
            Policy       = 'Replace_a_process_level_token'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
         }

        # 2.3.10.54 Ensure 'Restore files and directories' is set to 'Administrators, Backup Operators'
        UserRightsAssignment Restorefilesanddirectories {
            Policy       = 'Restore_files_and_directories'
            Identity     = 'Administrators, Backup Operators'
         }

        # 2.3.10.55 Ensure 'Shut down the system' is set to 'Administrators'
        UserRightsAssignment Shutdownthesystem {
            Policy       = 'Shut_down_the_system'
            Identity     = 'Administrators'
         }

        # 2.3.10.56 Ensure 'Take ownership of files or other objects' is set to 'Administrators'
        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy       = 'Take_ownership_of_files_or_other_objects'
            Identity     = 'Administrators'
         }

        # Account Management

        # 2.3.10.84 Ensure 'Audit Application Group Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Application Group Management (Success)'
        {
            Name      = 'Application Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Application Group Management (Failure)'
        {
            Name      = 'Application Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 2.3.10.81 Policy: Account Management: Other Account Management Events
        AuditPolicySubcategory 'Audit Other Account Management Events (Success)' 
        {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Other Account Management Events (Failure)' 
        {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 2.3.10.83 Audit Policy: Account Management: User Account Management
        AuditPolicySubcategory 'Audit User Account Management (Success)' 
        {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit User Account Management (Failure)' 
        {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 2.3.10.82 Audit Policy: Account Management: Security Group Management
        AuditPolicySubcategory 'Audit Security Group Management (Success)' 
        {
            Name      = 'Security Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Failure)' 
        {
            Name      = 'Security Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # Logon/Logoff
        # 2.3.10.87 Audit Policy: Logon-Logoff: Logoff
        AuditPolicySubcategory 'Audit Logoff (Success)' 
        {
            Name      = 'Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Logoff (Failure)' 
        {
            Name      = 'Logoff'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 2.3.10.88 Audit Policy: Logon-Logoff: Logon
        AuditPolicySubcategory 'Audit Logon (Success)' 
        {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Logon (Failure)' 
        {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 2.3.10.86 Audit Policy: Logon-Logoff: Account Lockout
        AuditPolicySubcategory 'Audit Account Lockout (Success)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 2.3.10.89 Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 2.3.10.90 Audit Policy: Logon-Logoff: Special Logon
        AuditPolicySubcategory 'Audit Special Logon (Success)' 
        {
            Name      = 'Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Special Logon (Failure)' 
        {
            Name      = 'Special Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # System
        
        # 2.3.10.13 Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSystemLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '32768'
        }

        # 2.3.10.14 Audit Policy: System: Security State Change
        AuditPolicySubcategory 'Audit Security State Change (Success)' {
         Name      = 'Security State Change'
         Ensure    = 'Present'
         AuditFlag = 'Success'
        }
        
        AuditPolicySubcategory 'Audit Security State Change (Failure)' {
         Name      = 'Security State Change'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
        }
        
        # 2.3.10.15 Audit Policy: System: Security System Extension
        AuditPolicySubcategory 'Audit Security System Extension (Success)' 
        {
            Name      = 'Security System Extension'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # 2.3.10.16 Audit Policy: System: System Integrity
        AuditPolicySubcategory 'Audit System Integrity (Failure)' 
        {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit System Integrity (Success)' 
        {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        
        # 2.3.10.17 Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSystemLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }
        
        # 2.3.10.18 Audit Policy: System: IPsec Driver
        AuditPolicySubcategory 'Audit IPsec Driver (Failure)' {
         Name      = 'IPsec Driver'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
        }
        
        AuditPolicySubcategory 'Audit IPsec Driver (Success)' {
         Name      = 'IPsec Driver'
         Ensure    = 'Present'
         AuditFlag = 'Success'
        }

        # 2.3.10.19 Audit Policy: System: Other System Events
        AuditPolicySubcategory 'Audit Other System Events (Failure)' 
        {
            Name      = 'Other System Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Other System Events (Success)' 
        {
            Name      = 'Other System Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # Account Logon

        # 2.3.10.80 Audit Policy: Account Logon: Credential Validation
        AuditPolicySubcategory "Audit Credential Validation (Success)"
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Credential Validation (Failure)'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # Detailed Tracking
        # 2.3.10.85 Audit Policy: Detailed Tracking: Process Creation
        AuditPolicySubcategory 'Audit Process Creation (Success)' 
        {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Process Creation (Failure)' 
        {
            Name      = 'Process Creation'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # Privilege Use
        # Audit Policy: Privilege Use: Sensitive Privilege Use
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        # Object Access
        # 2.3.10.92 Ensure 'Audit Removable Storage' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
            Name      = 'Removable Storage'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
            Name      = 'Removable Storage'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # Policy Change

        # 2.3.10.93 Audit Policy: Policy Change: Audit Policy Change
        AuditPolicySubcategory 'Audit Policy Change (Success)' 
        {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Change (Failure)' 
        {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 2.3.10.94 Audit Policy: Policy Change: Authentication Policy Change
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success)' {
         Name      = 'Authentication Policy Change'
         Ensure    = 'Present'
         AuditFlag = 'Success'
		}
        
        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure)' {
         Name      = 'Authentication Policy Change'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
        }


        # 2.3.10.95 Ensure 'Audit Authorization Policy Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success)' {
            Name      = 'Authorization Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure)' {
            Name      = 'Authorization Policy Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        SecurityOption AccountSecurityOptions {
          Name                                   = 'AccountSecurityOptions'
          # Accounts

          # 2.3.10.58 Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
          Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'

          # 2.3.10.57 Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
          Accounts_Guest_account_status = 'Disabled'

          # Devices

          # 2.3.10.62 Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
          Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'

          # 2.3.10.61 Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
          Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'

          # Interactive logon

          # 2.3.10.63 Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
          Interactive_logon_Do_not_display_last_user_name = 'Enabled'

          # 2.3.10.64 Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
          Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'

          # Microsoft network client

          # 2.3.10.77 Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
          Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'

          # 2.3.10.78 Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
          Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'

          # 2.3.10.79 Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
          Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'

          # Microsoft network server

          # 2.3.10.65 Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute, but not 0'
          Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15' 

          # 2.3.10.66 Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
          Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'

          # 2.3.10.67 Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
          Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'

          # 2.3.10.68 Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
          Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled' 

          # Network access

          # 2.3.10.3 Network access: Do not allow anonymous enumeration of SAM accounts and shares
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'

          # 2.3.10.2 Network access: Do not allow anonymous enumeration of SAM accounts
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'

          # 2.3.10.5 Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
          Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled' 

          # 2.3.10.6 Network access: Restrict anonymous access to Named Pipes and Shares
          Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled' 

          # 2.3.10.11 Network access: Sharing and security model for local accounts 
          Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
          
          # 2.3.10.10 Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' 
          Network_access_Shares_that_can_be_accessed_anonymously = ''

          # 2.3.10.7 Configure 'Network access: Remotely accessible registry paths' 
          # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
          # Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, SOFTWARE\Microsoft\Windows NT\CurrentVersion'
          
          # 2.3.10.8 Configure 'Network access: Remotely accessible registry paths and sub-paths' 
          # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
          #Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Print, Software\Microsoft\Windows NT\CurrentVersion\Windows, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog'

          # Network security

          # 2.3.10.127 Network security: Allow LocalSystem NULL session fallback
          Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'

          # 2.3.10.119 Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
          Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'

          # 2.3.10.126 Network security: Do not store LAN Manager hash value on next password change
          Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'

          # 2.3.10.124 Network security: LDAP client signing requirements
          Network_security_LDAP_client_signing_requirements = 'Negotiate Signing' 

          # 2.3.10.123 Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
          Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
          
          # 2.3.10.125 Network security: Minimum session security for NTLM SSP based (including secure RPC) servers 
          Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'

          # 2.3.10.120 Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
          Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'

          # 2.3.10.121 Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
          Network_security_Configure_encryption_types_allowed_for_Kerberos = 'RC4_HMAC_MD5','AES128_HMAC_SHA1','AES256_HMAC_SHA1','FUTURE'
          
          # 2.3.10.122 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
          Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'

          # Shutdown

          # 2.3.10.154 Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
          Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'

          # System objects

          # 2.3.10.143 System objects: Require case insensitivity for non-Windows subsystems
          System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled' 

          # 2.3.10.144 System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
          System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'

          # User Account Control

          # 2.3.10.145 User Account Control: Admin Approval Mode for the Built-in Administrator account
          User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'

          # 2.3.10.151 User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop
          User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'

          # 2.3.10.147 User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
          User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'

          # 2.3.10.148 User Account Control: Behavior of the elevation prompt for standard users
          User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'

          # 2.3.10.150 User Account Control: Detect application installations and prompt for elevation
          User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'

          # 2.3.10.149 User Account Control: Only elevate UIAccess applications that are installed in secure locations
          User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'

          # 2.3.10.146 User Account Control: Run all administrators in Admin Approval Mode
          User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'

          # 2.3.10.153 User Account Control: Switch to the secure desktop when prompting for elevation
          User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'

          # 2.3.10.152 User Account Control: Virtualize file and registry write failures to per-user locations
          User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'     

          # Audit

          # 2.3.10.60 Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
          Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'

          # 2.3.10.59 Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
          Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
                 
        }
        
        # Security
        
        # 2.3.10.114 Ensure 'Always prompt for password upon connection' is set to 'Enabled'
        Registry 'fPromptForPassword' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fPromptForPassword'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # 2.3.10.115 Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSecurityLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }
        
        # 2.3.10.116 Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
        Registry 'MaxSizeSecurityLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '196608'
        }
        
        # 2.3.10.117 Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
        Registry 'MinEncryptionLevel' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'MinEncryptionLevel'
            ValueType  = 'DWord'
            ValueData  = '3'
        }
        
        # 2.3.10.118 Ensure 'Require secure RPC communication' is set to 'Enabled'
        Registry 'fEncryptRPCTraffic' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fEncryptRPCTraffic'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # WinRM Service

        # 2.3.10.9 Ensure 'Allow unencrypted traffic' is set to 'Disabled'
        Registry 'AllowUnencryptedTraffic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowUnencryptedTraffic'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # 2.3.10.10 Ensure 'Allow Basic authentication' is set to 'Disabled'
        Registry 'AllowBasic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowBasic'
          ValueType  = 'DWord'
          ValueData  = '0'
        } 
        
        # 2.3.10.11 Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
        Registry 'DisableRunAs' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'DisableRunAs'
            ValueType = 'DWord'
            ValueData = '1'
        }
        
        # WinRM Client
        # 2.3.10.71 Ensure 'Disallow Digest authentication' is set to 'Enabled'
        Registry 'AllowDigest' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowDigest'
          ValueType  = 'DWord'
          ValueData  = '0'
        }
        
        # Logon
        
        # 2.3.10.20 Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' 
        Registry 'DisableLockScreenAppNotifications' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'DisableLockScreenAppNotifications'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # 2.3.10.21 Ensure 'Do not display network selection UI' is set to 'Enabled'
        Registry 'DontDisplayNetworkSelectionUI' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'DontDisplayNetworkSelectionUI'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # 2.3.10.22 'Turn on convenience PIN sign-in' is set to 'Disabled'
        Registry 'AllowDomainPINLogon' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
           ValueName  = 'AllowDomainPINLogon'
           ValueType  = 'DWord'
           ValueData  = '0'
        }
        
        # Public Profile

        <# 2.3.10.73 Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
        Registry 'AllowLocalPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
        
        # 2.3.10.72 Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
        Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalIPsecPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
        
        # 2.3.10.76 Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
        Registry 'DefaultOutboundActionPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'DefaultOutboundAction'
            ValueType    = 'DWord'
            ValueData    = '0'
        }#>
        
        # 2.3.10.74 Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'EnableFirewall'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
        
        # 2.3.10.75 Windows Firewall: Public: Display a notification
        Registry 'DisableNotificationsPublic' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName  = 'DisableNotifications'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Private Profile
        
        # 2.3.10.131 Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'EnableFirewall'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
        
        # 2.3.10.132 Windows Firewall: Private: Display a notification
        Registry 'DisableNotificationsPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'DisableNotifications'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
        
        # 2.3.10.133 Windows Firewall: Private: Outbound connections
        Registry 'DefaultOutboundActionPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'DefaultOutboundAction'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
        
        # Domain Profile
        
        # 2.3.10.138 Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        
        # 2.3.10.139 Windows Firewall: Domain: Display a notification
        Registry 'DisableNotificationsDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        
        # 2.3.10.140 Windows Firewall: Domain: Outbound connections
        Registry 'DefaultOutboundActionDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        
        # Temporary folders

        # 2.3.10.141 Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
        Registry 'DeleteTempDirsOnExit' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'DeleteTempDirsOnExit'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # 2.3.10.142 Ensure 'Do not use temporary folders per session' is set to 'Disabled'
        Registry 'PerSessionTempDir' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'PerSessionTempDir'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        # Windows Installer

        # 2.3.10.112 Ensure 'Always install with elevated privileges' is set to 'Disabled'
        Registry 'AlwaysInstallElevated' {
           Ensure       = 'Present'
           Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer'
           ValueName    = 'AlwaysInstallElevated'
           ValueType    = 'DWord'
           ValueData    = '0'
        }

        # 2.3.10.113 Ensure 'Allow user control over installs' is set to 'Disabled'
        Registry 'EnableUserControl' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
          ValueName  = 'EnableUserControl'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # File Explorer (formerly Windows Explorer)

        # 2.3.10.103 Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
        Registry 'NoHeapTerminationOnCorruption' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoHeapTerminationOnCorruption'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # 2.3.10.104 Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
        Registry 'PreXPSP2ShellProtocolBehavior' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'PreXPSP2ShellProtocolBehavior'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # 2.3.10.105 Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
        Registry 'NoDataExecutionPrevention' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoDataExecutionPrevention'
          ValueType  = 'DWord'
          ValueData  = '0'
        }
        
        # Setup

        # 2.3.10.134 Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSetupLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '32768'
        }
        
        # 2.3.10.135 Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSetupLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }
        
        # Application

        # 2.3.10.136 Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionApplicationLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }
        
        # 2.3.10.137 Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeApplication' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '32768'
        }

        # AutoPlay Policies

        # 2.3.10.106 Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
        Registry 'NoDriveTypeAutoRun' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName  = 'NoDriveTypeAutoRun'
            ValueType  = 'DWord'
            ValueData  = '255'
        }
        
        # 2.3.10.107 Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
        Registry 'NoAutorun' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName  = 'NoAutorun'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # 2.3.10.108 Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
        Registry 'NoAutoplayfornonVolume' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName  = 'NoAutoplayfornonVolume'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Personalization
        
        # 2.3.10.100 Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' 
        Registry 'NoLockScreenCamera' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName  = 'NoLockScreenCamera'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # 2.3.10.101 Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
        Registry 'NoLockScreenSlideshow' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName    = 'NoLockScreenSlideshow'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
        
        # Remote Assistance

        # 2.3.10.69 Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
        Registry 'fAllowToGetHelp' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
           ValueName  = 'fAllowToGetHelp'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # 2.3.10.70 Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
        Registry 'fAllowUnsolicited' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
           ValueName  = 'fAllowUnsolicited'
           ValueType  = 'DWord'
           ValueData  = '0'
        }
        
        # Remote Desktop Connection Client
        # 2.3.10.12 Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
        Registry 'DisablePasswordSaving' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'DisablePasswordSaving'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Consent
        # 2.3.10.96 Ensure 'Configure Default consent' is set to 'Enabled: Send all data'
        Registry 'DefaultConsent' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent'
          ValueName  = 'DefaultConsent'
          ValueType  = 'DWord'
          ValueData  = '4'
        }
        
        # Audit Process Creation
        # 2.3.10.97 Ensure 'Include command line in process creation events' is set to 'Disabled'
        Registry 'ProcessCreationIncludeCmdLine_Enabled' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName  = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Windows Logon Options
        # Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
        Registry 'DisableAutomaticRestartSignOn' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'DisableAutomaticRestartSignOn'
          ValueType  = 'DWord'
          ValueData  = '1'
        }
        
        # RSS Feeds
        # 2.3.10.99 Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
        Registry 'DisableEnclosureDownload' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName  = 'DisableEnclosureDownload'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Network Connections
        # 2.3.10.102 Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
        Registry 'NC_AllowNetBridge_NLA' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
           ValueName    = 'NC_AllowNetBridge_NLA'
           ValueType    = 'DWord'
           ValueData    = '0'
        }
        
        # Windows Connection Manager
        # 2.3.10.109 Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
        Registry 'fMinimizeConnections' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueName = 'fMinimizeConnections'
            ValueType = 'DWord'
            ValueData = '1'
        }
        
        # Early Launch Antimalware
        # 2.3.10.110 Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
        Registry 'DriverLoadPolicy' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName  = 'DriverLoadPolicy'
            ValueType  = 'DWord'
            ValueData  = '3'
        }

        # App runtime
        # 2.3.10.111 Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
        Registry 'MSAOptional' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName  = 'MSAOptional'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        # Credential User Interface
        
        # 2.3.10.128 Ensure 'Do not display the password reveal button' is set to 'Enabled'
        Registry 'DisablePasswordReveal' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
            ValueName   = 'DisablePasswordReveal'
            ValueType   = 'DWord'
            ValueData   = '1'
        }

        # 2.3.10.129 Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
        Registry 'EnumerateAdministrators' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
          ValueName  = 'EnumerateAdministrators'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # Windows Error Reporting
        # 2.3.10.130 Ensure 'Automatically send memory dumps for OS-generated error reports' is set to 'Disabled'
        Registry 'AutoApproveOSDumps' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
          ValueName  = 'AutoApproveOSDumps'
          ValueType  = 'DWord'
          ValueData  = '0'
        }
        
        # Internet Communication settings
        # 2.3.10.155 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
        Registry 'DisableWebPnPDownload' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
            ValueName  = 'DisableWebPnPDownload'
            ValueType  = 'DWord'
            ValueData  = '0'
        }
        
        # Remote Procedure Call
        # 2.3.10.156 Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
        Registry 'EnableAuthEpResolution' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName  = 'EnableAuthEpResolution'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
    }
 }

CIS_Benchmark_WindowsServer2012_R2_v1_0_0