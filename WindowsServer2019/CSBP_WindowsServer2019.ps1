<#
.SYNOPSIS
    DSC script to harden Windows Server 2019 VM baseline policies for CSBP.
.DESCRIPTION
    This script aims to harden Windows Server 2019 VM baseline policies using Desired State Configurations (DSC) for CIS Benchmark Windows Server 2019 Version 1.0.0 supported by ZCSPM.
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
    
    .\CSBP_WindowsServer2019.ps1 [Script will generate MOF files in directory]
    Start-DscConfiguration -Path .\CSBP_WindowsServer2019  -Force -Verbose -Wait
#>

# Configuration Definition
Configuration CSBP_WindowsServer2019 {
    param (
        [string[]]$ComputerName = 'localhost'
    )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'NetworkingDsc'
 
    Node $ComputerName {
        AccountPolicy AccountPolicies 
        {
            Name                                        = 'PasswordPolicies'

            # CceId: CCE-36286-3
            # DataSource: Security Policy
            # Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'

            # CceId: CCE-37063-5
            # DataSource: Security Policy
            # Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'

            # CceId: CCE-37432-2
            # DataSource: Security Policy
            # Ensure 'Accounts: Guest account status' is set to 'Disabled' 
            #Accounts_Guest_account_status = 'Disabled'


            # CceId: CCE-36534-6
            # DataSource: Security Policy
            # Ensure 'Minimum password length' is set to '14 or more character'
            Minimum_Password_Length                     = '14'

            # CceId: CCE-37073-4
            # DataSource: Security Policy
            # Ensure 'Minimum password age' is set to '1 or more day'
            Minimum_Password_Age                        = '2'

            # CceId: CCE-37166-6
            # DataSource: Security Policy
            #  Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                     = '24'

            # CceId: CCE-37167-4
            # DataSource: Security Policy
            # Ensure 'Maximum password age' is set to '70 or fewer days, but not 0'
            Maximum_Password_Age                        = '50'
        }

        # CceId: CCE-38325-7
        # DataSource: Security Policy
        # Ensure 'Take ownership of files or other objects' is set to 'Administrators'
        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy   = 'Take_ownership_of_files_or_other_objects'
            Identity = 'Administrators'
        }

        # CceId: CCE-37877-8
        # DataSource: Security Policy
        # Ensure 'Force shutdown from a remote system' is set to 'Administrators'
        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy   = 'Force_shutdown_from_a_remote_system'
            Identity = 'Administrators'
        }

        # CceId: CCE-38328-1
        # DataSource: Security Policy
        # Ensure 'Shut down the system' is set to 'Administrators'
        UserRightsAssignment Shutdownthesystem {
            Policy   = 'Shut_down_the_system'
            Identity = 'Administrators'
        }

        # CceId: CCE-37613-7
        # DataSource: Security Policy
        #  Ensure 'Restore files and directories' is set to 'Administrators'
        UserRightsAssignment Restorefilesanddirectories {
            Policy   = 'Restore_files_and_directories'
            Identity = 'Administrators'
        }

        # CceId: CCE-37430-6
        # DataSource: Security Policy
        # Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Replaceaprocessleveltoken {
            Policy   = 'Replace_a_process_level_token'
            Identity = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        # CceId:
        # DataSource: Security Policy
        # Ensure 'Increase a process working set' is set to 'Administrators, Local Service'
        UserRightsAssignment Increaseaprocessworkingset {
            Policy   = 'Increase_a_process_working_set'
            Identity = 'Administrators,  Local Service'
        }

        # CceId: CCE-36052-9
        # DataSource: Security Policy
        # Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
        UserRightsAssignment Profilesystemperformance {
            Policy   = 'Profile_system_performance'
            Identity = 'Administrators, NT SERVICE\WdiServiceHost'
        }

        # CceId: CCE-37131-0
        # DataSource: Security Policy
        # Ensure 'Profile single process' is set to 'Administrators'
        UserRightsAssignment Profilesingleprocess {
            Policy   = 'Profile_single_process'
            Identity = 'Administrators'
        }

        # CceId: CCE-36143-6
        # DataSource: Security Policy
        # Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
        UserRightsAssignment Performvolumemaintenancetasks {
            Policy   = 'Perform_volume_maintenance_tasks'
            Identity = 'Administrators'
        }

        # CceId: CCE-38113-7
        # DataSource: Security Policy
        # Ensure 'Modify firmware environment values' is set to 'Administrators'
        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy   = 'Modify_firmware_environment_values'
            Identity = 'Administrators'
        }

        # CceId: CCE-36054-5
        # DataSource: Security Policy
        # Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment Modifyanobjectlabel {
            Policy   = 'Modify_an_object_label'
            Identity = 'No One'
        }

        # CceId: CCE-36495-0
        # DataSource: Security Policy
        # Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment Lockpagesinmemory {
            Policy   = 'Lock_pages_in_memory'
            Identity = 'No One'
        }

        # CceId: 
        # DataSource: Security Policy
        # Ensure 'Access  this computer from the network' is set to 'Administrators, Authenticated Users' (DC only)
        UserRightsAssignment  Accessthiscomputerfromthenetwork {
            Policy   = 'Access_this_computer_from_the_network'
            Identity = 'Administrators, Authenticated Users'
        }

        # CceId: CCE-36318-4
        # DataSource: Security Policy
        # Ensure 'Load and unload device drivers' is set to 'Administrators'
        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy   = 'Load_and_unload_device_drivers'
            Identity = 'Administrators'
        }

        
    

        # CceId: CCE-36867-0 
        # DataSource: Security Policy
        # Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = 'Guests, Local account'
        }

        # CceId: CCE-36877-9
        # DataSource: Security Policy
        # Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy   = 'Deny_log_on_as_a_service'
            Identity = 'Guests'
        }

        # CceId: CCE-36923-1
        # DataSource: Security Policy
        # Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = 'Guests'
        }

        # CceId: CCE-36532-0
        # DataSource: Security Policy
        # Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment Createpermanentsharedobjects {
            Policy   = 'Create_permanent_shared_objects'
            Identity = 'No One'
        }

        # CceId: CCE-37453-8
        # DataSource: Security Policy
        # Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Createglobalobjects {
            Policy   = 'Create_global_objects'
            Identity = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        }

        # CceId: CCE-36861-3
        # DataSource: Security Policy
        # Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment Createatokenobject {
            Policy   = 'Create_a_token_object'
            Identity = 'No One'
        }
        

        # CceId: CCE-35821-8
        # DataSource: Security Policy
        # Ensure 'Create a pagefile' is set to 'Administrators'
        UserRightsAssignment Createapagefile {
            Policy   = 'Create_a_pagefile'
            Identity = 'Administrators'
        }

        # CceId:
        # DataSource: Security Policy
        # Ensure 'Bypass traverse checking' is set to 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
        UserRightsAssignment Bypasstraversechecking {
            Policy   = 'Bypass_traverse_checking'
            Identity = 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
        }

        # CceId: CCE-37700-2
        # DataSource: Security Policy       
        # Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethetimezone {
            Policy   = 'Change_the_time_zone'
            Identity = 'Administrators, LOCAL SERVICE'
        }

        # CceId: CCE-35912-5
        # DataSource: Security Policy
        # Ensure 'Back up files and directories' is set to 'Administrators'
        UserRightsAssignment Backupfilesanddirectories {
            Policy   = 'Back_up_files_and_directories'
            Identity = 'Administrators'
        }

        # CceId: CCE-36876-1
        # DataSource: Security Policy
        # Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy   = 'Act_as_part_of_the_operating_system'
            Identity = 'No One'
        }

        # CceId: CCE-37056-9
        # DataSource: Security Policy
        # Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
        UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity = 'No One'
        }

        # CceId: CCE-35823-4
        # DataSource: Security Policy
        # Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)
        UserRightsAssignment Createsymboliclinks {
            Policy   = 'Create_symbolic_links'
            Identity = 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
        }

        # CceId: CCE-37659-0
        # DataSource: Security Policy
        # Ensure 'Allow log on locally' is set to 'Administrators'
        UserRightsAssignment Allowlogonlocally {
            Policy   = 'Allow_log_on_locally'
            Identity = 'Administrators' 
        }

        # CceId: CCE-37639-2
        # DataSource: Security Policy
        # Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Generatesecurityaudits {
            Policy   = 'Generate_security_audits'
            Identity = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        # CceId: CCE-37146-8
        # DataSource: Security Policy
        # Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy   = 'Deny_log_on_locally'
            Identity = 'Guests'
        }

        # CceId: CCE-37452-0
        # DataSource: Security Policy
        # Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethesystemtime {
            Policy   = 'Change_the_system_time'
            Identity = 'Administrators, LOCAL SERVICE'
        }

        # CceId: CCE-35906-7
        # DataSource: Security Policy
        # Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)
        UserRightsAssignment  Manageauditingandsecuritylog {
            Policy   = 'Manage_auditing_and_security_log'
            Identity = 'Administrators'
        }

        # CceId: CCE-36860-5
        # DataSource: Security Policy
        # Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only)
        UserRightsAssignment  Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy   = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity = 'Administrators'
        }

        # CceId: CCE-37954-5
        # DataSource: Security Policy
        # Ensure 'Deny access to this computer from the network' is set to 'Guests' (DC only)
        UserRightsAssignment  Denyaccesstothiscomputerfromthenetwork {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = 'Guests'
        }

        # CceId: CCE-38326-5
        # DataSource: Security Policy
        # Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'
        UserRightsAssignment Increaseschedulingpriority {
            Policy   = 'Increase_scheduling_priority'
            Identity = 'Administrators'
        }


        # CceId: CCE-37072-6
        # DataSource: Security Policy
        # Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)
        UserRightsAssignment  AllowlogonthroughRemoteDesktopServices {
            Policy   = 'Allow_log_on_through_Remote_Desktop_Services'
            Identity = 'Administrators'
        }

        # CceId: 
        # DataSource: Audit Policy
        # Ensure 'Audit Group Membership' is set to 'Success'
        AuditPolicySubcategory 'Audit Group Membership (Success)' {
            Name      = 'Group Membership'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        # CceId: CCE-38327-3
        # DataSource: Audit Policy
        # Ensure 'Audit Authentication Policy Change' is set to 'Success'
        <#AuditPolicySubcategory 'Audit Authentication Policy Change (Success)' {
            Name      = 'Authentication Policy'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>

        # CceId: CCE-38028-7
        # DataSource: Audit Policy
        # Ensure 'Audit Audit Policy Change' is set to include 'Success'
        AuditPolicySubcategory 'Audit Audit Policy Change (Success)' {
            Name      = 'Audit Policy change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # CceId: CCE-36059-4 
        # DataSource: Audit Policy
        # Ensure 'Audit Process Creation' is set to include 'Success'
        <#AuditPolicySubcategory 'Audit Process Creation (Success)' {
            Name      = 'Audit process creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>
    
        # CceId: CCE-37620-2
        # DataSource: Audit Policy
        # Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
        <#AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
            Name      = 'Object Access Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>
        <#AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
            Name      = 'Object Access Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }#>
        # CceId: 
        # DataSource: Audit Policy
        # Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
        <#AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success)' {
            Name      = 'MPSSVC Rule-Level Policy'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>
        <#AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)' {
            Name      = 'MPSSVC Rule-Level Policy'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }#>
        # CceId: CCE-37133-6
        # DataSource: Audit Policy
        # Ensure 'Audit Account Lockout' is set to 'Success and Failure'
        <#AuditPolicySubcategory 'Audit Account Lockout (Success)' {
            Name      = 'Audit Account Lockout'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>
        <#AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Audit Account Lockout'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }#>
        # CceId: CCE-38036-0
        # DataSource: Audit Policy
        # Ensure 'Audit Logon' is set to 'Success and Failure'
        <#AuditPolicySubcategory 'Audit Logon (Success)' {
            Name      = 'Audit Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>
        <#AuditPolicySubcategory 'Audit Logon (Failure)' {
            Name      = 'Audit Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }#>
        # CceId: 
        # DataSource: Audit Policy
        # Ensure 'Audit Credential Validation' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Credential Validation (Success)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Credential Validation (Failure)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        # CceId: CCE-37132-8
        # DataSource: Audit Policy
        # Ensure 'Audit System Integrity' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit System Integrity (Success)' {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit System Integrity (Failure)' {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        # CceId: CCE-36266-5
        # DataSource: Audit Policy
        # Ensure 'Audit Special Logon' is set to 'Success'
        <#AuditPolicySubcategory 'Audit Special Logon (Success)' {
            Name      = 'Audit Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>
        # CceId: 
        # DataSource: Audit Policy
        # Ensure 'Audit PNP Activity' is set to 'Success'
        <#AuditPolicySubcategory 'Audit PNP Activity (Success)' {
            Name      = 'Audit PNP Activity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>
        # CceId: CCE-36322-6
        # DataSource: Audit Policy
        # Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
        <#AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Logon/Logoff Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>
        <#AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Logon/Logoff Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }#>
        # CceId: CCE-38237-4
        # DataSource: Audit Policy
        # Ensure 'Audit Logoff' is set to 'Success'
        <#AuditPolicySubcategory 'Audit Logoff (Success)' {
            Name      = 'Audit Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }#>

        # CceId: CCE-36267-3
        # DataSource: Audit Policy
        # Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
           Name      = 'Sensitive Privilege Use'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        # CceId: CCE-37856-2
        # DataSource: Audit Policy
        # Ensure 'Audit User Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
           Name      = 'User Account Management'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }
        # CceId: CCE-36144-4
        # DataSource: Audit Policy
        # Ensure 'Audit Security System Extension' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security System Extension (Success)' {
           Name      = 'Security System Extension'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Security System Extension (Failure)' {
           Name      = 'Security System Extension'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }
        # CceId: CCE-38114-5
        # DataSource: Audit Policy
        # Ensure 'Audit Security State Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Security State Change (Success)' {
           Name      = 'Security State Change'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        # CceId: CCE-38034-5
        # DataSource: Audit Policy
        # Ensure 'Audit Security Group Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security Group Management (Success)' {
           Name      = 'Security Group Management'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Security Group Management (Failure)' {
           Name      = 'Security Group Management'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }
        
        # CceId: CCE-38028-7
        # DataSource: Audit Policy
        # Ensure 'Audit Removable Storage' is set to 'Success and Failure'
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

        SecurityOption AccountSecurityOptions {
            Name                                   = 'AccountSecurityOptions'

        # CceId: CCE-36056-0
        # DataSource: Registry Policy
        # Ensure 'Windows Search Service' is set to 'Disabled'
        # Windows_Search_Service           =  'Disabled'    

        # CceId: CCE-36056-0
        # DataSource: Registry Policy
        # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
        Interactive_logon_Do_not_display_last_user_name                                                                 = 'Enabled'
        
        # CceId: CCE-37637-6
        # DataSource: Registry Policy
        # Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
        Interactive_logon_Do_not_require_CTRL_ALT_DEL                                                                   = 'Disabled'
        
        # CceId: CCE-36325-9
        # DataSource: Registry Policy
        # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
        Microsoft_network_client_Digitally_sign_communications_always                                                   = 'Enabled'

        # CceId: CCE-36269-9
        # DataSource: Registry Policy
        # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
        Microsoft_network_client_Digitally_sign_communications_if_server_agrees                                         = 'Enabled'

        # CceId: CCE-37863-8
        # DataSource: Registry Policy
        # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
        Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers                                   = 'Disabled'

        # CceId: CCE-37615-2
        # DataSource: Registry Policy
        # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
        Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only                                       = 'Enabled'

        # CceId: CCE-36788-8
        # DataSource: Registry Policy
        # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
        Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on                                                  = 'Disabled'

        # CceId: CCE-36347-3
        # DataSource: Registry Policy
        # Configure 'Network access: Remotely accessible registry paths and sub-paths' 
        # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
        Network_access_Remotely_accessible_registry_paths_and_subpaths                                                 = 'System\CurrentControlSet\Control\Print\Printers|#|System\CurrentControlSet\Services\Eventlog|#|Software\Microsoft\OLAP Server|#|Software\Microsoft\Windows NT\CurrentVersion\Print|#|Software\Microsoft\Windows NT\CurrentVersion\Windows|#|System\CurrentControlSet\Control\ContentIndex|#|System\CurrentControlSet\Control\Terminal Server|#|System\CurrentControlSet\Control\Terminal Server\UserConfig|#|System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration|#|Software\Microsoft\Windows NT\CurrentVersion\Perflib|#|System\CurrentControlSet\Services\SysmonLog'

        # CceId: CCE-37194-8
        # DataSource: Registry Policy
        # Configure 'Network access: Remotely accessible registry paths' 
        # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
        Network_access_Remotely_accessible_registry_paths                                                               = 'System\CurrentControlSet\Control\ProductOptions|#|System\CurrentControlSet\Control\Server Applications|#|Software\Microsoft\Windows NT\CurrentVersion'


        # CceId: CCE-36858-9
        # DataSource: Registry Policy
        # Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
        Network_security_LDAP_client_signing_requirements = 'Negotiate signing'

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' is set to 'Enabled'
        System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Enabled'

        # CceId: CCE-37623-6  
        # DataSource: Registry Policy
        # Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
        Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - local users authenticate as themselves'

        # CceId: CCE-35907-5
        # DataSource: Registry Policy
        # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
        Audit_Shut_down_system_immediately_if_unable_to_log_security_audits                                             = 'Disabled'

        # CceId: CCE-37850-5
        # DataSource: Registry Policy
        # Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
        Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'

        # CceId: CCE-37972-7
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
        Microsoft_network_server_Disconnect_clients_when_logon_hours_expire                                             = 'Enabled'

        # CceId: CCE-35988-5
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
        Microsoft_network_server_Digitally_sign_communications_if_client_agrees                                         = 'Enabled'

        # CceId: CCE-37864-6
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
        Microsoft_network_server_Digitally_sign_communications_always                                                   = 'Enabled'

        # CceId: CCE-37755-6
        # DataSource: Registry Policy
        # Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
        Network_security_Configure_encryption_types_allowed_for_Kerberos                = 'DES_CBC_CRC', 'DES_CBC_MD5', 'RC4_HMAC_MD5', 'AES128_HMAC_SHA1', 'AES256_HMAC_SHA1', 'FUTURE'

        # CceId: CCE-37701-0
        # DataSource: Registry Policy
        # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
        Devices_Allowed_to_format_and_eject_removable_media                                                             = 'Administrators'

        # CceId: CCE-37942-0
        # DataSource: Registry Policy
        # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
        Devices_Prevent_users_from_installing_printer_drivers                                                           = 'Enabled'

        # CceId: CCE-38341-4
        # DataSource: Registry Policy
        # Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
        Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM                                           = 'Enabled'

        # CceId: CCE-38047-7
        # DataSource: Registry Policy
        # Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
        Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities                  = 'Disabled'

        # CceId: CCE-36148-5
        # DataSource: Registry Policy
        # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
        Network_access_Let_Everyone_permissions_apply_to_anonymous_users                                                = 'Disabled'

        # CceId: CCE-36148-5
        # DataSource: Registry Policy
        # Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
        Network_security_Allow_LocalSystem_NULL_session_fallback                                                = 'Disabled'

        # CceId: CCE-38046-9
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute, but not 0'
        Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'


        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Devices: Allow undock without having to log on' is set to 'Enabled'
        Devices_Allow_undock_without_having_to_log_on                                                = 'Disabled'

        # CceId: CCE-37701-0
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
        User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode            = 'Prompt for consent on the secure desktop'

        }
        
        # CceId: CCE-37864-6
        # DataSource: Registry Policy
        # Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
        <#Registry 'SupportedEncryptionTypes' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Sofware\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueName = 'SupportedEncryptionTypes'
            ValueType = 'DWord'
            ValueData = '2147483644'
        }#>

         # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow Cortana above lock screen' is set to 'Disabled'
        Registry 'AllowCortanaAboveLock' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortanaAboveLock'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)
        <#Registry 'RestrictRemoteSam' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictRemoteSam'
            ValueType = 'DWord'
            ValueData = 'O:BAG:BAD:(A  RC   BA)'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
        Registry 'NullSessionShares' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName = 'NullSessionShares'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36173-3
        # DataSource: Registry Policy
        # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
        Registry 'LmCompatibilityLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'LmCompatibilityLevel'
            ValueType = 'DWord'
            ValueData = '5'
        }

        # CceId: CCE-37835-6
        # DataSource: Registry Policy
        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinServerSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinServerSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }

        # CceId: CCE-37553-5 
        # DataSource: Registry Policy
        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinClientSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinClientSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }



        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: CCE-36863-9 
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled' 
        Registry 'EnableUIADesktopToggle' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableUIADesktopToggle'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow Cortana' is set to 'Disabled'
        Registry 'AllowCortana' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortana'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Enable 'Turn on behavior monitoring'
        Registry 'DisableBehaviorMonitoring' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection'
            ValueName = 'DisableBehaviorMonitoring'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Enable 'Send file samples when further analysis is required' for 'Send Safe Samples'
        Registry 'SubmitSamplesConsent' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet'
            ValueName = 'SubmitSamplesConsent'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Scan removable drives' is set to 'Enabled'
        Registry 'DisableRemovableDriveScanning' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
            ValueName = 'DisableRemovableDriveScanning'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Detect change from default RDP port' is configured
        Registry 'PortNumber' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp'
            ValueName = 'PortNumber'
            ValueType = 'DWord'
            ValueData = '3389'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow search and Cortana to use location' is set to 'Disabled'
        Registry 'AllowSearchToUseLocation' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowSearchToUseLocation'
            ValueType = 'DWord'
            ValueData = '0'
        }

       

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow Input Personalization' is set to 'Disabled'
        Registry 'AllowInputPersonalization' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization'
            ValueName = 'AllowInputPersonalization'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Shutdown: Clear virtual memory pagefile' is set to 'Enabled'
        Registry 'ClearPageFileAtShutdown' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management'
            ValueName = 'ClearPageFileAtShutdown'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Recovery console: Allow floppy copy and access to all drives and all folders' is set to 'Disabled'
        Registry 'AllowAllPaths' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand'
            ValueName = 'AllowAllPaths'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36864-7
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
        Registry 'ConsentPromptBehaviorUser' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'ConsentPromptBehaviorUser'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Specify the interval to check for definition updates' is set to 'Enabled:1'
        Registry 'SignatureUpdateInterval' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Signature Updates'
            ValueName = 'SignatureUpdateInterval'
            ValueType = 'DWord'
            ValueData = '8'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Allow unicast response' is set to 'No'
        Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Allow unicast response' is set to 'No'
        <#Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Allow unicast response' is set to 'No'
        <#Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '0'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
        Registry 'AllowLocalPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'AllowLocalPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37346-4
        # DataSource: Registry Policy
        # Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
        Registry 'EnableAuthEpResolution' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName = 'EnableAuthEpResolution'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37843-0
        # DataSource: Registry Policy
        # Ensure 'Enable Windows NTP Client' is set to 'Enabled'
        Registry 'NTPClientEnabled' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36512-2
        # DataSource: Registry Policy
        # Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
        Registry 'EnumerateAdministrators' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueName = 'EnumerateAdministrators'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36925-6
        # DataSource: Registry Policy
        # Ensure 'Include command line in process creation events' is set to 'Disabled'
        Registry 'ProcessCreationIncludeCmdLine_Enabled' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType = 'DWord'
            ValueData = '1'
        }

        
        # CceId: CCE-36254-1
        # DataSource: Registry Policy
        # Ensure 'Allow Basic authentication' is set to 'Disabled'
        Registry 'AllowBasic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowBasic'
            ValueType = 'DWord'
            ValueData = '0'
        } 
        

        # CceId: CCE-38338-0
        # DataSource: Registry Policy
        # Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
        Registry 'fMinimizeConnections' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueName = 'fMinimizeConnections'
            ValueType = 'DWord'
            ValueData = '1'
        }

        

        # CceId: CCE-36977-7
        # DataSource: Registry Policy
        # Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
        Registry 'DisableAutomaticRestartSignOn' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37526-1
        # DataSource: Registry Policy
        # Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSetupLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # CceId: CCE-38276-2
        # DataSource: Registry Policy
        # Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSetupLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # CceId: CCE-38217-6
        # DataSource: Registry Policy
        # Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
        Registry 'NoAutorun' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoAutorun'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37695-4
        # DataSource: Registry Policy
        # Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
        Registry 'MaxSizeSecurityLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '196700'
        }

        # CceId: CCE-37145-0
        # DataSource: Registry Policy
        # Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSecurityLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # CceId: CCE-38002-2
        # DataSource: Registry Policy
        # Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
        Registry 'NC_AllowNetBridge_NLA' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_AllowNetBridge_NLA'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38348-9
        # DataSource: Registry Policy
        # Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
        Registry 'NoLockScreenSlideshow' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenSlideshow'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38347-1
        # DataSource: Registry Policy
        # Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' 
        Registry 'NoLockScreenCamera' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenCamera'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37126-0
        # DataSource: Registry Policy
        # Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
        Registry 'DisableEnclosureDownload' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName = 'DisableEnclosureDownload'
            ValueType = 'DWord'
            ValueData = '1'
        }

        

        # CceId: CCE-36326-7 
        # DataSource: Registry Policy
        # Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' 
        Registry 'NoLMHash' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'NoLMHash'
            ValueType = 'DWord'
            ValueData = '1'
        }

        

        # CceId:  
        # DataSource: Registry Policy
        # Ensure 'Continue experiences on this device' is set to 'Disabled' 
        Registry 'EnableCdp' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableCdp'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36388-7
        # DataSource: Registry Policy
        # Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
        Registry 'OfferRemoteAssistance' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'OfferRemoteAssistance'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37912-3
        # DataSource: Registry Policy
        # Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
        Registry 'DriverLoadPolicy' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName = 'DriverLoadPolicy'
            ValueType = 'DWord'
            ValueData = '3'
        }
        
        

        # CceId: CCE-37775-4
        # DataSource: Registry Policy
        # Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionApplicationLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        

        # CceId: CCE-36000-8
        # DataSource: Registry Policy
        # Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
        Registry 'DisableRunAs' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'DisableRunAs'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38318-2
        # DataSource: Registry Policy
        # Ensure 'Disallow Digest authentication' is set to 'Enabled'
        Registry 'AllowDigest' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowDigest'
            ValueType = 'DWord'
            ValueData = '0'
        }

        

        # CceId: CCE-37636-8
        # DataSource: Registry Policy
        # Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
        Registry 'NoAutoplayfornonVolume' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoAutoplayfornonVolume'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38354-7
        # DataSource: Registry Policy
        # Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
        Registry 'MSAOptional' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'MSAOptional'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
        Registry 'AllowIndexingEncryptedStoresOrItems' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
        Registry 'BlockUserFromSh owingAccountDetailsOnSignin' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'BlockUserFromShowingAccountDetailsOnSignin'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)
        Registry 'RestrictAnonymousSAM' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictAnonymousSAM'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36077-6
        # DataSource: Registry Policy
        # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)
        Registry 'RestrictAnonymous' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictAnonymous'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37567-5
        # DataSource: Registry Policy
        # Ensure 'Require secure RPC communication' is set to 'Enabled'
        Registry 'fEncryptRPCTraffic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEncryptRPCTraffic'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: NOT_ASSIGNED
        # Control no: AZ-WIN-00143
        # DataSource: Registry Policy
        # Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
        Registry 'NC_PersonalFirewallConfig' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_PersonalFirewallConfig'
            ValueType = 'DWord'
            ValueData = '0'
        }

        

        # CceId: CCE-37534-5
        # DataSource: Registry Policy
        # Ensure 'Do not display the password reveal button' is set to 'Enabled'
        Registry 'DisablePasswordReveal' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
            ValueName = 'DisablePasswordReveal'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36627-8
        # DataSource: Registry Policy
        # Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
        Registry 'MinEncryptionLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'DWord'
            ValueData = '3'
        }

        

        # CceId: CCE-37490-0
        # DataSource: Registry Policy
        # Ensure 'Always install with elevated privileges' is set to 'Disabled'
        Registry 'AlwaysInstallElevated' {
            Ensure    = 'Present'
            Key       = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'AlwaysInstallElevated'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36400-0
        # DataSource: Registry Policy
        # Ensure 'Allow user control over installs' is set to 'Disabled'
        Registry 'EnableUserControl' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueName = 'EnableUserControl'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38223-4
        # DataSource: Registry Policy
        # Ensure 'Allow unencrypted traffic' is set to 'Disabled'
        Registry 'AllowUnencryptedTraffic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37726-7 
        # DataSource: Registry Policy
        # Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'
        Registry 'AllowTelemetry' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36223-6
        # DataSource: Registry Policy
        # Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
        Registry 'DisablePasswordSaving' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DisablePasswordSaving'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37946-1
        # DataSource: Registry Policy
        # Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
        Registry 'DeleteTempDirsOnExit' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DeleteTempDirsOnExit'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38353-9
        # DataSource: Registry Policy
        # Ensure 'Do not display network selection UI' is set to 'Enabled'
        Registry 'DontDisplayNetworkSelectionUI' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37929-7
        # DataSource: Registry Policy
        # Ensure 'Always prompt for password upon connection' is set to 'Enabled'
        Registry 'fPromptForPassword' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueType = 'DWord'
            ValueData = '1'
        }

        

        # CceId: CCE-37948-7
        # DataSource: Registry Policy
        # Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeApplication' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # CceId: CCE-37948-7
        # DataSource: Registry Policy
        # Ensure 'Do not show feedback notifications' is set to 'Enabled'
        Registry 'DoNotShowFeedbackNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'DoNotShowFeedbackNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38180-6
        # DataSource: Registry Policy
        # Ensure 'Do not use temporary folders per session' is set to 'Disabled'
        Registry 'PerSessionTempDir' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'PerSessionTempDir'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Enable insecure guest logons' is set to 'Disabled'
        Registry 'AllowInsecureGuestAuth' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36021-4
        # DataSource: Registry Policy
        # Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
        Registry 'RestrictNullSessAccess' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName = 'RestrictNullSessAccess'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37528-7
        # DataSource: Registry Policy
        # Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
        Registry 'AllowDomainPINLogon' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
            ValueName = 'AllowDomainPINLogon'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36494-3
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
        Registry 'FilterAdministratorToken' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'FilterAdministratorToken'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37861-2
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
        <#Registry 'AllowLocalPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }#>

        

        # CceId: CCE-38239-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPrivate' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36268-1
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalIPsecPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }#>

        # CceId: CCE-37330-8
        # DataSource: Registry Policy
        # Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'
        Registry 'UserAuthentication' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'UserAuthentication'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37330-8
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
        Registry 'turuoffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'turuoffNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36875-3
        # DataSource: Registry Policy
        # Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
        Registry 'NoDriveTypeAutoRun' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'DWord'
            ValueData = '255'
        }

        # CceId: CCE-36146-9 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
        Registry 'OutboundActionDefault' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
            ValueName = 'OutboundActionDefault'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37621-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No''
        Registry 'DisableNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DisableNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36625-2
        # DataSource: Registry Policy
        # Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
        Registry 'DisableWebPnPDownload' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
            ValueName = 'DisableWebPnPDownload'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37064-0
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
        Registry 'EnableVirtualization' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableVirtualization'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37064-0
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
        Registry 'PromptOnSecureDesktop' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'PromptOnSecureDesktop'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36869-6 
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
        Registry 'EnableLUA' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableLUA'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36869-6 
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
        Registry 'EnableInstallerDetection' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableInstallerDetection'
            ValueType = 'DWord'
            ValueData = '1'
        }

        
        # CceId: CCE-36062-8
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallDomain' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

         # CceId: CCE-37809-1
        # DataSource: Registry Policy
        # Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
        Registry 'NoDataExecutionPrevention' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoDataExecutionPrevention'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-35893-7
        # DataSource: Registry Policy
        # Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' 
        Registry 'DisableLockScreenAppNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DisableLockScreenAppNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36092-5
        # DataSource: Registry Policy
        # Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSystemLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36160-0
        # DataSource: Registry Policy
        # Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSystemLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # CceId: CCE-37644-2
        # DataSource: Registry Policy
        # Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
        Registry 'ProtectionMode' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'
            ValueName = 'ProtectionMode'
            ValueType = 'String'
            ValueData = '1'
        }

        # CceId: CCE-37885-1 
        # DataSource: Registry Policy
        # Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
        Registry 'ObCaseInsensitive' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'
            ValueName = 'ObCaseInsensitiv'
            ValueType = 'String'
            ValueData = '1'
        }

        # CceId: CCE-37862-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPublic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37434-8 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)
        Registry 'OutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'OutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37434-8 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
        Registry 'DefaultOutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36660-9
        # DataSource: Registry Policy
        # Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
        Registry 'NoHeapTerminationOnCorruption' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoHeapTerminationOnCorruption'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38041-0 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
        Registry 'OffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
            ValueName = 'OffNotifications'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37163-3 
        # DataSource: Registry Policy
        # Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
        Registry 'ExitOnMSICW' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
            ValueName = 'ExitOnMSICW'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
        Registry 'DisableWindowsConsumerFeatures' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37450-4 
        # DataSource: Registry Policy
        # Ensure 'Turn off multicast name resolution' is set to 'Enabled' 
        Registry 'EnableMulticast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName = 'EnableMulticast'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36809-2 
        # DataSource: Registry Policy
        # Ensure 'Turn off shell protocol protected mode' is set to 'Disabled' 
        Registry 'PreXPSP2ShellProtocolBehavior' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explore r'
            ValueName = 'PreXPSP2ShellProtocolBehavior'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37057-7 
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' 
        Registry 'EnableSecureUIAPaths' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableSecureUIAPaths'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-35859-8  
        # DataSource: Registry Policy
        # Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' 
        Registry 'EnableSmartScreen' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableSmartScreen'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37281-3
        # DataSource: Registry Policy
        # Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
        Registry 'fAllowToGetHelp' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fAllowToGetHelp'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36940-5
        # DataSource: Registry Policy
        # Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'
        Registry 'LocalSettingOverrideSpynetReporting' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'LocalSettingOverrideSpynetReporting'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Configure SMB v1 server' is set to 'Disabled'
        Registry 'SMB1' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName = 'SMB1'
            ValueType = 'DWord'
            ValueData = '0'
        }
    }
}
CSBP_WindowsServer2019

