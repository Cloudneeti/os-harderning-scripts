<#
.SYNOPSIS
    DSC script to harden Windows Server 2012 R2 VM baseline policies for CSBP.
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
    
    .\CSBP_WindowsServer2012_R2.ps1 [Script will generate MOF files in directory]
    Start-DscConfiguration -Path .\CSBP_WindowsServer2012_R2  -Force -Verbose -Wait
#>

# Configuration Definition
Configuration CSBP_WindowsServer2012_R2 {
    param (
        [string[]]$ComputerName ='localhost'
        )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
	Import-DscResource -ModuleName 'NetworkingDsc'
 
    Node $ComputerName {
      AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'

            # CceId: CCE-37166-6
            # DataSource: Security Policy
            # Ensure 'Enforce password history' is set to '24 or more password'
            Enforce_password_history                    = 24

            # CceId: CCE-37167-4
            # DataSource: Security Policy
            # Ensure 'Maximum password age' is set to '70 or fewer days, but not 0'
            Maximum_Password_Age                        = 70

            # CceId: CCE-37073-4
            # DataSource: Security Policy
            # Ensure 'Minimum password age' is set to '1 or more day'
            Minimum_Password_Age                        = 1

            # CceId: CCE-36534-6
            # DataSource: Security Policy
            # Ensure 'Minimum password length' is set to '14 or more character'
            Minimum_Password_Length                     = 14

            # CceId: CCE-37063-5
            # DataSource: Security Policy
            # Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'

            # CceId: CCE-36286-3
            # DataSource: Security Policy
            # Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }

        # CceId: CCE-35818-4
        # DataSource: Security Policy
        # Configure 'Access this computer from the network'
        UserRightsAssignment Accessthiscomputerfromthenetwork {
            Policy       = 'Access_this_computer_from_the_network'
            Identity     = 'Administrators, Authenticated Users, Backup Operators'
        }

        # CceId: CCE-37072-6
        # DataSource: Security Policy
        # Configure 'Allow log on through Remote Desktop Services'
       UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
        Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
        Identity     = 'Administrators, Remote Desktop Users' 
        }
		
		# CceId: CCE-37659-0
        # DataSource: Security Policy
        # Ensure 'Allow log on locally' is set to 'Administrators'
       UserRightsAssignment Allowlogonlocally {
        Policy       = 'Allow_log_on_locally'
        Identity     = 'Administrators' 
        }

        # CceId: CCE-35823-4
        # DataSource: Security Policy
        # Configure 'Create symbolic links'
       UserRightsAssignment Createsymboliclinks {
        Policy       = 'Create_symbolic_links'
        Identity     = 'Administrators'
        }
        
        # CceId: CCE-37954-5
        # DataSource: Security Policy
        # Configure 'Deny access to this computer from the network'
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests'
         }

        # CceId: CCE-36860-5
        # DataSource: Security Policy
        # Configure 'Enable computer and user accounts to be trusted for delegation'
        UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity     = ''
         }

        # CceId: CCE-35906-7
        # DataSource: Security Policy
        # Configure 'Manage auditing and security log'
        UserRightsAssignment Manageauditingandsecuritylog {
            Policy       = 'Manage_auditing_and_security_log'
            Identity     = 'Administrators'
         }

        # CceId: CCE-37056-9
        # DataSource: Security Policy
        # Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
        UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity     = ''
         }

        # CceId: CCE-36876-1
        # DataSource: Security Policy
        # Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy       = 'Act_as_part_of_the_operating_system'
            Identity     = ''
         }

        # CceId: CCE-35912-5
        # DataSource: Security Policy
        # Ensure 'Back up files and directories' is set to 'Administrators'
        UserRightsAssignment Backupfilesanddirectories {
            Policy       = 'Back_up_files_and_directories'
            Identity     = 'Administrators,Backup Operators'
         }

        # CceId: CCE-37452-0
        # DataSource: Security Policy
        # Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethesystemtime {
            Policy       = 'Change_the_system_time'
            Identity     = 'Administrators, LOCAL SERVICE'
         }

        # CceId: CCE-37700-2
        # DataSource: Security Policy       
        # Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethetimezone {
            Policy       = 'Change_the_time_zone'
            Identity     = 'Administrators, LOCAL SERVICE'
         }

        # CceId: CCE-35821-8
        # DataSource: Security Policy
        # Ensure 'Create a pagefile' is set to 'Administrators'
        UserRightsAssignment Createapagefile {
            Policy       = 'Create_a_pagefile'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36861-3
        # DataSource: Security Policy
        # Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment Createatokenobject {
            Policy       = 'Create_a_token_object'
            Identity     = ''
         }

        # CceId: CCE-37453-8
        # DataSource: Security Policy
        # Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Createglobalobjects {
            Policy       = 'Create_global_objects'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
         }

        # CceId: CCE-36532-0
        # DataSource: Security Policy
        # Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment Createpermanentsharedobjects {
            Policy       = 'Create_permanent_shared_objects'
            Identity     = ''
         }

        # CceId: CCE-36923-1
        # DataSource: Security Policy
        # Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
         }

        # CceId: CCE-36877-9
        # DataSource: Security Policy
        # Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
         }

        # CceId: CCE-37146-8
        # DataSource: Security Policy
        # Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
         }

        # CceId: CCE-36867-0
        # DataSource: Security Policy
        # Ensure 'Deny log on through Remote Desktop Services' to include 'Guests'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests'
         }

        # CceId: CCE-37877-8
        # DataSource: Security Policy
        # Ensure 'Force shutdown from a remote system' is set to 'Administrators'
        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy       = 'Force_shutdown_from_a_remote_system'
            Identity     = 'Administrators'
         }

        # CceId: CCE-37639-2
        # DataSource: Security Policy
        # Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Generatesecurityaudits {
            Policy       = 'Generate_security_audits'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
         }

        # CceId: CCE-38326-5
        # DataSource: Security Policy
        # Ensure 'Increase scheduling priority' is set to 'Administrators'
        UserRightsAssignment Increaseschedulingpriority {
            Policy       = 'Increase_scheduling_priority'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36318-4
        # DataSource: Security Policy
        # Ensure 'Load and unload device drivers' is set to 'Administrators'
        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy       = 'Load_and_unload_device_drivers'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36495-0
        # DataSource: Security Policy
        # Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment Lockpagesinmemory {
            Policy       = 'Lock_pages_in_memory'
            Identity     = ''
         }

        # CceId: CCE-36054-5
        # DataSource: Security Policy
        # Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment Modifyanobjectlabel {
            Policy       = 'Modify_an_object_label'
            Identity     = ''
         }

        # CceId: CCE-38113-7
        # DataSource: Security Policy
        # Ensure 'Modify firmware environment values' is set to 'Administrators'
        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy       = 'Modify_firmware_environment_values'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36143-6
        # DataSource: Security Policy
        # Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
        UserRightsAssignment Performvolumemaintenancetasks {
            Policy       = 'Perform_volume_maintenance_tasks'
            Identity     = 'Administrators'
         }

        # CceId: CCE-37131-0
        # DataSource: Security Policy
        # Ensure 'Profile single process' is set to 'Administrators'
        UserRightsAssignment Profilesingleprocess {
            Policy       = 'Profile_single_process'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36052-9
        # DataSource: Security Policy
        # Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
        UserRightsAssignment Profilesystemperformance {
            Policy       = 'Profile_system_performance'
            Identity     = 'Administrators,WdiServiceHost'
         }

        # CceId: CCE-37430-6
        # DataSource: Security Policy
        # Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Replaceaprocessleveltoken {
            Policy       = 'Replace_a_process_level_token'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
         }

        # CceId: CCE-37613-7
        # DataSource: Security Policy
        # Ensure 'Restore files and directories' is set to 'Administrators, Backup Operators'
        UserRightsAssignment Restorefilesanddirectories {
            Policy       = 'Restore_files_and_directories'
            Identity     = 'Administrators, Backup Operators'
         }

        # CceId: CCE-38328-1
        # DataSource: Security Policy
        # Ensure 'Shut down the system' is set to 'Administrators'
        UserRightsAssignment Shutdownthesystem {
            Policy       = 'Shut_down_the_system'
            Identity     = 'Administrators'
         }

        # CceId: CCE-38325-7
        # DataSource: Security Policy
        # Ensure 'Take ownership of files or other objects' is set to 'Administrators'
        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy       = 'Take_ownership_of_files_or_other_objects'
            Identity     = 'Administrators'
         }

		# Control No: AZ-WIN-00119
        # DataSource: Security Policy
        # Bypass traverse checking
        UserRightsAssignment Bypasstraversechecking {
            Policy       = 'Bypass_traverse_checking'
            Identity     = 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
         }

		# Control No: AZ-WIN-00147
        # DataSource: Security Policy
        # Increase a process working set
        UserRightsAssignment Increaseaprocessworkingset {
            Policy       = 'Increase_a_process_working_set'
            Identity     = 'Administrators, Local Service'
         }
		
        # CceId: CCE-38329-9
        # DataSource: Audit Policy
        # Ensure 'Audit Application Group Management' is set to 'Success and Failure'
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

        # CceId: CCE-37741-6
        # DataSource: Audit Policy
        # Audit Policy: Account Logon: Credential Validation
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

        <# CceId: CCE-36265-7
        # DataSource: Audit Policy
        # Ensure 'Audit Distribution Group Management' is set to 'No Auditing'
        AuditPolicySubcategory 'Audit Distribution Group Management (Success)' 
        {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Distribution Group Management (Failure)' 
        {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }#>

        # CceId: CCE-38237-4
        # DataSource: Audit Policy
        # EAudit Policy: Logon-Logoff: Logoff
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

        # CceId: CCE-38036-0
        # DataSource: Audit Policy
        # Audit Policy: Logon-Logoff: Logon
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

        # CceId: CCE-37855-4
        # DataSource: Audit Policy
        # Audit Policy: Account Management: Other Account Management Events
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

        # CceId: CCE-36059-4
        # DataSource: Audit Policy
        # Audit Policy: Detailed Tracking: Process Creation
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

        # CceId: CCE-37617-8
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

        # CceId: CCE-38034-5
        # DataSource: Audit Policy
        # Audit Policy: Account Management: Security Group Management
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

        # CceId: CCE-36266-5
        # DataSource: Audit Policy
        # Audit Policy: Logon-Logoff: Special Logon
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

        # CceId: CCE-37856-2
        # DataSource: Audit Policy
        # Audit Policy: Account Management: User Account Management
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

        # Control no: AZ-WIN-00112
        # DataSource: Audit Policy
        # Audit Non Sensitive Privilege Use
        AuditPolicySubcategory 'Audit Non Sensitive Privilege Use (Success)'
        {
            Name      = 'Non Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Non Sensitive Privilege Use (Failure)'
        {
            Name      = 'Non Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # CceId: CCE-38327-3
        # DataSource: Audit Policy
        # Audit Policy: Policy Change: Authentication Policy Change
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
        
        # CceId: CCE-38114-5
        # DataSource: Audit Policy
        # Audit Policy: System: Security State Change
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
        
        # CceId: CCE-38028-7
        # DataSource: Audit Policy
        # Audit Policy: Policy Change: Audit Policy Change
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
        
        # CceId: CCE-37853-9
        # DataSource: Audit Policy
        # Audit Policy: System: IPsec Driver
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
        
        # CceId: CCE-38030-3
        # DataSource: Audit Policy
        # Audit Policy: System: Other System Events
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
        
        # CceId: CCE-36322-6
        # DataSource: Audit Policy
        # Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
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
        
        # CceId: CCE-36144-4
        # DataSource: Audit Policy
        # Audit Policy: System: Security System Extension
        AuditPolicySubcategory 'Audit Security System Extension (Success)' 
        {
            Name      = 'Security System Extension'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        
        # CceId: CCE-37133-6
        # DataSource: Audit Policy
        # Audit Policy: Logon-Logoff: Account Lockout
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
        
        # CceId: CCE-36320-0
        # DataSource: Audit Policy
        # Ensure 'Audit Authorization Policy Change' is set to 'Success'
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
        
        # CceId: CCE-37132-8
        # DataSource: Audit Policy
        # Audit Policy: System: System Integrity
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
        
        # CceId: CCE-36267-3
        # DataSource: Audit Policy
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
        
        # Control no: AZ-WIN-00108
        # DataSource: Audit Policy
        # Audit IPsec Extended Mode
        AuditPolicySubcategory 'Audit IPsec Extended Mode (Success)'
        {
            Name      = 'IPsec Extended Mode'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit IPsec Extended Mode (Failure)'
        {
            Name      = 'IPsec Extended Mode'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00100
        # DataSource: Audit Policy
        # Audit Detailed File Share
        AuditPolicySubcategory 'Audit Detailed File Share (Success)'
        {
            Name      = 'Detailed File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00105
        # DataSource: Audit Policy
        # Audit Filtering Platform Packet Drop
        AuditPolicySubcategory 'Audit Filtering Platform Packet Drop (Success)'
        {
            Name      = 'Filtering Platform Packet Drop'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Filtering Platform Packet Drop (Failure)'
        {
            Name      = 'Filtering Platform Packet Drop'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00111
        # DataSource: Audit Policy
        # Audit MPSSVC Rule-Level Policy Change
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success)'
        {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)'
        {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00110
        # DataSource: Audit Policy
        # Audit Kernel Object
        AuditPolicySubcategory 'Audit Kernel Object (Success)'
        {
            Name      = 'Kernel Object'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Kernel Object (Failure)'
        {
            Name      = 'Kernel Object'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00003
        # DataSource: Audit Policy
        # Audit IPsec Main Mode
        AuditPolicySubcategory 'Audit IPsec Main Mode (Success)'
        {
            Name      = 'IPsec Main Mode'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit IPsec Main Mode (Failure)'
        {
            Name      = 'IPsec Main Mode'
            AuditFlag = 'Failure'
        }
        
        # Control no: AZ-WIN-00102
        # DataSource: Audit Policy
        # Audit File Share
        AuditPolicySubcategory 'Audit File Share (Success)'
        {
            Name      = 'File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit File Share (Failure)'
        {
            Name      = 'File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00113
        # DataSource: Audit Policy
        # Audit Other Object Access Events
        AuditPolicySubcategory 'Audit Other Object Access Events (Success)'
        {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Failure)'
        {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00109
        # DataSource: Audit Policy
        # Audit IPsec Quick Mode
        AuditPolicySubcategory 'Audit IPsec Quick Mode (Success)'
        {
            Name      = 'IPsec Quick Mode'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit IPsec Quick Mode (Failure)'
        {
            Name      = 'IPsec Quick Mode'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00106
        # DataSource: Audit Policy
        # Audit Filtering Platform Policy Change
        AuditPolicySubcategory 'Audit Filtering Platform Policy Change (Success)'
        {
            Name      = 'Filtering Platform Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Filtering Platform Policy Change (Failure)'
        {
            Name      = 'Filtering Platform Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00107
        # DataSource: Audit Policy
        # Audit Handle Manipulation
        AuditPolicySubcategory 'Audit Handle Manipulation (Success)'
        {
            Name      = 'Handle Manipulation'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Handle Manipulation (Failure)'
        {
            Name      = 'Handle Manipulation'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00096
        # DataSource: Audit Policy
        # Audit Network Policy Server
        AuditPolicySubcategory 'Audit Network Policy Server (Success)'
        {
            Name      = 'Network Policy Server'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Network Policy Server (Failure)'
        {
            Name      = 'Network Policy Server'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00006
        # DataSource: Audit Policy
        # Audit Other Account Logon Events
        AuditPolicySubcategory "Audit Other Account Logon Events (Success)"
        {
            Name      = 'Other Account Logon Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Other Account Logon Events (Failure)'
        {
            Name      = 'Other Account Logon Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00104
        # DataSource: Audit Policy
        # Audit Filtering Platform Connection
        AuditPolicySubcategory 'Audit Filtering Platform Connection (Success)'
        {
            Name      = 'Filtering Platform Connection'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Filtering Platform Connection (Failure)'
        {
            Name      = 'Filtering Platform Connection'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00099
        # DataSource: Audit Policy
        # Audit Application Generated
        AuditPolicySubcategory 'Audit Application Generated (Success)'
        {
            Name      = 'Application Generated'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Application Generated (Failure)'
        {
            Name      = 'Application Generated'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00101
        # DataSource: Audit Policy
        # Audit DPAPI Activity
        AuditPolicySubcategory 'Audit DPAPI Activity (Success)'

        {
            Name      = 'DPAPI Activity'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit DPAPI Activity (Failure)'
        {
            Name      = 'DPAPI Activity'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00103
        # DataSource: Audit Policy
        # Audit File System
        AuditPolicySubcategory 'Audit File System (Success)'
        {
            Name      = 'File System'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit File System (Failure)'
        {
            Name      = 'File System'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00009
        # DataSource: Audit Policy
        # Audit Process Termination
        AuditPolicySubcategory 'Audit Process Termination (Success)'
        {
            Name      = 'Process Termination'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Process Termination (Failure)'
        {
            Name      = 'Process Termination'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00117
        # DataSource: Audit Policy
        # Audit SAM
        AuditPolicySubcategory 'Audit SAM (Success)'
        {
            Name      = 'SAM'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit SAM (Failure)'
        {
            Name      = 'SAM'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00115
        # DataSource: Audit Policy
        # Audit Registry
        AuditPolicySubcategory 'Audit Registry (Success)'
        {
            Name      = 'Registry'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        
        # Control no: AZ-WIN-00114
        # DataSource: Audit Policy
        # Audit Other Policy Change Events
        AuditPolicySubcategory 'Audit Other Policy Change Events (Success)'
        {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Other Policy Change Events (Failure)'
        {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00097
        # DataSource: Audit Policy
        # Audit Other Privilege Use Events
        AuditPolicySubcategory 'Audit Other Privilege Use Events (Success)'
        {
            Name      = 'Other Privilege Use Events'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Other Privilege Use Events (Failure)'
        {
            Name      = 'Other Privilege Use Events'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        
        # Control no: AZ-WIN-00116
        # DataSource: Audit Policy
        # Audit RPC Events
        AuditPolicySubcategory 'Audit RPC Events (Success)'
        {
            Name      = 'RPC Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit RPC Events (Failure)'
        {
            Name      = 'RPC Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        SecurityOption AccountSecurityOptions {
          Name                                   = 'AccountSecurityOptions'

          # CceId: CCE-37615-2
          # DataSource: Registry Policy
          # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
          Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'

          # CceId: CCE-35907-5
          # DataSource: Registry Policy
          # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
          Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'

          # CceId: CCE-37942-0
          # DataSource: Registry Policy
          # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
          Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'

          # CceId: CCE-36056-0
          # DataSource: Registry Policy
          # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
          Interactive_logon_Do_not_display_last_user_name = 'Enabled'

          # CceId: CCE-37637-6
          # DataSource: Registry Policy
          # Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
          Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled' 

          # CceId: CCE-36325-9
          # DataSource: Registry Policy
          # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
          Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'

          # CceId: CCE-36269-9
          # DataSource: Registry Policy
          # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
          Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'

          # CceId: CCE-37863-8
          # DataSource: Registry Policy
          # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
          Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'

          # CceId: CCE-38046-9
          # DataSource: Registry Policy
          # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute, but not 0'
          Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15' 

          # CceId: CCE-37864-6
          # DataSource: Registry Policy
          # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
          Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'

          # CceId: CCE-35988-5
          # DataSource: Registry Policy
          # Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
          Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'

          # CceId: CCE-37972-7
          # DataSource: Registry Policy
          # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
          Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled' 

          # CceId: CCE-36077-6
          # DataSource: Registry Policy
          # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'

          # CceId: CCE-36316-8
          # DataSource: Registry Policy
          # Network access: Do not allow anonymous enumeration of SAM accounts and shares
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'

          # CceId: CCE-36148-5
          # DataSource: Registry Policy
          # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
          Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled' 

          # CceId: CCE-36021-4
          # DataSource: Registry Policy
          # Network access: Restrict anonymous access to Named Pipes and Shares
          Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled' 

          # CceId: CCE-37623-6
          # DataSource: Registry Policy
          # Network access: Sharing and security model for local accounts 
          Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
          
          # CceId: CCE-37035-3
          # DataSource: Registry Policy
          # Network security: Allow LocalSystem NULL session fallback
          Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'

          # CceId: CCE-38047-7
          # DataSource: Registry Policy
          # Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
          Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'

          # CceId: CCE-36326-7
          # DataSource: Registry Policy
          # Network security: Do not store LAN Manager hash value on next password change
          Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'

          # CceId: CCE-36858-9
          # DataSource: Registry Policy
          # Network security: LDAP client signing requirements
          Network_security_LDAP_client_signing_requirements = 'Negotiate Signing' 

          # CceId: CCE-37553-5
          # DataSource: Registry Policy
          # Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
          Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
          
          # CceId: CCE-37835-6
          # DataSource: Registry Policy
          # Network security: Minimum session security for NTLM SSP based (including secure RPC) servers 
          Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'

          # CceId: CCE-36788-8
          # DataSource: Registry Policy
          # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
          Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'

          # CceId: CCE-37885-1
          # DataSource: Registry Policy
          # System objects: Require case insensitivity for non-Windows subsystems
          System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled' 

          # CceId: CCE-37644-2
          # DataSource: Registry Policy
          # System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
          System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'

          # CceId: CCE-36494-3
          # DataSource: Registry Policy
          # User Account Control: Admin Approval Mode for the Built-in Administrator account
          User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'

          # CceId: CCE-36863-9
          # DataSource: Registry Policy
          # User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop
          User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'

          # CceId: CCE-37029-6
          # DataSource: Registry Policy
          # User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
          User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'

          # CceId: CCE-36864-7
          # DataSource: Registry Policy
          # User Account Control: Behavior of the elevation prompt for standard users
          User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'

          # CceId: CCE-36533-8
          # DataSource: Registry Policy
          # User Account Control: Detect application installations and prompt for elevation
          User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'

          # CceId: CCE-37057-7
          # DataSource: Registry Policy
          # User Account Control: Only elevate UIAccess applications that are installed in secure locations
          User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'

          # CceId: CCE-36869-6
          # DataSource: Registry Policy
          # User Account Control: Run all administrators in Admin Approval Mode
          User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'

          # CceId: CCE-36866-2
          # DataSource: Registry Policy
          # User Account Control: Switch to the secure desktop when prompting for elevation
          User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'

          # CceId: CCE-37064-3
          # DataSource: Registry Policy
          # User Account Control: Virtualize file and registry write failures to per-user locations
          User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'

          # CceId: NOT_ASSIGNED
          # Control no: CCE-37307-6
          # DataSource: Registry Policy
          # Recovery console: Allow floppy copy and access to all drives and all folders
          Recovery_console_Allow_floppy_copy_and_access_to_all_drives_and_folders = 'Disabled'
          
          # CceId: CCE-38341-4
          # DataSource: Registry Policy
          # Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
          Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
          
          # CceId: CCE-38095-6
          # DataSource: Registry Policy
          # Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' 
          Network_access_Shares_that_can_be_accessed_anonymously = ''
          
          # CceId: CCE-37850-5
          # DataSource: Registry Policy
          # Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
          Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
          
          # CceId: CCE-37755-6
          # DataSource: Registry Policy
          # Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
          Network_security_Configure_encryption_types_allowed_for_Kerberos = 'RC4_HMAC_MD5','AES128_HMAC_SHA1','AES256_HMAC_SHA1','FUTURE'
          
          # CceId: CCE-37194-8
          # DataSource: Registry Policy
          # Configure 'Network access: Remotely accessible registry paths' 
          # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
          # Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, SOFTWARE\Microsoft\Windows NT\CurrentVersion'
          
          # CceId: CCE-36173-3
          # DataSource: Registry Policy
          # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
          Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
          
          # CceId: CCE-37701-0
          # DataSource: Registry Policy
          # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
          Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
          
          # CceId: CCE-36347-3
          # DataSource: Registry Policy
          # Configure 'Network access: Remotely accessible registry paths and sub-paths' 
          # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
          #Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Print, Software\Microsoft\Windows NT\CurrentVersion\Windows, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog'
          
          # CceId: CCE-37432-2
          # DataSource: Security Policy
          # Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
          Accounts_Guest_account_status = 'Disabled'
       }

       
        # CceId: NOT_ASSIGNED
		# Control no: AZ-WIN-00167
        # DataSource: Registry Policy
        # Disable SMB v1 server
		Registry 'SMB1' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters'
           ValueName    = 'SMB1'
           ValueType    = 'DWord'
           ValueData    = '0'
        }

        # CceId: NOT_ASSIGNED
		# Control no: AZ-WIN-00124
        # DataSource: Registry Policy
        # Disable Windows Search Service
		Registry 'Start' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Wsearch'
          ValueName    = 'Start'
          ValueType    = 'DWord'
          ValueData    = '4'
        }
		
	    # CceId: CCE-38002-2
        # DataSource: Registry Policy
        # Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
        Registry 'NC_AllowNetBridge_NLA' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
           ValueName    = 'NC_AllowNetBridge_NLA'
           ValueType    = 'DWord'
           ValueData    = '0'
        }

        # CceId: NOT_ASSIGNED
		# Control no: AZ-WIN-00143
        # DataSource: Registry Policy
        # Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
        Registry 'NC_PersonalFirewallConfig' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
          ValueName    = 'NC_PersonalFirewallConfig'
          ValueType    = 'DWord'
          ValueData    = '0'
        }

        # CceId: CCE-37528-7
        # DataSource: Registry Policy
        # Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
        Registry 'AllowDomainPINLogon' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
           ValueName  = 'AllowDomainPINLogon'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: CCE-36388-7
        # DataSource: Registry Policy
        # Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
        Registry 'fAllowUnsolicited' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
           ValueName  = 'fAllowUnsolicited'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: CCE-37281-3
        # DataSource: Registry Policy
        # Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
        Registry 'fAllowToGetHelp' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
           ValueName  = 'fAllowToGetHelp'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: NOT_ASSIGNED
		# CceId: CCE-38335-6
        # DataSource: Registry Policy
        # Shutdown: Clear virtual memory pagefile
        Registry 'ClearPageFileAtShutdown' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management'
          ValueName  = 'ClearPageFileAtShutdown'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # CceId: CCE-36512-2
        # DataSource: Registry Policy
        # Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
       Registry 'EnumerateAdministrators' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
          ValueName  = 'EnumerateAdministrators'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # CceId: CCE-37809-1
        # DataSource: Registry Policy
        # Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
        Registry 'NoDataExecutionPrevention' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoDataExecutionPrevention'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # CceId: CCE-36660-9
        # DataSource: Registry Policy
        # Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
        Registry 'NoHeapTerminationOnCorruption' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoHeapTerminationOnCorruption'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # CceId: CCE-36809-2
        # DataSource: Registry Policy
        # Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
        Registry 'PreXPSP2ShellProtocolBehavior' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'PreXPSP2ShellProtocolBehavior'
          ValueType  = 'DWord'
          ValueData  = '0'
        }


        # CceId: CCE-36400-0
        # DataSource: Registry Policy
        # Ensure 'Allow user control over installs' is set to 'Disabled'
        Registry 'EnableUserControl' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
          ValueName  = 'EnableUserControl'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # CceId: CCE-36977-7
        # DataSource: Registry Policy
        # Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
        Registry 'DisableAutomaticRestartSignOn' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'DisableAutomaticRestartSignOn'
          ValueType  = 'DWord'
          ValueData  = '1'
        }

        # CceId: CCE-36254-1
        # DataSource: Registry Policy
        # Ensure 'Allow Basic authentication' is set to 'Disabled'
       Registry 'AllowBasic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowBasic'
          ValueType  = 'DWord'
          ValueData  = '0'
       } 

        # CceId: CCE-38223-4
        # DataSource: Registry Policy
        # Ensure 'Allow unencrypted traffic' is set to 'Disabled'
       Registry 'AllowUnencryptedTraffic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowUnencryptedTraffic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: CCE-38318-2
        # DataSource: Registry Policy
        # Ensure 'Disallow Digest authentication' is set to 'Enabled'
        Registry 'AllowDigest' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowDigest'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: CCE-37490-0
        # DataSource: Registry Policy
        # Ensure 'Always install with elevated privileges' is set to 'Disabled'
        Registry 'AlwaysInstallElevated' {
           Ensure       = 'Present'
           Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer'
           ValueName    = 'AlwaysInstallElevated'
           ValueType    = 'DWord'
           ValueData    = '0'
        }
        
        # CceId: CCE-38354-7
        # DataSource: Registry Policy
        # Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
        Registry 'MSAOptional' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName  = 'MSAOptional'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-38353-9
        # DataSource: Registry Policy
        # Ensure 'Do not display network selection UI' is set to 'Enabled'
        Registry 'DontDisplayNetworkSelectionUI' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'DontDisplayNetworkSelectionUI'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-38347-1
        # DataSource: Registry Policy
        # Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' 
        Registry 'NoLockScreenCamera' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName  = 'NoLockScreenCamera'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-35893-7
        # DataSource: Registry Policy
        # Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' 
        Registry 'DisableLockScreenAppNotifications' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'DisableLockScreenAppNotifications'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-38348-9
        # DataSource: Registry Policy
        # Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
        Registry 'NoLockScreenSlideshow' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName    = 'NoLockScreenSlideshow'
            ValueType    = 'DWord'
            ValueData    = '1'
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
        
        # CceId: CCE-38276-2
        # DataSource: Registry Policy
        # Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSetupLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }
        
        # CceId: CCE-38217-6
        # DataSource: Registry Policy
        # Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
        Registry 'NoAutorun' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName  = 'NoAutorun'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-38180-6
        # DataSource: Registry Policy
        # Ensure 'Do not use temporary folders per session' is set to 'Disabled'
        Registry 'PerSessionTempDir' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'PerSessionTempDir'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-37946-1
        # DataSource: Registry Policy
        # Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
        Registry 'DeleteTempDirsOnExit' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'DeleteTempDirsOnExit'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-37929-7
        # DataSource: Registry Policy
        # Ensure 'Always prompt for password upon connection' is set to 'Enabled'
        Registry 'fPromptForPassword' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fPromptForPassword'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-37912-3
        # DataSource: Registry Policy
        # Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
        Registry 'DriverLoadPolicy' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName  = 'DriverLoadPolicy'
            ValueType  = 'DWord'
            ValueData  = '3'
        }
        
        # CceId: CCE-37775-4
        # DataSource: Registry Policy
        # Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionApplicationLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }
        
        # CceId: CCE-36925-6
        # DataSource: Registry Policy
        # Ensure 'Include command line in process creation events' is set to 'Disabled'
        Registry 'ProcessCreationIncludeCmdLine_Enabled' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName  = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-37636-8
        # DataSource: Registry Policy
        # Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
        Registry 'NoAutoplayfornonVolume' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName  = 'NoAutoplayfornonVolume'
            ValueType  = 'DWord'
            ValueData  = '1'
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
        
        # CceId: CCE-37126-0
        # DataSource: Registry Policy
        # Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
        Registry 'DisableEnclosureDownload' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName  = 'DisableEnclosureDownload'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-37534-5
        # DataSource: Registry Policy
        # Ensure 'Do not display the password reveal button' is set to 'Enabled'
        Registry 'DisablePasswordReveal' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
            ValueName   = 'DisablePasswordReveal'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        
        # CceId: CCE-36223-6
        # DataSource: Registry Policy
        # Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
        Registry 'DisablePasswordSaving' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'DisablePasswordSaving'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-37567-5
        # DataSource: Registry Policy
        # Ensure 'Require secure RPC communication' is set to 'Enabled'
        Registry 'fEncryptRPCTraffic' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fEncryptRPCTraffic'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-36625-2
        # DataSource: Registry Policy
        # Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
        Registry 'DisableWebPnPDownload' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
            ValueName  = 'DisableWebPnPDownload'
            ValueType  = 'DWord'
            ValueData  = '0'
        }
        
        # CceId: CCE-36160-0
        # DataSource: Registry Policy
        # Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSystemLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }
        
        # CceId: CCE-36627-8
        # DataSource: Registry Policy
        # Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
        Registry 'MinEncryptionLevel' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'MinEncryptionLevel'
            ValueType  = 'DWord'
            ValueData  = '3'
        }
        
        # CceId: CCE-37695-4
        # DataSource: Registry Policy
        # Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
        Registry 'MaxSizeSecurityLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '196608'
        }
        
        # CceId: CCE-37621-0
        # DataSource: Registry Policy
        # Windows Firewall: Private: Display a notification
        Registry 'DisableNotificationsPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'DisableNotifications'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
        
        # CceId: CCE-36092-5
        # DataSource: Registry Policy
        # Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSystemLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '32768'
        }
        
        # CceId: CCE-37526-1
        # DataSource: Registry Policy
        # Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSetupLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName  = 'MaxSize'
            ValueType  = 'DWord'
            ValueData  = '32768'
        }
        
        # CceId: CCE-37145-0
        # DataSource: Registry Policy
        # Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSecurityLog' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName  = 'Retention'
            ValueType  = 'String'
            ValueData  = '0'
        }
        
        # CceId: CCE-36875-3
        # DataSource: Registry Policy
        # Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
        Registry 'NoDriveTypeAutoRun' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName  = 'NoDriveTypeAutoRun'
            ValueType  = 'DWord'
            ValueData  = '255'
        }
        
        # CceId: CCE-37346-4
        # DataSource: Registry Policy
        # Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
        Registry 'EnableAuthEpResolution' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName  = 'EnableAuthEpResolution'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Control no: AZ-WIN-00152
        # DataSource: Registry Policy
        # Specify the interval to check for definition updates
        Registry 'SignatureUpdateInterval' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Signature Updates'
            ValueName  = 'SignatureUpdateInterval'
            ValueType  = 'DWord'
            ValueData  = '8'
        }
        
        # CceId: CCE-37843-0
        # DataSource: Registry Policy
        # Ensure 'Enable Windows NTP Client' is set to 'Enabled'
        Registry 'NTPClientEnabled' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
            ValueName  = 'Enabled'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Control no: AZ-WIN-00120
        # DataSource: Registry Policy
        # Devices: Allow undock without having to log on
        Registry 'UndockWithoutLogon' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName  = 'UndockWithoutLogon'
            ValueType  = 'DWord'
            ValueData  = '0'
        }
        
        # CceId: CCE-37860-4
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
        Registry 'AllowLocalPolicyMergeDomain' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName  = 'AllowLocalPolicyMerge'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-37438-9
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
        Registry 'AllowLocalPolicyMergePrivate' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName  = 'AllowLocalPolicyMerge'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Control no: AZ-WIN-00090
        # DataSource: Registry Policy
        # Windows Firewall: Public: Allow unicast response
        Registry 'DisableUnicastResponsesToMulticastBroadcastPublic' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName  = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-37163-3
        # DataSource: Registry Policy
        # Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
        Registry 'ExitOnMSICW' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
            ValueName  = 'ExitOnMSICW'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Control no: AZ-WIN-00149
        # DataSource: Registry Policy
        # Require user authentication for remote connections by using Network Level Authentication
        Registry 'UserAuthentication' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'UserAuthentication'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-37172-4
        # DataSource: Registry Policy
        # System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies
        Registry 'AuthenticodeEnabled' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
            ValueName  = 'AuthenticodeEnabled'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-38043-6
        # DataSource: Registry Policy
        # Windows Firewall: Public: Display a notification
        Registry 'DisableNotificationsPublic' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName  = 'DisableNotifications'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # CceId: CCE-38041-0
        # DataSource: Registry Policy
        # Windows Firewall: Domain: Display a notification
        Registry 'DisableNotificationsDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'DisableNotifications'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        
        # CceId: CCE-36062-8
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
        }
        
        # CceId: CCE-36146-9
        # DataSource: Registry Policy
        # Windows Firewall: Domain: Outbound connections
        Registry 'DefaultOutboundActionDomain' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'DefaultOutboundAction'
            ValueType   = 'DWord'
            ValueData   = '0'
        }
        
        # CceId: CCE-38040-2
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
        Registry 'AllowLocalIPsecPolicyMergeDomain' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName  = 'AllowLocalIPsecPolicyMerge'
            ValueType  = 'DWord'
            ValueData  = '1'
        }

        # Control no: AZ-WIN-00088
        # DataSource: Registry Policy
        # Windows Firewall: Domain: Allow unicast response
        Registry 'DisableUnicastResponsesToMulticastBroadcastDomain' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName  = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType  = 'DWord'
            ValueData  = '0'
        }
        
        # CceId: CCE-38332-3
        # DataSource: Registry Policy	
        # Windows Firewall: Private: Outbound connections
        Registry 'DefaultOutboundActionPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'DefaultOutboundAction'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
        
        # CceId: CCE-38239-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPrivate' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName    = 'EnableFirewall'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
        
        # CceId: CCE-36063-6
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'
        Registry 'AllowLocalIPsecPolicyMergePrivate' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName  = 'AllowLocalIPsecPolicyMerge'
            ValueType  = 'DWord'
            ValueData  = '1'
        }
        
        # Control no: AZ-WIN-00089
        # DataSource: Registry Policy
        # Windows Firewall: Private: Allow unicast response
        Registry 'DisableUnicastResponsesToMulticastBroadcastPrivate' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName  = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType  = 'DWord'
            ValueData  = '0'
        }
        
        <# CceId: CCE-37861-2
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
        Registry 'AllowLocalPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
        
        # CceId: CCE-36268-1
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
        Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalIPsecPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
        
        # CceId: CCE-37434-8
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
        Registry 'DefaultOutboundActionPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'DefaultOutboundAction'
            ValueType    = 'DWord'
            ValueData    = '0'
        }#>

        # CceId: CCE-37862-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'EnableFirewall'
            ValueType    = 'DWord'
            ValueData    = '1'
        }
        
        # CceId: CCE-37948-7
        # DataSource: Registry Policy
        # Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeApplication' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '32768'
        }

       	# CceId: CCE-36978-5
        # DataSource: Registry Policy
        # Ensure 'Automatically send memory dumps for OS-generated error reports' is set to 'Disabled'
        Registry 'AutoApproveOSDumps' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
          ValueName  = 'AutoApproveOSDumps'
          ValueType  = 'DWord'
          ValueData  = '0'
        }
        
        # CceId: CCE-37112-0
        # DataSource: Registry Policy
        # Ensure 'Configure Default consent' is set to 'Enabled: Send all data'
        Registry 'DefaultConsent' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent'
          ValueName  = 'DefaultConsent'
          ValueType  = 'DWord'
          ValueData  = '4'
        }
        
        # CceId: CCE-37348-0
        # DataSource: Registry Policy
        # Ensure 'Always use classic logon' is set to 'Enabled'
        Registry 'LogonType' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'LogonType'
          ValueType  = 'DWord'
          ValueData  = '0'
        } 
    }
 }

CSBP_WindowsServer2012_R2