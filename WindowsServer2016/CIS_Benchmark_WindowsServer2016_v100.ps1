<#
.SYNOPSIS
    DSC script to harden Windows Server 2016 VM baseline policies.

.DESCRIPTION
   This script aims to harden Windows Server 2016 VM baseline policies using Desired State Configurations (DSC) for CIS Benchmark Windows Server 2016 Version 1.0.0 supported by ZCSPM.

.NOTE

    Copyright (c) ZCSPM. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    # PREREQUISITE
    * Windows PowerShell version 5 and above
        1. To check PowerShell version type "$PSVersionTable.PSVersion" in PowerShell and you will find PowerShell version,
        2. To Install powershell follow link https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell?view=powershell-6
    * DSC modules should be installed
        1. AuditPolicyDsc
        2. SecurityPolicyDsc
        3. NetworkingDsc
        4. PSDesiredStateConfiguration
        
        To check Azure AD version type "Get-InstalledModule -Name <ModuleName>" in PowerShell window
        You can Install the required modules by executing below command.
            Install-Module -Name <ModuleName> -MinimumVersion <Version>

.EXAMPLE
    
    .\CIS_Benchmark_WindowsServer2016_v100.ps1 [Script will generate MOF files in directory]
    Start-DscConfiguration -Path .\CIS_Benchmark_WindowsServer2016_v1_0_0  -Force -Verbose -Wait

#>

Configuration CIS_Benchmark_WindowsServer2016_v1_0_0 {
   param (
      [string[]]$ComputerName ='localhost'
   )

   # Import DSC, OS Baseline Modules
   Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
   Import-DscResource -ModuleName 'AuditPolicyDsc'
   Import-DscResource -ModuleName 'SecurityPolicyDsc'
   Import-DscResource -ModuleName 'NetworkingDsc'

   Node $ComputerName {
      
      # 1. ACCOUNT POLICIES
      AccountPolicy AccountPolicies
      {
         # 1.1 Password Policies
         Name                                        = 'PasswordPolicies'
         # 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
         Enforce_password_history                    = 24
         # 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
         Maximum_Password_Age                        = 60
         # 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
         Minimum_Password_Age                        = 1
         # 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
         Minimum_Password_Length                     = 14
         # 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
         Password_must_meet_complexity_requirements  = 'Enabled'
         # 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
         Store_passwords_using_reversible_encryption = 'Disabled'            
      }

      # 2. LOCAL POLICIES

      # 2.2 User Right Assignments
      #  2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
      UserRightsAssignment Generatesecurityaudits {
         Policy       = 'Generate_security_audits'
         Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
      }

      #  2.2.37 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'
      UserRightsAssignment Manageauditingandsecuritylog {
         Policy       = 'Manage_auditing_and_security_log'
         Identity     = 'Administrators'
      }

      # 2.3 Security Option
      SecurityOption AccountSecurityOptions {
         Name                                   = 'AccountSecurityOptions'

         # 2.3.1 Accounts
         # 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
         Accounts_Guest_account_status          = 'Disabled'
         # 2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'

         # 2.3.2 Audit   
         # 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
         Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
         # 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
         Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'

         # 2.3.4 Devices
         # 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
         Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
         # 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
         Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
         
         # 2.3.7 Interactive Login
         # 2.3.7.1 (L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
         Interactive_logon_Do_not_display_last_user_name = 'Enabled' 
         # 2.3.7.2 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
         Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled' 
         
         # 2.3.8 Microsoft network client
         # 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' 
         Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
         # 2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' 
         Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
         # 2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
         Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
         
         # 2.3.8 Microsoft network server        
         # 2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
         Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15' 
         # 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' 
         Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
         # 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled' 
         Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
         # 2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
         Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled' 

         # 2.3.10 Netowrk access
         # 2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only) 
         Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
         # 2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only) 
         Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
         # 2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths' 
         # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
         # Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, SOFTWARE\Microsoft\Windows NT\CurrentVersion'
         # 2.3.10.9 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths' 
         # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
         #Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Print, Software\Microsoft\Windows NT\CurrentVersion\Windows, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog'
         # 2.3.10.10 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' 
         Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled' 
         # 2.3.10.12 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' 
         Network_access_Shares_that_can_be_accessed_anonymously = ''
         # 2.3.10.13 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' 
         Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - local users authenticate as themselves'

         # 2.3.11 Network security
         # 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
         Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
         # 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' 
         Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
         # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' 
         Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
         # 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
         Network_security_Configure_encryption_types_allowed_for_Kerberos = 'AES128_HMAC_SHA1','AES256_HMAC_SHA1','FUTURE'
         # 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' 
         Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
         # 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
         Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM' 
         # 2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
         Network_security_LDAP_client_signing_requirements = 'Negotiate signing' 
         # 2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
         Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
         # 2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
         Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked' 

         # 2.3.13 Shutdown
         # 2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
         Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled' 
         
         # 2.3.15 System object
         # 2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
         System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled' 
         # 2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
         System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled' 
         
         # 2.3.17 User Account Control
         # 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
         User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
         # 2.3.17.2 (L1) Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled' 
         User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
         # 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' 
         User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
         # 2.3.17.4 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' 
         User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
         # 2.3.17.5 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' 
         User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
         # 2.3.17.6 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' 
         User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
         # 2.3.17.7 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
         User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
         # 2.3.17.8 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' 
         User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
         # 2.3.17.9 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
         User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
      }

      # 9 WINDOWS FIREWALL WITH ADVANCED SECURITY

      # 9.1 Domain Profile
      # 9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
      Registry 'EnableFirewallDomain' {
         Ensure      = 'Present'
         Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
         ValueName   = 'EnableFirewall'
         ValueType   = 'DWord'
         ValueData   = '1'
      }

      # 9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
      Registry 'DefaultOutboundActionDomain' {
         Ensure      = 'Present'
         Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
         ValueName   = 'DefaultOutboundAction'
         ValueType   = 'DWord'
         ValueData   = '0'
      }

      # 9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
      Registry 'DisableNotificationsDomain' {
         Ensure      = 'Present'
         Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
         ValueName   = 'DisableNotifications'
         ValueType   = 'DWord'
         ValueData   = '0'
      }

      # 9.2 Private Profile
      #  9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
      Registry 'EnableFirewallPrivate' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         ValueName    = 'EnableFirewall'
         ValueType    = 'DWord'
         ValueData    = '1'
      }

      #  9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
      Registry 'DefaultOutboundActionPrivate' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         ValueName    = 'DefaultOutboundAction'
         ValueType    = 'DWord'
         ValueData    = '0'
      }

      #  9.2.4 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
      Registry 'DisableNotificationsPrivate' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         ValueName    = 'DisableNotifications'
         ValueType    = 'DWord'
         ValueData    = '0'
      }

      # 9.3 Public profile
      #  9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
      Registry 'EnableFirewallPublic' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         ValueName    = 'EnableFirewall'
         ValueType    = 'DWord'
         ValueData    = '1'
      }

      #  9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
      Registry 'DefaultOutboundActionPublic' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         ValueName    = 'DefaultOutboundAction'
         ValueType    = 'DWord'
         ValueData    = '0'
      }

      #  9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
      Registry 'DisableNotificationsPublic' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         ValueName    = 'DisableNotifications'
         ValueType    = 'DWord'
         ValueData    = '0'
      }

      #  9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
      Registry 'AllowLocalPolicyMerge' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         ValueName    = 'AllowLocalPolicyMerge'
         ValueType    = 'DWord'
         ValueData    = '0'
      }

      #  9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
      Registry 'AllowLocalIPsecPolicyMerge' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         ValueName    = 'AllowLocalIPsecPolicyMerge'
         ValueType    = 'DWord'
         ValueData    = '0'
      }

      # 17. ADVANCED AUDIT POLICY CONFIGURATION

      # 17.1 Account Logon
      # 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
      AuditPolicySubcategory "Audit Credential Validation (Success)"
      {
         Name      = 'Credential Validation'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Credential Validation (Failure)'
      {
         Name      = 'Credential Validation'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      # 17.2 Account Management      
      # 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Application Group Management (Success)'
      {
         Name      = 'Application Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Application Group Management (Failure)'
      {
         Name      = 'Application Group Management'    
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      # 17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Computer Account Management (Failure)' 
      {
         Name      = 'Computer Account Management'
         Ensure    = 'Present'
         AuditFlag = 'Failure'      
      }

      AuditPolicySubcategory 'Audit Computer Account Management (Success)' {
         Name      = 'Computer Account Management'
         Ensure    = 'Present'   
         AuditFlag = 'Success'      
      }

      # 17.2.3 (L1) Ensure 'Audit Distribution Group Management' is set to 'Success and Failure' (DC only)
      AuditPolicySubcategory 'Audit Distribution Group Management (Failure)' {
      Name      = 'Distribution Group Management'
      Ensure    = 'Present'
      AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit Distribution Group Management (Success)' {
      Name      = 'Distribution Group Management'
      Ensure    = 'Present'
      AuditFlag = 'Success'
      }

      # 17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit User Account Management (Failure)' {
         Name      = 'User Account Management'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit User Account Management (Success)' {
         Name      = 'User Account Management'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      # 17.3 Detailed Tracking
      # 17.3.2 (L1) Ensure 'Audit Process Creation' is set to 'Success'
      AuditPolicySubcategory 'Audit Process Creation (Success)' {
         Name      = 'Process Creation'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Process Creation (Failure)' {
         Name      = 'Process Creation'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
      }

      # 17.5 Logon/Logoff
      # 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'
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
          
      # 17.5.3 (L1) Ensure 'Audit Logoff' is set to 'Success'
      AuditPolicySubcategory 'Audit Logoff (Success)' {
         Name      = 'Logoff'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Logoff (Failure)' {
         Name      = 'Logoff'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
      }
      
      # 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Logon (Success)' {
         Name      = 'Logon'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Logon (Failure)' {
         Name      = 'Logon'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }
      
      # 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
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
      
      # 17.5.6 (L1) Ensure 'Audit Special Logon' is set to 'Success'
      AuditPolicySubcategory 'Audit Special Logon (Success)' {
         Name      = 'Special Logon'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Special Logon (Failure)' {
         Name      = 'Special Logon'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
      }
      
      # 17.6 
      # 17.6.1 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
         Name      = 'Other Object Access Events'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
         Name      = 'Other Object Access Events'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }
      
      # 17.6.1 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Removable Storage (Success)' {
         Name      = 'Removable Storage'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
         Name      = 'Removable Storage'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }
      
      # 17.7 Policy Change
      # 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Policy Change (Success)' {
         Name      = 'Audit Policy Change'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Policy Change (Failure)' {
         Name      = 'Audit Policy Change'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }
      
      # 17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to 'Success'
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
      
      # 17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to 'Success'
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
      
      # 17.8 Privilege Use
      # 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
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
      
      # 17.9 System
      # 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
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
      
      # 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Other System Events (Failure)' {
         Name      = 'Other System Events'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit Other System Events (Success)' {
         Name      = 'Other System Events'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }
      
      # 17.9.3 (L1) Ensure 'Audit Security State Change' is set to 'Success'
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
      
      # 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Security System Extension (Failure)' {
         Name      = 'Security System Extension'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit Security System Extension (Success)' {
         Name      = 'Security System Extension'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }
      
      # 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit System Integrity (Failure)' {
         Name      = 'System Integrity'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit System Integrity (Success)' {
         Name      = 'System Integrity'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }
      
      # 18. ADMINISTRATIVE TEMPLATES (COMPUTER)

      # 18.1 Control Panel - Personalization 
      # 18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
      Registry 'NoLockScreenCamera' {
         Ensure      = 'Present'
         Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
         ValueName   = 'NoLockScreenCamera' 
         ValueType   = 'DWord' 
         ValueData   = '1' 
      }

      #  18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
      Registry 'NoLockScreenSlideshow' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
         ValueName    = 'NoLockScreenSlideshow'
         ValueType    = 'DWord'
         ValueData    = '1'
      }

      # 18.4 Network
      # 18.4.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
      Registry 'NC_AllowNetBridge_NLA' {
         Ensure    = 'Present'
         Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
         ValueName = 'NC_AllowNetBridge_NLA'
         ValueType = 'DWord'
         ValueData = '0'
      }

      # 18.4.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
      Registry 'fMinimizeConnections' {
         Ensure    = 'Present'
         Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
         ValueName = 'fMinimizeConnections'
         ValueType = 'DWord'
         ValueData = '1'
      }

      # 18.8 System
      # 18.8.3 Audit Process Creation
      # 18.8.3.1 (L1) Ensure 'Include command line in process creation events' is set to 'Disabled'
      Registry 'ProcessCreationIncludeCmdLine_Enabled' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
         ValueName  = 'ProcessCreationIncludeCmdLine_Enabled'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

      # 18.8.14 Early Launch Antimalware
      #  18.8.14.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
      Registry 'DriverLoadPolicy' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
         ValueName  = 'DriverLoadPolicy'
         ValueType  = 'DWord'
         ValueData  = '3'
      }

      #  18.8.22.1.1 (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
      Registry 'DisableWebPnPDownload' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
         ValueName  = 'DisableWebPnPDownload'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

      # 18.8.31 Remote Assistance
      #  18.8.31.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
      Registry 'fAllowUnsolicited' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'fAllowUnsolicited'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

      #  18.8.31.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
      Registry 'fAllowToGetHelp' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'fAllowToGetHelp'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

      #  18.8.32.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
      Registry 'EnableAuthEpResolution' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Rpc'
         ValueName  = 'EnableAuthEpResolution'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      # 18.9 Windows Components

      # 18.9.6 App runtime
      # 18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
      Registry 'MSAOptional' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
         ValueName  = 'MSAOptional'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      # 18.9.8 AutoPlay Policies   
      # 18.9.8.1 (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
      Registry 'NoAutoplayfornonVolume' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
         ValueName  = 'NoAutoplayfornonVolume'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      #  18.9.8.2 (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
      Registry 'NoAutorun' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         ValueName  = 'NoAutorun'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      #  18.9.8.3 (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
      Registry 'NoDriveTypeAutoRun' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         ValueName  = 'NoDriveTypeAutoRun'
         ValueType  = 'DWord'
         ValueData  = '255'
      }
      

      # 18.9.15 Credential User Interface    
      # 18.9.15.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'
      Registry 'DisablePasswordReveal' {
         Ensure      = 'Present'
         Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
         ValueName   = 'DisablePasswordReveal'
         ValueType   = 'DWord'
         ValueData   = '1'
      }

      # 18.9.15.2 (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
      Registry 'EnumerateAdministrators' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
         ValueName  = 'EnumerateAdministrators'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

      # 18.9.26 Event Log Service
      # 18.9.26.1.1 (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
      Registry 'RetentionApplicationLog' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
         ValueName  = 'Retention'
         ValueType  = 'String'
         ValueData  = '0'
      }

      # 18.9.26.1.2 (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
      Registry 'MaxSizeApplicationLog' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
         ValueName  = 'MaxSize'
         ValueType  = 'DWord'
         ValueData  = '32768'
      }

      # 18.9.26.2.1 (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
      Registry 'RetentionSecurityLog' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
         ValueName  = 'Retention'
         ValueType  = 'String'
         ValueData  = '0'
      }

      # 18.9.26.2.2 (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
      Registry 'MaxSizeSecurityLog' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
         ValueName  = 'MaxSize'
         ValueType  = 'DWord'
         ValueData  = '196608'
      }

      # 18.9.26.3.1 (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
      Registry 'RetentionSetupLog' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
         ValueName  = 'Retention'
         ValueType  = 'String'
         ValueData  = '0'
      }

      # 18.9.26.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
      Registry 'MaxSizeSetupLog' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
         ValueName  = 'MaxSize'
         ValueType  = 'DWord'
         ValueData  = '32768'
      }

      # 18.9.26.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
      Registry 'RetentionSystemLog' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
         ValueName  = 'Retention'
         ValueType  = 'String'
         ValueData  = '0'
      }

      # 18.9.26.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
      Registry 'MaxSizeSystemLog' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
         ValueName  = 'MaxSize'
         ValueType  = 'DWord'
         ValueData  = '32768'
      }
      
      # 18.9.30 File Explorer (formerly Windows Explorer)
      # 18.9.30.2 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
      Registry 'NoDataExecutionPrevention' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
         ValueName  = 'NoDataExecutionPrevention'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

      # 18.9.30.3 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
      Registry 'NoHeapTerminationOnCorruption' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
         ValueName  = 'NoHeapTerminationOnCorruption'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

      # 18.9.52.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
      Registry 'DisablePasswordSaving' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'DisablePasswordSaving'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      # 18.9.52.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'
      Registry 'fPromptForPassword' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'fPromptForPassword'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      # 18.9.52.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled'
      Registry 'fEncryptRPCTraffic' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'fEncryptRPCTraffic'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      # 18.9.52.3.9.3 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
      Registry 'MinEncryptionLevel' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'MinEncryptionLevel'
         ValueType  = 'DWord'
         ValueData  = '3'
      }

      # 18.9.52.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
      Registry 'DeleteTempDirsOnExit' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'DeleteTempDirsOnExit'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      # 18.9.52.3.11.1 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'
      Registry 'PerSessionTempDir' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'PerSessionTempDir'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      #  18.9.53.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
      Registry 'DisableEnclosureDownload' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InternetExplorer\Feeds'
         ValueName  = 'DisableEnclosureDownload'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      #  18.9.54.4 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
      Registry 'AllowIndexingEncryptedStoresOrItems' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsSearch'
         ValueName  = 'AllowIndexingEncryptedStoresOrItems'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

      # 18.9.30.2 (L1) Ensure 'Configure Windows SmartScreen' is set to 'Enabled' 
      Registry 'EnableSmartScreen' {
         Ensure    = 'Present'
         Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
         ValueName = 'EnableSmartScreen'
         ValueType = 'DWord'
         ValueData = '1'
      }  

      # 18.9.74.1 (L1) Ensure 'Allow user control over installs' is set to 'Disabled'
      Registry 'EnableUserControl' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
         ValueName  = 'EnableUserControl'
         ValueType  = 'DWord'
         ValueData  = '0'
      }
      
      # 18.9.75.1 (L1) Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
      Registry 'DisableAutomaticRestartSignOn' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
         ValueName  = 'DisableAutomaticRestartSignOn'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

      # 18.9.97.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'
      Registry 'AllowDigest' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
         ValueName  = 'AllowDigest'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

      # 18.9.86.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled' 
      Registry 'AllowBasic1' {
         Ensure    = 'Present'
         Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
         ValueName = 'AllowBasic'
         ValueType = 'DWord'
         ValueData = '0'
      }

      # 18.9.86.2.3 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
      Registry 'AllowUnencryptedTraffic1' {
         Ensure    = 'Present'
         Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
         ValueName = 'AllowUnencryptedTraffic'
         ValueType = 'DWord'
         ValueData = '0'
      }

      # 18.9.86.2.4 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
      Registry 'DisableRunAs' {
         Ensure    = 'Present'
         Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
         ValueName = 'DisableRunAs'
         ValueType = 'DWord'
         ValueData = '1'
      }

      # 18.9.74.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled' 
      Registry 'AlwaysInstallElevated' {
         Ensure    = 'Present'
         Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer'
         ValueName = 'AlwaysInstallElevated'
         ValueType = 'DWord'
         ValueData = '0'
      }
   }
}

CIS_Benchmark_WindowsServer2016_v1_0_0