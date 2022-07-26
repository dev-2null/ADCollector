# ADCollector
ADCollector is a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors. It will give you a basic understanding of the configuration/deployment of the environment as a starting point. 

#### Notes: 
ADCollector is not an alternative to the powerful PowerView, it just automates enumeration to quickly identify juicy information without thinking too much at the early Recon stage. Functions implemented in ADCollector are ideal for enumeration in a large Enterprise environment with lots of users/computers, without generating lots of traffic and taking a large amount of time. It only focuses on extracting useful attributes/properties/ACLs from the most valuable targets instead of enumerating all available attributes from all the user/computer objects in the domain. ~~You will definitely need PowerView to do more detailed enumeration later.~~ You can use ADSI instead of PowerView to enumerate the domain as long as you know what you want to enumerate, see <https://dev-2null.github.io/Easy-Domain-Enumeration-with-ADSI/>.

The aim of developing this tool is to help me learn more about Active Directory security in a different perspective as well as to figure out what's behind the scenes of those PowerView functions. 


It uses S.DS namespace to retrieve domain/forest information from the domain controller(LDAP server). It also utilizes S.DS.P namespace for LDAP searching.

_**This tool is still under construction. Features will be implemented can be seen from my [project page](https://github.com/dev-2null/ADCollector/projects/1)**_

Make sure you have access to the SYSVOL if you run it from a non domain joined host. You may need to run the following command if harden UNC policy is applied:

```batch
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths /v "\\*\SYSVOL" /d "RequireMutualAuthentication=0" /t REG_SZ
```

## Enumeration
* Current Domain/Forest information
* Domains in the current forest (with domain SIDs)
* Domain Controllers in the current domain \[GC/RODC]
* Domain/Forest trusts as well as trusted domain objects[SID filtering status]
* Privileged users (currently in DA and EA group)
* Unconstrained delegation accounts (Excluding DCs)
* Constrained Delegation (S4U2Self, S4U2Proxy)
* Resources-based constrained delegation
* MSSQL/Exchange(/RDP/PS) Remoting SPN accounts
* User accounts with SPN set & password does not expire account
* Protected Users
* Confidential attributes
* ASREQROAST (DontRequirePreAuth accounts)
* AdminSDHolder protected accounts
* Domain attributes (MAQ, minPwdLength, maxPwdAge lockoutThreshold, gpLink[group policies that linked to the current domain object])
* LDAP basic info(supportedLDAPVersion, supportedSASLMechanisms, domain/forest/DC Functionality)
* Kerberos Policy
* Interesting ACLs on the domain object, resolving GUIDs (User defined object in the future)
* Interesting ACLs on GPOs
* Interesting descriptions on user objects
* Sensitive & Not delegate account
* Group Policy Preference cpassword in SYSVOL
* Effective GPOs on the current user/computer
* Nested Group Membership
* Restricted Group
* LAPS Password View Access
* ADCS Configurations
* Certificate Templates
* Machine Owner
* ACL Scan
* Privileges Rights defined in Group Policies
* User Credentials stored in LDAP


## Usage
```
PS C:\> .\ADCollector.exe --help

      _    ____   ____      _ _             _
     / \  |  _ \ / ___|___ | | | ___  ___ _| |_ ___  _ __
    / _ \ | | | | |   / _ \| | |/ _ \/ __|_  __/ _ \| '__|
   / ___ \| |_| | |__| (_) | | |  __/ (__  | || (_) | |
  /_/   \_\____/ \____\___/|_|_|\___|\___| |__/\___/|_|

  v3.0.1  by dev2null


  --Domain            Domain to enumerate
  --LDAPS             (Default: false) LDAP over SSL/TLS
  --DisableSigning    (Default: false) Disable Kerberos Encryption (with -LDAPS flag)
  --UserName          Alternative UserName
  --Password          Alternative Credential
  --DC                Alternative Domain Controller (Hostname/IP) to connect to
  --OU                Perform the Search under a specific Organizational Unit
  --LDAPONLY          Only Enumearte Objects in LDAP
  --ACLScan           Perform ACL scan for an Identity
  --ADCS              (Default: false) Only Perform AD Certificate Service Check
  --TEMPLATES         (Default: false) Only Enumerate All Certificate Templates with their DACL
  --SCHEMA            (Default: false) Count Schema Attributes in the default naming context
  --ADIDNS            (Default: false) Only Collect ADIDNS Records
  --NGAGP             Only enumerate Nested Group Membership and Applied Group Policies on the target object
  --DACL              Enumerate DACL on the target object (with DistinguishedName)
  --SessionEnum       (Default: false) Enumerate session information on the target host
  --UserEnum          (Default: false) Enumerate user information on the target host
  --LocalGMEnum       (Default: false) Enumerate local group members on the target host
  --Host              (Default: Localhost) Hostname for Session/User/Groupmember Enumeration
  --Group             (Default: Administrators) Local Group Name for Local GroupMember Enumeration
  --Debug             (Default: false) Debug Mode
  --help              Display this help screen.

Example: .\ADCollector.exe
         .\ADCollector.exe --LDAPs --DisableSigning
         .\ADCollector.exe --OU IT
         .\ADCollector.exe --OU OU=IT,DC=domain,DC=local
         .\ADCollector.exe --ADCS
         .\ADCollector.exe --TEMPLATES
         .\ADCollector.exe --LDAPOnly
         .\ADCollector.exe --SCHEMA
         .\ADCollector.exe --ADIDNS
         .\ADCollector.exe --NGAGP samaccountname
         .\ADCollector.exe --DACL DC=domain,DC=net
         .\ADCollector.exe --ACLScan user --OU OU=IT,DC=domain,DC=local
         .\ADCollector.exe --SessionEnum --Host targetHost
         .\ADCollector.exe --UserEnum --Host targetHost
         .\ADCollector.exe --LocalGMEnum --Host targetHost --Group 'Remote Desktop Users'
         .\ADCollector.exe --Domain domain.local --Username user --Password pass
         .\ADCollector.exe --Domain domain.local --DC 10.10.10.1

```


## Changelog

##### v 3.0.1:
    1. Added enumeration for certificate templates, schema and user credentials
    2. Added a few flags
##### v 3.0.0:
    1. Code Refactoring & Bug fix
    2. Added privielge rights and object DACL enumeration
    3. Added Debug mode
    4. Merged interactive menu into command line and removed some simple LDAP enum (use ADSI, see [ADSI Enum](https://dev-2null.github.io/Easy-Domain-Enumeration-with-ADSI/))
##### v 2.1.2:
    1. Bug fix with some improvements
    2. New implementation logic for LAPS & Restricted Group enum
    3. Use Task to handle some heavy enumeration functions (much faster for large domain)
    4. Remove GPP cache and DCSync accounts enumeration
##### v 2.1.1:
    1. Search under a specific OU
    2. LAPS detailed view
    3. Machine Owners
    4. Restricted Groups
    5. ADCS Configurations
    6. ACL Scan
    7. Bug Fix: SYSVOL access, Nested Group Membership
    8. Replace external readINF dependency with custom implementation
    9. Protected Users
##### v 2.0.0:
    1. Complete Rewrite (more extensible)
    2. Add Interactive Menu with command line choice
    3. Use direct API call to enumerate Trust relationship
    4. Update Applied GPO Enumeration with Security Filtering and WMI Filtering (WMIFilter needs to be checked manually)
    5. Add LDAP DNS Record Enumeration
    6. RunAs: Run ADCollector under another user context
    7. Flexiable SPN Scan, DNS Records, Nested Group Membership, ACL Enumeration
    8. Add NetSessionEnum, NetLocalGroupGetMembers and NetWkstaUserEnum
##### v 1.1.4:
    1. Some bugs are killed and some details are improved
    2. SPN scanning is now optional
    3. GPP cpassword in SYSVOL/Cache
    4. Interesting ACLs on GPOs; Interesting descriptions on user objects;
    5. Unusual DCSync accounts; Sensitive & not delegate accounts
    6. Effective GPOs on user/computer
    7. Restricted groups
    8. Nested Group Membership
    9. LAPS Password View Access
##### v 1.1.3:
    1. Fixed SPN scanning result, privilege accounts group membership
    2. Password does not expire accounts; User accounts with SPN set; 
    3. Kerberos Policy
    4. Interesting ACLs enumeration for the domain object, resolving GUIDs
    5. DC info is back
##### v 1.1.2:
    1. Separated into three classes.
    2. Dispose ldap connection properly.
    3. Enumerations: AdminSDHolder, Domain attributes(MAQ, minPwdLengthm maxPwdAge, lockOutThreshold, GP linked to the domain object), accounts don't need pre-authentication.
    4. LDAP basic info (supportedLDAPVersion, supportedSASLMechanisms, domain/forest/DC Functionality)
    5. SPN scanning (SPNs for MSSQL,Exchange,RDP and PS Remoting)
    6. Constrained Delegation enumerations (S4U2Self, S4U2Proxy as well as Resources-based constrained delegation)
    7. RODC (group that administers the RODC)
##### v 1.1.1:
    1. It now uses S.DS.P namespace to perform search operations, making searches faster and easier to implement. (It also supports paged search. )
    2. It now supports searching in other domains. (command line parser is not implemented yet).
    3. The code logic is reconstructed, less code, more understandable and cohesive.

## Project
For more information (current progress/Todo list/etc) about this tool, you can visit my [project page](https://github.com/dev-2null/ADCollector/projects/1)

