# ADCollector
ADCollector is a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors. It will give you a basic understanding of the configuration/deployment of the environment as a starting point. 

#### Notes: 
ADCollector is not an alternative to the powerful PowerView, it just automates enumeration to quickly identify juicy information without thinking too much at the early Recon stage. Functions implemented in ADCollector are ideal for enumeration in a large Enterprise environment with lots of users/computers, without generating lots of traffic and taking a large amount of time. It only focuses on extracting useful attributes/properties/ACLs from the most valuable targets instead of enumerating all available attributes from all the user/computer objects in the domain. You will definitely need PowerView to do more detailed enumeration later.

The aim of developing this tool is to help me learn more about Active Directory security in a different perspective as well as to figure out what's behind the scenes of those PowerView functions. I just started learning .NET with C#, the code could be really **terrible**~


It uses S.DS namespace to retrieve domain/forest information from the domain controller(LDAP server). It also utilizes S.DS.P namespace for LDAP searching.

_**This tool is still under construction. Features will be implemented can be seen from my [project page](https://github.com/dev-2null/ADCollector/projects/1)**_


## Enumeration
* Current Domain/Forest information
* Domains in the current forest (with domain SIDs)
* Domain Controllers in the current domain \[GC/RODC] (with ~~IP,OS Site and ~~Roles)
* Domain/Forest trusts as well as trusted domain objects[SID filtering status]
* Privileged users (currently in DA and EA group)
* Unconstrained delegation accounts (Excluding DCs)
* Constrained Delegation (S4U2Self, S4U2Proxy, Resources-based constrained delegation)
* MSSQL/Exchange/RDP/PS Remoting SPN accounts
* User accounts with SPN set & password does not expire account
* Confidential attributes ()
* ASREQROAST (DontRequirePreAuth accounts)
* AdminSDHolder protected accounts
* Domain attributes (MAQ, minPwdLength, maxPwdAge lockoutThreshold, gpLink[group policies that linked to the current domain object])
* LDAP basic info(supportedLDAPVersion, supportedSASLMechanisms, domain/forest/DC Functionality)
* Kerberos Policy
* Interesting ACLs on the domain object, resolving GUIDs (User defined object in the future)
* Unusual DCSync Accounts
* Interesting ACLs on GPOs
* Interesting descriptions on user objects
* Sensitive & Not delegate account
* Group Policy Preference cpassword in SYSVOL/Cache
* Effective GPOs on the current user/computer
* Restricted groups

## Usage
```bat
C:\Users> ADCollector.exe  -h

      _    ____   ____      _ _             _
     / \  |  _ \ / ___|___ | | | ___  ___ _| |_ ___  _ __
    / _ \ | | | | |   / _ \| | |/ _ \/ __|_  __/ _ \| '__|
   / ___ \| |_| | |__| (_) | | |  __/ (__  | || (_) | |
  /_/   \_\____/ \____\___/|_|_|\___|\___| |__/\___/|_|

  v1.1.4  by dev2null

Usage: ADCollector.exe -h
    
    --Domain (Default: current domain)
            Enumerate the specified domain

    --Ldaps (Default: LDAP)
            Use LDAP over SSL/TLS

    --Spns (Default: no SPN scanning)
            Enumerate SPNs

    --Term (Default: 'pass')
            Term to search in user description field

    --Acls (Default: 'Domain object')
            Interesting ACLs on an object

Example: .\ADCollector.exe --SPNs --Term key --ACLs 'CN=Domain Admins,CN=Users,DC=lab,DC=local'
```


## Changelog
##### v 1.1.1:
    1. It now uses S.DS.P namespace to perform search operations, making searches faster and easier to implement. (It also supports paged search. )
    2. It now supports searching in other domains. (command line parser is not implemented yet).
    3. The code logic is reconstructed, less code, more understandable and cohesive.
##### v 1.1.2:
    1. Separated into three classes.
    2. Dispose ldap connection properly.
    3. Enumerations: AdminSDHolder, Domain attributes(MAQ, minPwdLengthm maxPwdAge, lockOutThreshold, GP linked to the domain object), accounts don't need pre-authentication.
    4. LDAP basic info (supportedLDAPVersion, supportedSASLMechanisms, domain/forest/DC Functionality)
    5. SPN scanning (SPNs for MSSQL,Exchange,RDP and PS Remoting)
    6. Constrained Delegation enumerations (S4U2Self, S4U2Proxy as well as Resources-based constrained delegation)
    7. RODC (group that administers the RODC)
##### v 1.1.3:
    1. Fixed SPN scanning result, privilege accounts group membership
    2. Password does not expire accounts; User accounts with SPN set; 
    3. Kerberos Policy
    4. Interesting ACLs enumeration for the domain object, resolving GUIDs
    5. DC info is back
##### v 1.1.4:
    1. Some bugs are killed and some details are improved
    2. SPN scanning is now optional
    3. GPP cpassword in SYSVOL/Cache
    4. Interesting ACLs on GPOs; Interesting descriptions on user objects;
    5. Unusual DCSync accounts; Sensitive & not delegate accounts
    6. Effective GPOs on user/computer
    7. Restricted groups

## Project
For more information (current progress/Todo list/etc) about this tool, you can visit my [project page](https://github.com/dev-2null/ADCollector/projects/1)


