# ADCollector
ADCollector is a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors. The aim of developing this tool is to help me learn more about Active Directory security in a different perspective. I just started learning .NET with C#, the code could be really **terrible**~


It currently uses S.DS namespace to retrieve domain/forest information from the domain controller(LDAP server). It also uses S.DS.P namespace for LDAP searching.

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

## Usage
```bat
C:\ADCollector>ADCollector.exe  -h

ADCollector v1.1.3
Usage: ADCollector.exe <options>

    -d , --Domain (Default: current domain)
           Enumerate the specified domain

    -s , --Ldaps (Default: use LDAP)
           Use LDAP over SSL/TLS
```


## Version
##### v 1.1.0:
    1. It now uses S.DS.P namespace to perform search operations, making searches faster and easier to implement. (It also supports paged search. )
    2. It now supports searching in other domains. (command line parser is not implemented yet).
    3. The code logic is reconstructed, less code, more understandable and cohesive.
##### v 1.1.1:
    1. Separated into three classes.
    2. Dispose ldap connection properly.
    3. Enumerations: AdminSDHolder, Domain attributes(MAQ, minPwdLengthm maxPwdAge, lockOutThreshold, GP linked to the domain object), accounts don't need pre-authentication.
    4. LDAP basic info (supportedLDAPVersion, supportedSASLMechanisms, domain/forest/DC Functionality)
    5. SPN scanning (SPNs for MSSQL,Exchange,RDP and PS Remoting)
    6. Constrained Delegation enumerations (S4U2Self, S4U2Proxy as well as Resources-based constrained delegation)
    7. RODC (group that administers the RODC)
##### v 1.1.3:
    1. Fixed SPN scanning result, privilege accounts group membership
    2. Password does not expire accounts
    3. User accounts with SPN set
    4. DC info
    5. Kerberos Policy


## Project
For more information (current progress/Todo list/etc) about this tool, you can visit my [project page](https://github.com/dev-2null/ADCollector/projects/1)


