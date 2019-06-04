# ADCollector
ADCollector is a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors. The aim of developing this tool is to help me learn more about Active Directory security in a different perspective. I just started learning .NET with C#, the code could be really **terrible**~


It currently uses S.DS namespace to retrieve information from the domain controller(LDAP server). 

_**This tool is still under construction.**_


## Features
* Current Domain/Forest information
* Domains in the current forest (with domain SIDs)
* Domain Controllers in the current domain \[GC/RODC] (with IP,OS Site and Roles)
* Domain trusts [SID filtering status]
* Forest trusts [SID filtering status]
* Privileged users (in DA and EA group)
* Unconstrained delegation accounts (Excluding DCs)
* MSSQL SPN accounts
* GPOs (... under construction)
* Confidential attributes ()

## Info
For more information (current progress/Todo list/etc) about this tool, you can visit my project page: 
**https://github.com/users/dev-2null/projects/1**
