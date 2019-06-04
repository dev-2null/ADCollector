# ADCollector
ADCollector is a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors. The aim of developing this tool is to help me learn more about Active Directory security in a different perspective. I just started learning .NET with C#, the code could be really **terrible**~


It currently uses S.DS namespace to retrieve information from the domain controller(LDAP server). 

_**This tool is still under construction.**_


## Current progress
- Learning S.DS.P namespace
- Reading [Sharphound](https://github.com/BloodHoundAD/SharpHound)
- Reading [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)

## Done
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

## Todo
* [ ] SMB version, SMB signing
* [ ] LDAP version
* [ ] GCs in current forest
* [ ] DAs EAs (group membership if(isgroup){get member})/ AdminSDHolder / Service Accounts? [password never expires]
* [x] Unconstrained Delegations
* [ ] Constrained Delegations
* [ ] Resources-based Constrained Delegation
* [ ] ASREQROAST
* [ ] GPP
* [ ] GPO (Get-NetGPO)
* [ ] Password policies
* [ ] Accounts with Group Policies edit rights
* [ ] Domain Policies (Kerberos policy, system access, registry values)
* [ ] MachineQuota
* [ ] DCSync accounts ?
* [ ] Shares
* [ ] Users/Computers properties 
    - pwdlastset
    - badpwdcount
    - logoncount
    - description. \*pass\*
    - ...
* [ ] ...

## Doubts
* Sharphound2/Utils.cs#L893 

```C#
var connection = new LdapConnection(new LdapDirectoryIdentifier(domainController, 3268));
```
[LdapDirectoryIdentifier can be useful to establish a connection over UDP or separate the identifying info about a connection from the creation of the LdapConnection object]
Why not just:
```C#
new LdapConnection(domainController)
```

* Limits the number of attributes returned (Differences)
* 
```C#
SearchRequest searchReq = new SearchRequest(Dn, searchQuery, searchScope, attributReturned);
```

```C#
search.PropertiesToLoad.Add()
```