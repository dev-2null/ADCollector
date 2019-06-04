# ADCollector
ADCollector is a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors. The aim of developing this tool is to help me learn more about the Active Directory security.


It currently uses S.DS namespace to retrieve information from the domain controller(LDAP server). 

* This tool is still under construction.


## Current progress
Learning S.DS.P namespace and reading [Sharphound](https://github.com/BloodHoundAD/SharpHound)



## Todo
* [x] Current Domain/Forest 
* [x] Domains in current Forest
* [x] DCs in current domain.  #dc.Roles ?
* [x] Trusts between domains/forests
* [x] Confidential attributes?
* [x] MSSQL SPN scan
* [ ] SMB version, SMB signing
* [ ] LDAP version
* [ ] Sensitive Info in description field
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
* [ ] DCSync accounts?
* [ ] Shares
* [ ] Users/Computers
* [ ] ...

