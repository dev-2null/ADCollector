using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    public class BuildSearchString
    {
        public List<Object[]> LDAPSearchStringObjectList { get; set; } = new List<object[]>();
        public List<SearchString> LDAPSearchStringList { get; set; } = new List<SearchString>();
        public List<Object[]> SMBSearchStringObjectList { get; set; } = new List<Object[]>();
        public List<SearchString> SMBSearchStringList { get; set; } = new List<SearchString>();
        public List<SearchString> DictionaryListSearchStringList { get; set; } = new List<SearchString>();
        public List<SearchString> NestedGMSearchStringList { get; set; } = new List<SearchString>();
        public List<SearchString> AppliedGPOSearchStringList { get; set; } = new List<SearchString>();


        LDAPInfo ldapInfo { get; set; }

        public BuildSearchString()
        {
            ldapInfo = Searcher.LdapInfo;
            CreateLDAPSearchString();
            CreateSMBSearchString();
        }

        public List<SearchString> GetLDAPSearchString()
        {
            foreach (var searchArray in LDAPSearchStringObjectList)
            {
                LDAPSearchStringList.Add(new LDAPSearchString
                {
                    Title = (string)searchArray[0],
                    DN = (string)searchArray[1],
                    Filter = (string)searchArray[2],
                    ReturnAttributes = (string[])searchArray[3],
                    Scope = (SearchScope)(searchArray.Length > 4 ? searchArray[4] : SearchScope.Subtree),
                    UseGlobalCatalog = (bool)(searchArray.Length > 5? searchArray[5] : false)
                });;
            }
            return LDAPSearchStringList;
        }

        public List<SearchString> GetSMBSearchString()
        {
            foreach(var searchArray in SMBSearchStringObjectList)
            {
                SMBSearchStringList.Add(new SMBSearchString
                {
                    Title = (string)searchArray[0],
                    FilePathList = (List<string>)searchArray[1],
                    FileAttributes = (List<string>)searchArray[2]
                });
            }

            return SMBSearchStringList;
        }

        public List<SearchString> GetNestedGMSearchString(List<string> sAMAccountNameList)
        {
            foreach(string sAMAccountName in sAMAccountNameList)
            {
                NestedGMSearchStringList.Add(
                new NestedGMSearchString { Title = $"Nested Group Membership for {sAMAccountName}", SAMAccountName = sAMAccountName }
                );
            }
            return NestedGMSearchStringList;
        }


        public List<SearchString> GetAppliedGPOSearchString(List<string> sAMAccountNameList)
        {
            foreach (string sAMAccountName in sAMAccountNameList)
            {
                AppliedGPOSearchStringList.Add(
                new AppliedGPOSearchString { Title = $"Effective GPOs Applied on {sAMAccountName}", SAMAccountName = sAMAccountName }
                );
            }
            return AppliedGPOSearchStringList;
        }



        public void CreateLDAPSearchString()
        {
            string targetDN = ldapInfo.TargetSearchBase;
            string RootDN = ldapInfo.RootDN;
            string SchemaDN = ldapInfo.SchemaDN;

            //Domain Attributes
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Domain Attributes", RootDN, @"(name=*)", new string[] {  "maxPwdAge","LockoutDuration", "whenCreated","whenChanged","ObjectSID", "ms-DS-MachineAccountQuota", "MinPwdLength","MinPwdLength","MaxPwdAge","LockoutThreshold","LockoutDuration",},SearchScope.Base
            });


            //TDO
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Trusted Domain Objects in the Current Domain", "CN=System,"+RootDN, @"(objectCategory=TrustedDomain)", new string[] { "cn", "securityidentifier" }
            });


            //Domain Controllers
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Domain Controllers", targetDN, @"(primaryGroupID=516)", new string[] {  "cn", "samaccountname", "dNSHostName", "logonCount", "operatingsystem", "operatingsystemversion", "whenCreated", "whenChanged", "managedBy", "dnsRecord" }
            });


            //Read Only Domain Controllers
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Read-Only Domain Controllers", targetDN, @"(primaryGroupID=521)", new string[] {  "cn", "samaccountname", "dNSHostName", "logonCount", "operatingsystem", "operatingsystemversion", "whenCreated", "whenChanged", "managedBy", "dnsRecord" }
            });



            //Unconstrainde Delegation
            //TRUSTED_FOR_DELEGATION
            //By default, DCs are configured to allow Kerberos Unconstrained Delegation.
            //So excluding DCs here
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Unconstrained Delegation Accounts", targetDN, @"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))", new string[] { "servicePrincipalName", "sAMAccountName" }
            });



            //Constrainde Delegation
            //TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
            //By default, RODCs are configured to allow Kerberos Constrained Delegation with Protocol Transition.
            //So excluding RODCs here
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Constrained Delegation [with S4U2Self enabled] Accounts (Any Authentication Protocol)", targetDN, @"(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(!primaryGroupID=521))", new string[] { "servicePrincipalName", "sAMAccountName" }
            });



            ////Constrainde Delegation with Services
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Constrained Delegation Accounts with associated services", targetDN, @"(msDS-AllowedToDelegateTo=*)", new string[] { "msDS-AllowedToDelegateTo", "servicePrincipalName", "sAMAccountName" }
            });


            //Resources-based Constrained Delegation
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Resources-based Constrained Delegation Accounts", targetDN, @"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", new string[] { "msDS-AllowedToActOnBehalfOfOtherIdentity", "servicePrincipalName", "sAMAccountName" }
            });



            //Privileged Accounts
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Privileged Accounts", targetDN, "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=CN=Administrators,CN=Builtin," + RootDN + "))", new string[] { "MemberOf", "sAMAccountName" }
            });



            //Sensitive & Not Delegated
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Sensitive & Not Delegated Accounts", targetDN, @"(userAccountControl:1.2.840.113556.1.4.803:=1048576)", new string[] { "servicePrincipalName", "sAMAccountName" }
            });



            //Protected Users     
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Protected Users", ("CN=Protected Users,CN=Users,"+RootDN),  @"(name=*)", new string[] { "member" }, SearchScope.Base
            });



            //AdminSDHolder
            LDAPSearchStringObjectList.Add(new object[]
            {
                "AdminSDHolder Protected Accounts", targetDN,  @"(&(adminCount=1)(objectCategory=person))", new string[] { "servicePrincipalName", "sAMAccountName" }
            });



            //Password Does Not Expire
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Password Does Not Expire Accounts", targetDN, @"(userAccountControl:1.2.840.113556.1.4.803:=65536)", new string[] { "servicePrincipalName", "sAMAccountName" }
            });



            //User Accounts With SPN
            LDAPSearchStringObjectList.Add(new object[]
            {
                "User Accounts With SPN Set", targetDN, @"(&(sAMAccountType=805306368)(servicePrincipalName=*))", new string[] { "servicePrincipalName", "sAMAccountName" }
            });



            //Accounts With No Password
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Accounts With No Password", targetDN, @"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))", new string[] { "servicePrincipalName", "sAMAccountName" }
            });



            //DontRequirePreauth
            LDAPSearchStringObjectList.Add(new object[]
            {
                "DontRequirePreauth Accounts", targetDN, @"(userAccountControl:1.2.840.113556.1.4.803:=4194304)", new string[] { "servicePrincipalName", "sAMAccountName" }
            });



            //Interesting Description
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Interesting Descriptions (default: pass) on User Objects", targetDN, @"(&(sAMAccountType=805306368)(description=*pass*))", new string[] { "description", "servicePrincipalName", "sAMAccountName" }
            });



            //Confidential Attributes
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Confidential Attributes", SchemaDN, @"(searchFlags:1.2.840.113556.1.4.803:=128)", new string[] { "" }
            });



            //Accounts Allow Reversible Password Encryption
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Accounts Allow Reversible Password Encryption", targetDN, @"(UserAccountControl:1.2.840.113556.1.4.803:=128)", new string[] { "sAMAccountName" }
            });



            //Machine Owners
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Machine Owners", targetDN, @"(ms-ds-CreatorSID=*)", new string[] { "ms-ds-CreatorSID", "sAMAccountName" }
            });


            //LAPS Password
            LDAPSearchStringObjectList.Add(new object[]
            {
                "LAPS Password", targetDN, @"(ms-Mcs-AdmPwd=*)", new string[] { "sAMAccountName", "ms-Mcs-AdmPwd" }
            });


            //UserPassword
            LDAPSearchStringObjectList.Add(new object[]
            {
                "User Passwords", targetDN, @"(|(userPassword=*)(UnixUserPassword=*)(unicodePwd=*)(msSFU30Password=*)(os400-password=*))", 
                new string[] { "sAMAccountName", "userPassword", "UnixUserPassword", "unicodePwd", "msSFU30Password", "os400-password" }
            });


            //SPN: EXCHANGE
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Accounts with Exchange Service SPNs", targetDN, @"(servicePrincipalName=exchange*)", new string[] { "servicePrincipalName", "sAMAccountName" }
            });


            //SPN: HTTP
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Accounts with HTTP Service SPNs", targetDN, @"(servicePrincipalName=http*)", new string[] { "servicePrincipalName", "sAMAccountName" }
            });


            //SPN: MSSQL
            LDAPSearchStringObjectList.Add(new object[]
            {
                "Accounts with MSSQL Service SPNs", targetDN, @"(servicePrincipalName=mssql*)", new string[] { "servicePrincipalName", "sAMAccountName" }
            });
        }



        public void CreateSMBSearchString()
        {
            SMBSearchStringObjectList.Add(new object[]
            {
                "Kerberos Policy & System Access",
                new List<string> {@"\\" + ldapInfo.DomainController + @"\SYSVOL\" + ldapInfo.DomainName + @"\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" },
                new List<string>{ "System Access", "Kerberos Policy" }
            });

            //SMBSearchStringObjectList.Add(new object[]
            //{
            //    "Privilege Rights",
            //    new List<string> {@"\\" + ldapInfo.DomainController + @"\SYSVOL\" + ldapInfo.DomainName + @"\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" },
            //    new List<string>{ "Privilege Rights" }
            //});

            List<string> gpoPathList = GPO.GroupPolicies.Keys.Select(
                k => $"\\\\{ldapInfo.DomainController}\\SYSVOL\\{ldapInfo.DomainName}\\Policies\\{k}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
                ).ToList();


            SMBSearchStringObjectList.Add(new object[]
            {
                "Privilege Rights",
                gpoPathList,
                new List<string>{ "Privilege Rights" }
            });


            SMBSearchStringObjectList.Add(new object[]
            {
                "Restricted Group",
                gpoPathList,
                new List<string>{ "Group Membership" }
            });

            
        }
    }
}
