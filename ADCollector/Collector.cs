using System;
using System.Net;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Collections.Generic;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;
using System.Collections.Concurrent;
using System.Linq;
using System.Diagnostics;
using static ADCollector.Printer;
using static ADCollector.Helper;
using SecurityMasks = System.DirectoryServices.Protocols.SecurityMasks;

namespace ADCollector
{
    public class Collector
    {
        public static Domain domain;
        public static Forest forest;
        public static string rootDn;
        public static string forestDn;
        public static string schemaDn;
        public static string configDn;
        public static string domainName;
        public static string forestName;
        public static string accessDC;
        public static string ouDn;
        public static string identity;
        public static bool useLdaps;
        public static bool disableSigning;
        public static bool aclScan;
        public static bool adcs;
        public static string dc;
        public static int port;
        public static DirectoryEntry rootDSE;
        public static string username;
        private static string _password;
        internal static readonly ConcurrentBag<LdapConnection> _ldapConnections = new ConcurrentBag<LdapConnection>();
        internal static readonly ConcurrentBag<DirectoryEntry> _entryPool = new ConcurrentBag<DirectoryEntry>();




        public Collector(Options options)
        {
            domainName = options.Domain;
            port = options.Ldaps ? 636 : 389;
            username = options.Username;
            _password = options.Password;
            dc = options.DC;
            disableSigning = options.DisableSigning;
            ouDn = options.OU == null ? null : options.OU.ToUpper();
            aclScan = options.ACLScan;
            identity = options.Identity;
            adcs = options.ADCS;

            if (domainName != null && dc == null)
            {
                dc = domainName;
            }
            else if (dc == null)
            {
                dc = Environment.GetEnvironmentVariable("USERDOMAIN");
            }

        }







        public void Connect()
        {
            rootDSE = GetSingleDirectoryEntry("rootDSE");

            //Test Connection
            try
            {
                rootDSE.RefreshCache();
            }
            catch (Exception e)
            {
                PrintYellow("[x] Cannot connect to LDAP://" + dc + ":" + port + "/rootDSE");
                PrintYellow("[x] ERROR: " + e.Message);
                Environment.Exit(1);
            }


            //Domain DN: DC=child,DC=domain,DC=local
            rootDn = rootDSE.Properties["defaultNamingContext"].Value.ToString();

            //Forest DN: DC=domain,DC=local
            forestDn = rootDSE.Properties["rootDomainNamingContext"].Value.ToString();

            //CN=Schema,CN=Configuration,
            schemaDn = rootDSE.Properties["schemaNamingContext"].Value.ToString();

            //CN=Configuration,
            configDn = rootDSE.Properties["configurationNamingContext"].Value.ToString();

            domainName = rootDn.Replace("DC=", "").Replace(",", ".");
            forestName = forestDn.Replace("DC=", "").Replace(",", ".");

            if (ouDn != null) { 
                if (!ouDn.Contains("DC=")) { 
                    var findOU = GetSingleResultEntry(rootDn, ("(&(objectClass=organizationalUnit)(name=" + ouDn + "))"), SearchScope.Subtree, null, false); 
                    if (findOU == null) { PrintYellow("[x] The specified OU does not exist\n"); Environment.Exit(1); }
                    else { ouDn = findOU.DistinguishedName; }
                }
            }
            else { ouDn = rootDn; }
        }









        public void Run()
        {
            if (username != null)
            {
                Utilities.RunAs(domainName, username, _password, () =>
                {
                    Connect();
                    if (aclScan){  var dacl = Utilities.InvokeACLScan(identity); PrintACLs(dacl); }
                    else if (adcs) { var adcs = Utilities.GetADCS(); PrintADCS(adcs); var certTemplateList = Utilities.GetInterestingCertTemplates(adcs); PrintCertTemplates(certTemplateList); }
                    else { RunAllCommands(); }
                });
            }
            else
            {
                Connect();
                if (aclScan) { var dacl = Utilities.InvokeACLScan(identity); PrintACLs(dacl); }
                else if (adcs) { var adcs = Utilities.GetADCS(); PrintADCS(adcs); var certTemplateList = Utilities.GetInterestingCertTemplates(adcs); PrintCertTemplates(certTemplateList); }
                else { RunAllCommands(); }
            }
        }



        public void RunAllCommands()
        {
            //LDAP Basic Info
            PrintBasicInfo();

            //DC
            var dcList = Utilities.GetDC();
            PrintDC(dcList, "Domain Controllers");

            //RODC
            bool getRODC = true;
            var rodcList = Utilities.GetDC(getRODC);
            PrintDC(rodcList, "Read-Only Domain Controllers");


            //Kerberos Policies & System Access
            accessDC = dcList[0].Attributes["dnsHostName"][0].ToString();
            PrintKerberosPolicy();


            var GPOs = Utilities.GetGPO();

            //Domain Attributes
            PrintDomainAttr(rootDn, GPOs);


            //TDO
            PrintTDO(rootDn);

            //Trusts
            PrintTrust(domainName);


            //ADCS*
            var adcs = Utilities.GetADCS();
            PrintADCS(adcs);

            var certTemplateList = Utilities.GetInterestingCertTemplates(adcs);
            PrintCertTemplates(certTemplateList);
 
            //Nested Group Membership
            var userGroupList = Utilities.GetNestedGroupMem(out string uguser, false);
            PrintNestedGroupMem(userGroupList, uguser, null);
            var machineGroupList = Utilities.GetNestedGroupMem(out string mguser, true);
            PrintNestedGroupMem(machineGroupList, mguser, null);


            //EffectiveGPOsOnUser
            string userDn = Utilities.GetDN(false, out string uname, null);
            if (userDn != null)
            {
                var userOUs = Utilities.GetMyOUs(uname, userDn, false);
                var userAppliedGPOs = Utilities.GetAppliedGPOs(userGroupList, userOUs, GPOs);
                PrintAppliedGPOs(userDn, userAppliedGPOs, false);
            }

            //EffectiveGPOsOnComputer
            string computerDn = Utilities.GetDN(true, out string cname, null);
            if (computerDn != null)
            {
                var computerOUs = Utilities.GetMyOUs(cname, computerDn, true);
                var computerAppliedGPOs = Utilities.GetAppliedGPOs(machineGroupList, computerOUs, GPOs);
                PrintAppliedGPOs(computerDn, computerAppliedGPOs, true);
            }
            

            var samAccount = new string[] { "sAMAccountName" };
            //Unconstrainde Delegation
            //TRUSTED_FOR_DELEGATION
            //By default, DCs are configured to allow Kerberos Unconstrained Delegation.
            //So excluding DCs here
            var udDict = Utilities.GetGeneral(ouDn, @"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))", samAccount);
            PrintDirectoryAttrsDict(udDict, "Unconstrained Delegation Accounts");


            //Constrainde Delegation
            //TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
            //By default, RODCs are configured to allow Kerberos Constrained Delegation with Protocol Transition.
            //So excluding RODCs here
            var cdDict = Utilities.GetGeneral(ouDn, @"(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(!primaryGroupID=521))", samAccount);
            PrintDirectoryAttrsDict(cdDict, "Constrained Delegation [with S4U2Self enabled] Accounts (Any Authentication Protocol)");


            ////Constrainde Delegation with Services
            var cdSrvDict = Utilities.GetGeneral(ouDn, @"(msDS-AllowedToDelegateTo=*)", new string[] { "msDS-AllowedToDelegateTo" });
            PrintDirectoryAttrsDict(cdSrvDict, "Constrained Delegation Accounts with associated services");


            //Resources-based Constrained Delegation
            var rbcdSrvDict = Utilities.GetGeneral(ouDn, @"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", new string[] { "msDS-AllowedToActOnBehalfOfOtherIdentity" });
            PrintDirectoryAttrsDict(rbcdSrvDict, "Resources-based Constrained Delegation Accounts");


            //SPN: MSSQL
            var mssqlSpn = Utilities.GetGeneral(ouDn, @"(servicePrincipalName=mssql*)", new string[] { "servicePrincipalName" });
            PrintDirectoryAttrsDict(mssqlSpn, "Accounts with MSSQL Service SPNs");

            //SPN: HTTP
            var httpSpn = Utilities.GetGeneral(ouDn, @"(servicePrincipalName=http*)", new string[] { "servicePrincipalName" });
            PrintDirectoryAttrsDict(httpSpn, "Accounts with HTTP Service SPNs");

            //SPN: EXCHANGE
            var exchangeSpn = Utilities.GetGeneral(ouDn, @"(servicePrincipalName=exchange*)", new string[] { "servicePrincipalName" });
            PrintDirectoryAttrsDict(exchangeSpn, "Accounts with Exchange Service SPNs");


            //Privileged Accounts
            var privAccounts = Utilities.GetGeneral(ouDn, "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=CN=Administrators,CN=Builtin," + rootDn + "))", new string[] { "MemberOf" });
            PrintDirectoryAttrsDict(privAccounts, "Privileged Accounts");


            //Sensitive & Not Delegated
            var sensitiveAccounts = Utilities.GetGeneral(ouDn, @"(userAccountControl:1.2.840.113556.1.4.803:=1048576)", samAccount);
            PrintDirectoryAttrsDict(sensitiveAccounts, "Sensitive & Not Delegated Accounts");


            //Protected Users
            var protectedAccounts = Utilities.GetSingleEntryAttr("CN=Protected Users,CN=Users," + rootDn,  "member");
            PrintSingleEntryAttribute(protectedAccounts, "Protected Users");

            //AdminSDHolder
            var sdholderAccounts = Utilities.GetGeneral(ouDn, @"(&(adminCount=1)(objectCategory=person))", samAccount);
            PrintDirectoryAttrsDict(sdholderAccounts, "AdminSDHolder Protected Accounts");


            //Password Does Not Expire
            var passnotexpireAccounts = Utilities.GetGeneral(ouDn, @"(userAccountControl:1.2.840.113556.1.4.803:=65536)", samAccount);
            PrintDirectoryAttrsDict(passnotexpireAccounts, "Password Does Not Expire Accounts");


            //User Accounts With SPN
            var spnAccounts = Utilities.GetGeneral(ouDn, @"(&(sAMAccountType=805306368)(servicePrincipalName=*))", new string[] { "servicePrincipalName" });
            PrintDirectoryAttrsDict(spnAccounts, "User Accounts With SPN Set");


            //DontRequirePreauth
            var nopreauthAccounts = Utilities.GetGeneral(ouDn, @"(userAccountControl:1.2.840.113556.1.4.803:=4194304)", samAccount);
            PrintDirectoryAttrsDict(nopreauthAccounts, "DontRequirePreauth Accounts");


            //Interesting Description
            string term = "pass";
            var interestingDescrip = Utilities.GetGeneral(ouDn, @"(&(sAMAccountType=805306368)(description=*" + term + "*))", new string[] { "description" });
            PrintDirectoryAttrsDict(interestingDescrip, "Interesting Descriptions (default: pass) on User Objects");


            //GPP Password in SYSVOL
            var gppXml = Utilities.GetGPPXML();
            var gppData = Utilities.GetGPPPass(gppXml);
            PrintGPPPass(gppData);


            //GPP Password in Cache
            var gppCache = Utilities.GetGPPXML();
            var gppCacheData = Utilities.GetGPPPass(gppCache);
            PrintGPPPass(gppCacheData, false);


            //Interesting ACLs on the domain object
            var dcSyncList = new Dictionary<string, int>();
            var domDnList = new List<string> { rootDn };
            var domACLs = Utilities.GetInterestingACLs(domDnList, out dcSyncList);
            PrintACLs(domACLs, "Interesting ACLs on the domain object");

            //DC Sync Accounts
            PrintDCSync(dcSyncList);


            //"CN=" + gPOID + ",CN=Policies,CN=System," + rootDn
            var gpoDnList = new List<string>();
            foreach (var gpo in GPOs)
            {
                gpoDnList.Add("CN=" + gpo.Key + ",CN=Policies,CN=System," + rootDn);
            }
            var gpoACLs = Utilities.GetInterestingACLs(gpoDnList, out _);
            PrintACLs(gpoACLs, "Interesting ACLs on Group Policy Objects");


            //Confidential Attributes
            var confidentialAttrs = Utilities.GetSingleAttr(schemaDn, @"(searchFlags:1.2.840.113556.1.4.803:=128)", "name");
            PrintSingleAttribute(confidentialAttrs, "Confidential Attributes");
            
            //Machine Owners
            var hasCreator = Utilities.GetGeneral(ouDn, @"(ms-ds-CreatorSID=*)", new string[] { "ms-ds-CreatorSID" });

            PrintDirectoryAttrsDict(hasCreator, "Machine Owners");
           
            //LAPS Password View Access
            var ouList = Utilities.GetSingleAttr(ouDn, "(objectClass=organizationalUnit)", "distinguishedName");
            var ouACLs = Utilities.GetLAPSViewACLs(ouList);
            PrintACLs(ouACLs, "LAPS Password View Access");
            Console.WriteLine();
            var hasLaps = Utilities.GetGeneral(ouDn, @"(ms-Mcs-AdmPwdExpirationTime=*)", new string[] { "sAMAccountName", "ms-Mcs-AdmPwd" });
            PrintDirectoryAttrsDict(hasLaps, null);

            //Restricted Groups
            var allOUs = Utilities.GetAllOUs(ouDn);

            var ouGPOs = Utilities.GetAppliedGPOs(userGroupList, allOUs, GPOs);

            var rGroups = Utilities.GetRestrictedGroup(ouGPOs,GPOs);

            PrintRestrictedGroups(rGroups);
            

            Console.WriteLine(); 
        }



        

        public void InteraciveMenu(int cmdChoice = 0, string parameter = null)
        {
            int choice;

            if (cmdChoice == 0)
            {
                PrintMenu();
                
                while (true)
                {
                    try
                    {
                        Console.Write("Please Select an Action: ");
                        choice = Convert.ToInt32(Console.ReadLine());
                        break;
                    }
                    catch { InteraciveMenu(); }
                }
            }
            else
            {
                choice = cmdChoice;
            }
            

            Connect();

            switch (choice)
            {
                case 0:
                    Environment.Exit(0);
                    break;
                case 1://Collect LDAP DNS Records
                    PrintDNS();
                    break;
                case 2://Find Single LDAP DNS Record
                    if (parameter == null) {
                        Console.Write("Enter the Host Name to Search: ");
                    }
                    string dnshostname = parameter ??  Console.ReadLine();
                    PrintGreen("\n[*] Search in the Domain:");
                    Console.WriteLine("    {0}", Utilities.GetSingleDNSRecord(dnshostname, false));
                    
                    PrintGreen("\n[*] Search in the Forest:");
                    Console.WriteLine("    {0}", Utilities.GetSingleDNSRecord(dnshostname, true));
                    break;
                case 3://SPN Scan
                    if (parameter == null)
                    {
                        Console.Write("Enter the Service Name to Search (e.g. mssql* / wsman*): ");
                    }
                    string srvTerm = parameter ?? Console.ReadLine();
                    var rdpSpn = Utilities.GetGeneral(ouDn, @"(servicePrincipalName=" + srvTerm + ")", new string[] { "servicePrincipalName" });
                    PrintDirectoryAttrsDict(rdpSpn, "Accounts with Service SPNs");
                    break;
                case 4://Find Nested Group Membership
                    if (parameter == null)
                    {
                        Console.Write("Enter the Name to Search (e.g. Harry / DEVMachine$ ): ");
                    }
                    string nestedUser = parameter ?? Console.ReadLine();
                    var userGroupList = Utilities.GetNestedGroupMem(out string uguser, false, nestedUser);
                    PrintNestedGroupMem(userGroupList, uguser, nestedUser);
                    break;
                case 5://Search Interesting Term on User Description Fields
                    if (parameter == null)
                    {
                        Console.Write("Enter the Term to Search : ");
                    }
                    string searchTerm = parameter ?? Console.ReadLine();
                    var interestingDescrip = Utilities.GetGeneral(ouDn, @"(&(sAMAccountType=805306368)(description=*" + searchTerm + "*))", new string[] { "description" });
                    PrintDirectoryAttrsDict(interestingDescrip, "Interesting Descriptions on User Objects");
                    break;
                case 6://Enumerate Interesting ACLs on an Object
                    if (parameter == null)
                    {
                        Console.Write("Enter the Distinguished Name to Search (e.g. DC=Domain,DC=Local): ");
                    }
                    string objDn = parameter ?? Console.ReadLine();
                    var objDnList = new List<string> { objDn };
                    var objACLs = Utilities.GetInterestingACLs(objDnList, out _);
                    PrintACLs(objACLs, "Interesting ACLs on the object");
                    break;
                case 7://NetSessionEnum
                    if (parameter == null)
                    {
                        Console.Write("Enter the Host Name to Enumerate Session : ");
                    }
                    string sessHostname = parameter ?? Console.ReadLine();
                    PrintNetSession(sessHostname);
                    break;
                case 8://NetLocalGroupGetMembers
                    if (parameter == null)
                    {
                        Console.Write("Enter the Host Name to Enumerate Users : ");
                    }
                    string userHostname = parameter ?? Console.ReadLine();
                    PrintNetWkstaUserEnum(userHostname);
                    break;
                case 9://NetWkstaUserEnum
                    if (parameter == null)
                    {
                        Console.Write("Enter the Host Name to Enumerate Local Group : ");
                    }
                    string groupHostname = parameter ?? Console.ReadLine();
                    PrintNetLocalGroupGetMembers(groupHostname);
                    break;
                default:
                    InteraciveMenu();
                    break;
            }
        }


        //FindOne
        internal static SearchResultEntry GetSingleResultEntry(string dn, string filter, SearchScope scope, string[] attrsToReturn, bool useGC)
        {
            var connection = useGC ? ConnectGCLDAP() : ConnectLDAP();

            var request = new SearchRequest(dn, filter, scope);//, attrsToReturn);

            // the size of each page
            var pageReqControl = new PageResultRequestControl(500);

            // turn off referral chasing so that data 
            // from other partitions is not returned

            var searchControl = new SearchOptionsControl(SearchOption.DomainScope);

            //To retrieve nTSecurityDescriptor attribute https://github.com/BloodHoundAD/SharpHound3/blob/master/SharpHound3/DirectorySearch.cs#L157
            var securityDescriptorFlagControl = new SecurityDescriptorFlagControl
            {
                SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
            };
            request.Controls.Add(securityDescriptorFlagControl);
            request.Controls.Add(pageReqControl);
            request.Controls.Add(searchControl);

            try
            {
                var response = (SearchResponse)connection.SendRequest(request);

                if (response.Entries.Count == 0) { return null; }

                return response.Entries[0];
            }
            catch (Exception e)
            {
                Debug.WriteLine("[x] Collecting SingleResultEntry Failed (Filter: [{0}])...",filter);
                PrintYellow("[x] ERROR: " + e.Message);
                return null;
            }
            finally
            {
                if (useGC)
                {
                    connection.Dispose();
                }
            }
        }


        //FindAll
        internal static IEnumerable<SearchResultEntry> GetResultEntries(string dn, string filter, SearchScope scope, string[] attrsToReturn, bool useGC = false)
        {
            var connection = useGC ? ConnectGCLDAP() : ConnectLDAP();

            var request = new SearchRequest(dn, filter, scope, attrsToReturn);

            // the size of each page
            var pageReqControl = new PageResultRequestControl(500);

            // turn off referral chasing so that data 
            // from other partitions is not returned

            var searchControl = new SearchOptionsControl(SearchOption.DomainScope);

            //To retrieve nTSecurityDescriptor attribute https://github.com/BloodHoundAD/SharpHound3/blob/master/SharpHound3/DirectorySearch.cs#L157
            var securityDescriptorFlagControl = new SecurityDescriptorFlagControl
            {
                SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
            };
            request.Controls.Add(securityDescriptorFlagControl);
            request.Controls.Add(pageReqControl);
            request.Controls.Add(searchControl);

            while (true)
            {
                SearchResponse response;

                try
                {
                    response = (SearchResponse)connection.SendRequest(request);
                }
                catch (Exception e)
                {
                    //Console.WriteLine(e.StackTrace);
                    PrintYellow($"[X] ERROR: {e.Message} (Cannot find the provided DN/OU)");
                    yield break;
                }

                if (response.Controls.Length != 1 || !(response.Controls[0] is PageResultResponseControl))
                {
                    Console.WriteLine("The server does not support this advanced search operation");
                    yield break;
                }

                var pageResControl = (PageResultResponseControl)response.Controls[0];

                //Console.WriteLine("\n[*] This page contains {0} response entries:\n", response.Entries.Count);

                foreach (SearchResultEntry entry in response.Entries)
                {
                    yield return entry;
                }

                if (pageResControl.Cookie.Length == 0) { break; }

                pageReqControl.Cookie = pageResControl.Cookie;

            }
        }






        public static DirectoryEntry GetSingleDirectoryEntry(string dn)
        {
            try
            {
                //var entry = new DirectoryEntry("LDAP://" + dc + ":" + port + "/" + dn, username, _password);//, AuthenticationTypes.Secure | AuthenticationTypes.SecureSocketsLayer);
                var entry = new DirectoryEntry("LDAP://" + dc + "/" + dn, username, _password);
                _entryPool.Add(entry);

                return entry;
            }
            catch (Exception e) { PrintYellow("[x] Error getting a single DirectoryEntry: " + e.Message); return null; }
        }


        private static LdapConnection ConnectLDAP()
        {
            if (_ldapConnections.TryTake(out var connection))
            {
                return connection;
            }

            var identifier = new LdapDirectoryIdentifier(dc, port, false, false);

            connection = (username != null) ?
                new LdapConnection(identifier, new NetworkCredential(username, _password)) :
                new LdapConnection(identifier);
            //new LdapConnection(identifier, new NetworkCredential(string.Empty, string.Empty))
            //{
            //    AuthType = AuthType.Anonymous
            //};
            connection.SessionOptions.SecureSocketLayer = useLdaps ? true : false;
            if (!disableSigning)
            {
                connection.SessionOptions.Signing = true;
                connection.SessionOptions.Sealing = true;
            }

            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            connection.SessionOptions.SendTimeout = new TimeSpan(0, 0, 10, 0);
            connection.Timeout = new TimeSpan(0, 0, 10, 0);
            connection.AuthType = AuthType.Negotiate;
            connection.SessionOptions.VerifyServerCertificate += delegate { return true; };
            
            _ldapConnections.Add(connection);
            return connection;
        }


        private static LdapConnection ConnectGCLDAP()
        {
            var identifier = new LdapDirectoryIdentifier(dc, 3268);

            var connection = (username != null) ?
                new LdapConnection(identifier, new NetworkCredential(username, _password)) :
                new LdapConnection(identifier);
            connection.SessionOptions.SecureSocketLayer = useLdaps ? true : false;
            if (!disableSigning)
            {
                connection.SessionOptions.Signing = true;
                connection.SessionOptions.Sealing = true;
            }
            connection.SessionOptions.Signing = true;
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            connection.SessionOptions.VerifyServerCertificate += delegate { return true; };
            connection.Timeout = new TimeSpan(0, 5, 0);

            return connection;
        }

































        



        ~Collector()
        {
            try
            {
                foreach (var conn in _ldapConnections)
                {
                    conn.Dispose();
                }
                foreach (var entry in _entryPool)
                {
                    entry.Dispose();
                }
            }
            catch { }
            
        }

    }
}
