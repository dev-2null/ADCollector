using System;
using System.Net;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Collections.Generic;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;
using System.Collections.Concurrent;
using System.Security.Principal;
using CommandLine;

namespace ADCollector
{
    public class Collector
    {
        public static Domain domain;
        public static Forest forest;
        public static string rootDn;
        public static string forestDn;
        public static string schemaDn;
        public static string domainName;
        public static string forestName;
        public static bool useLdaps;
        public static string dc;
        public static int port;
        public static DirectoryEntry rootDSE;
        public static string username;
        private static string _password;
        internal static readonly ConcurrentBag<LdapConnection> _ldapConnections = new ConcurrentBag<LdapConnection>();
        internal static readonly ConcurrentBag<DirectoryEntry> _entryPool = new ConcurrentBag<DirectoryEntry>();




        public Collector(Options options)
        {
            Printer.PrintBanner();

            domainName = options.Domain;
            port = options.Ldaps ? 636 : 389;
            username = options.Username;
            _password = options.Password;
            dc = options.DC;


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
            rootDSE = GetSingleEntry("rootDSE");

            //Test Connection
            try
            {
                rootDSE.RefreshCache();
            }
            catch (Exception e)
            {
                Helper.PrintYellow("[x] Cannot connect to LDAP://" + dc + ":" + port + "/rootDSE");
                Helper.PrintYellow("[x] ERROR: " + e.Message);
                Environment.Exit(1);
            }


            //Domain DN: DC=child,DC=domain,DC=local
            rootDn = rootDSE.Properties["defaultNamingContext"].Value.ToString();

            //Forest DN: DC=domain,DC=local
            forestDn = rootDSE.Properties["rootDomainNamingContext"].Value.ToString();

            //CN = Schema,CN = Configuration,
            schemaDn = rootDSE.Properties["schemaNamingContext"].Value.ToString();

            domainName = rootDn.Replace("DC=", "").Replace(",", ".");
            forestName = forestDn.Replace("DC=", "").Replace(",", ".");
        }









        public void Run()
        {
            if (username != null)
            {
                Utilities.RunAs(domainName, username, _password, () =>
                {
                    Connect();

                    RunAllCommands();
                });
            }
            else
            {
                Connect();

                RunAllCommands();
            }
        }



        public void RunAllCommands()
        {
            //LDAP Basic Info
            Printer.PrintBasicInfo();

            //Kerberos Policies & System Access
            Printer.PrintKerberosPolicy(domainName);

            var GPOs = Utilities.GetGPO();

            //Domain Attributes
            Printer.PrintDomainAttr(rootDn, GPOs);

            //DC
            Printer.PrintDC();

            //RODC
            Printer.PrintDC(true);

            //TDO
            Printer.PrintTDO(rootDn);

            //Trusts
            Printer.PrintTrust(domainName);

            Printer.PrintNestedGroupMem(false, null);

            Printer.PrintNestedGroupMem(true, null);


            //EffectiveGPOsOnUser
            string userDn = Utilities.GetDN(false, out string uname, null);

            var userOUs = Utilities.GetMyOUs(uname, userDn, false);

            var userAppliedGPOs = Utilities.GetAppliedGPOs(userOUs, GPOs);

            Printer.PrintAppliedGPOs(userDn, userAppliedGPOs, false);


            //EffectiveGPOsOnComputer
            string computerDn = Utilities.GetDN(true, out string cname, null);

            var computerOUs = Utilities.GetMyOUs(cname, computerDn, true);

            var computerAppliedGPOs = Utilities.GetAppliedGPOs(computerOUs, GPOs);

            Printer.PrintAppliedGPOs(computerDn, computerAppliedGPOs, true);


            //Unconstrainde Delegation
            //TRUSTED_FOR_DELEGATION
            //By default, DCs are configured to allow Kerberos Unconstrained Delegation.
            //So excluding DCs here
            var udDict = Utilities.GetGeneral(rootDn, @"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))");
            Printer.PrintDirectoryAttrDict(udDict, "Unconstrained Delegation Accounts");


            //Constrainde Delegation
            //TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
            //By default, RODCs are configured to allow Kerberos Constrained Delegation with Protocol Transition.
            //So excluding RODCs here
            var cdDict = Utilities.GetGeneral(rootDn, @"(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(!primaryGroupID=521))");
            Printer.PrintDirectoryAttrDict(cdDict, "Constrained Delegation [with S4U2Self enabled] Accounts (Any Authentication Protocol)");


            ////Constrainde Delegation with Services
            var cdSrvDict = Utilities.GetGeneral(rootDn, @"(msDS-AllowedToDelegateTo=*)", "msDS-AllowedToDelegateTo");
            Printer.PrintDirectoryAttrDict(cdSrvDict, "Constrained Delegation Accounts with associated services");



            //Resources-based Constrained Delegation
            var rbcdSrvDict = Utilities.GetGeneral(rootDn, @"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", "msDS-AllowedToActOnBehalfOfOtherIdentity");
            Printer.PrintDirectoryAttrDict(rbcdSrvDict, "Resources-based Constrained Delegation Accounts");


            //SPN: MSSQL
            var mssqlSpn = Utilities.GetGeneral(rootDn, @"(servicePrincipalName=mssql*)", "servicePrincipalName");
            Printer.PrintDirectoryAttrDict(mssqlSpn, "Accounts with MSSQL Service SPNs");


            //SPN: EXCHANGE
            var exchangeSpn = Utilities.GetGeneral(rootDn, @"(servicePrincipalName=exchange*)", "servicePrincipalName");
            Printer.PrintDirectoryAttrDict(exchangeSpn, "Accounts with Exchange Service SPNs");


            ////SPN: RDP
            //var rdpSpn = Utilities.GetGeneral(rootDn, @"(servicePrincipalName=term*)", "servicePrincipalName");
            //Printer.PrintDirectoryAttrDict(rdpSpn, "Accounts with RDP Service SPNs");


            ////SPN: PSRemoting
            //var psremotingSpn = Utilities.GetGeneral(rootDn, @"(servicePrincipalName=wsman*)", "servicePrincipalName");
            //Printer.PrintDirectoryAttrDict(psremotingSpn, "Accounts with PS Remoting Service SPNs");


            //Privileged Accounts
            var privAccounts = Utilities.GetGeneral(rootDn, "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users," + rootDn + "))", "MemberOf");
            Printer.PrintDirectoryAttrDict(privAccounts, "Privileged Accounts");


            //Sensitive & Not Delegated
            var sensitiveAccounts = Utilities.GetGeneral(rootDn, @"(userAccountControl:1.2.840.113556.1.4.803:=1048576)");
            Printer.PrintDirectoryAttrDict(sensitiveAccounts, "Sensitive & Not Delegated Accounts");


            //AdminSDHolder
            var sdholderAccounts = Utilities.GetGeneral(rootDn, @"(&(adminCount=1)(objectCategory=person))");
            Printer.PrintDirectoryAttrDict(sdholderAccounts, "AdminSDHolder Protected Accounts");


            //Password Does Not Expire
            var passnotexpireAccounts = Utilities.GetGeneral(rootDn, @"(userAccountControl:1.2.840.113556.1.4.803:=65536)");
            Printer.PrintDirectoryAttrDict(passnotexpireAccounts, "Password Does Not Expire Accounts");


            //User Accounts With SPN
            var spnAccounts = Utilities.GetGeneral(rootDn, @"(&(sAMAccountType=805306368)(servicePrincipalName=*))", "servicePrincipalName");
            Printer.PrintDirectoryAttrDict(spnAccounts, "User Accounts With SPN Set");


            //DontRequirePreauth
            var nopreauthAccounts = Utilities.GetGeneral(rootDn, @"(userAccountControl:1.2.840.113556.1.4.803:=4194304)");
            Printer.PrintDirectoryAttrDict(nopreauthAccounts, "DontRequirePreauth Accounts");


            //Interesting Description
            string term = "pass";
            var interestingDescrip = Utilities.GetGeneral(rootDn, @"(&(sAMAccountType=805306368)(description=*" + term + "*))", "description");
            Printer.PrintDirectoryAttrDict(interestingDescrip, "Interesting Descriptions (default: pass) on User Objects");


            //GPP Password in SYSVOL
            var gppXml = Utilities.GetGPPXML();
            var gppData = Utilities.GetGPPPass(gppXml);
            Printer.PrintGPPPass(gppData);


            //GPP Password in Cache
            var gppCache = Utilities.GetGPPXML();
            var gppCacheData = Utilities.GetGPPPass(gppCache);
            Printer.PrintGPPPass(gppCacheData, false);


            //Interesting ACLs on the domain object
            var dcSyncList = new Dictionary<string, int>();
            var domDnList = new List<string> { rootDn };
            var domACLs = Utilities.GetInterestingACLs(domDnList,  out dcSyncList);
            Printer.PrintACLs(domACLs, "Interesting ACLs on the domain object");


            //DC Sync Accounts
            Printer.PrintDCSync(dcSyncList);


            //"CN=" + gPOID + ",CN=Policies,CN=System," + rootDn
            var gpoDnList = new List<string>();
            foreach(var gpo in GPOs)
            {
                gpoDnList.Add("CN=" + gpo.Key + ",CN=Policies,CN=System," + rootDn);
            }
            var gpoACLs = Utilities.GetInterestingACLs(gpoDnList, out _);
            Printer.PrintACLs(gpoACLs, "Interesting ACLs on Group Policy Objects");


            //Confidential Attributes
            var confidentialAttrs = Utilities.GetSingleAttr(schemaDn, @"(searchFlags:1.2.840.113556.1.4.803:=128)", "name");
            Printer.PrintSingleAttribute(confidentialAttrs, "Confidential Attributes");
 

            //LAPS Password View Access
            var ouList = Utilities.GetSingleAttr(rootDn, "(objectClass=organizationalUnit)", "distinguishedName");
            var ouACLs = Utilities.GetLAPSViewACLs(ouList);
            Printer.PrintACLs(ouACLs, "LAPS Password View Access");



        }



        

        public void InteraciveMenu(int cmdChoice = 0, string parameter = null)
        {
            int choice;

            if (cmdChoice == 0)
            {
                Printer.PrintMenu();
                
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
                case 1:
                    Printer.PrintDNS();
                    break;
                case 2:
                    if (parameter == null) {
                        Console.Write("Enter the Host Name to Search: ");
                    }
                    string dnshostname = parameter ??  Console.ReadLine();
                    Helper.PrintGreen("\n[*] Search in the Domain:");
                    Console.WriteLine("    {0}", Utilities.GetSingleDNSRecord(dnshostname, false));
                    
                    Helper.PrintGreen("\n[*] Search in the Forest:");
                    Console.WriteLine("    {0}", Utilities.GetSingleDNSRecord(dnshostname, true));
                    break;
                case 3:
                    if (parameter == null)
                    {
                        Console.Write("Enter the Service Name to Search (e.g. mssql* / wsman*): ");
                    }
                    string srvTerm = parameter ?? Console.ReadLine();
                    var rdpSpn = Utilities.GetGeneral(rootDn, @"(servicePrincipalName=" + srvTerm + ")", "servicePrincipalName");
                    Printer.PrintDirectoryAttrDict(rdpSpn, "Accounts with Service SPNs");
                    break;
                case 4:
                    if (parameter == null)
                    {
                        Console.Write("Enter the Name to Search (e.g. Harry / DEVMachine$ ): ");
                    }
                    string nestedUser = parameter ?? Console.ReadLine();
                    Printer.PrintNestedGroupMem(false, nestedUser);
                    break;
                case 5:
                    if (parameter == null)
                    {
                        Console.Write("Enter the Term to Search : ");
                    }
                    string searchTerm = parameter ?? Console.ReadLine();
                    var interestingDescrip = Utilities.GetGeneral(rootDn, @"(&(sAMAccountType=805306368)(description=*" + searchTerm + "*))", "description");
                    Printer.PrintDirectoryAttrDict(interestingDescrip, "Interesting Descriptions on User Objects");
                    break;
                case 6:
                    if (parameter == null)
                    {
                        Console.Write("Enter the Distinguished Name to Search (e.g. DC=Domain,DC=Local): ");
                    }
                    string objDn = parameter ?? Console.ReadLine();
                    var objDnList = new List<string> { objDn };
                    var objACLs = Utilities.GetInterestingACLs(objDnList, out _);
                    Printer.PrintACLs(objACLs, "Interesting ACLs on the object");
                    break;
                case 7:
                    if (parameter == null)
                    {
                        Console.Write("Enter the Host Name to Enumerate Session : ");
                    }
                    string sessHostname = parameter ?? Console.ReadLine();
                    Printer.PrintNetSession(sessHostname);
                    break;
                case 8:
                    if (parameter == null)
                    {
                        Console.Write("Enter the Host Name to Enumerate Users : ");
                    }
                    string userHostname = parameter ?? Console.ReadLine();
                    Printer.PrintNetWkstaUserEnum(userHostname);
                    break;
                case 9:
                    if (parameter == null)
                    {
                        Console.Write("Enter the Host Name to Enumerate Local Group : ");
                    }
                    string groupHostname = parameter ?? Console.ReadLine();
                    Printer.PrintNetLocalGroupGetMembers(groupHostname);
                    break;
                default:
                    InteraciveMenu();
                    break;
            }
        }




        internal static SearchResultEntry GetSingleResponse(string dn, string filter, SearchScope scope, string[] attrsToReturn, bool useGC)
        {
            var connection = useGC ? ConnectGCLDAP() : ConnectLDAP();

            var request = new SearchRequest(dn, filter, scope);//, attrsToReturn);

            // the size of each page
            var pageReqControl = new PageResultRequestControl(500);

            // turn off referral chasing so that data 
            // from other partitions is not returned

            var searchControl = new SearchOptionsControl(SearchOption.DomainScope);
            //Unhandled Exception: System.ComponentModel.InvalidEnumArgumentException: 
            //The value of argument 'value' (0) is invalid for Enum type 'SearchOption'.
            //var searchControl = new SearchOptionsControl();

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
                Console.WriteLine(e.Message);
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



        internal static IEnumerable<SearchResultEntry> GetResponses(string dn, string filter, SearchScope scope, string[] attrsToReturn, bool useGC = false)
        {
            var connection = useGC ? ConnectGCLDAP() : ConnectLDAP();

            var request = new SearchRequest(dn, filter, scope, attrsToReturn);

            // the size of each page
            var pageReqControl = new PageResultRequestControl(500);

            // turn off referral chasing so that data 
            // from other partitions is not returned

            var searchControl = new SearchOptionsControl(SearchOption.DomainScope);
            //Unhandled Exception: System.ComponentModel.InvalidEnumArgumentException: 
            //The value of argument 'value' (0) is invalid for Enum type 'SearchOption'.
            //var searchControl = new SearchOptionsControl();

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
                    Console.WriteLine("[X] ERROR: {0}",e.Message);
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






        public static DirectoryEntry GetSingleEntry(string dn)
        {
            try
            {
                var entry = new DirectoryEntry("LDAP://" + dc + ":" + port + "/" + dn, username, _password);
                _entryPool.Add(entry);
                return entry;
            }
            catch (Exception e) { Helper.PrintYellow("[x] ERROR: " + e.Message); return null; }
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

            connection.SessionOptions.Signing = true;
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            connection.SessionOptions.SendTimeout = new TimeSpan(0, 0, 10, 0);
            connection.Timeout = new TimeSpan(0, 0, 10, 0);

            connection.SessionOptions.SecureSocketLayer = useLdaps ? true : false;

            _ldapConnections.Add(connection);
            return connection;
        }


        private static LdapConnection ConnectGCLDAP()
        {
            var identifier = new LdapDirectoryIdentifier(dc, 3268);

            var connection = (username != null) ?
                new LdapConnection(identifier, new NetworkCredential(username, _password)) :
                new LdapConnection(identifier);

            connection.SessionOptions.Signing = true;
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

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
