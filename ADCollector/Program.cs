using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;




namespace ADCollector2
{
    class MainClass
    {
        private static Domain domain;
        private static Forest forest;
        private static string domainName;
        private static bool ldaps;

        public static void Main(string[] args)
        {
            PrintBanner();

            // Command line argument: domainName, ldaps
            // -Domain domain.local
            // -ldaps 

            domainName = null;
            ldaps = false;

            if (domainName != null)
            {
                try
                {
                    var context = new DirectoryContext(DirectoryContextType.Domain, domainName);
                    domain = Domain.GetDomain(context);
                    forest = domain.Forest;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Domain \"{0}\" does not exist!", domainName);
                    Console.WriteLine(e.Message);
                }
            }
            else
            {
                domain = Domain.GetCurrentDomain();
                forest = Forest.GetCurrentForest();
            }



            //Domain DN: DC=child,DC=domain,DC=local
            string rootDn = "DC=" + domain.Name.Replace(".", ",DC=");

            //Forest DN: DC=domain,DC=local
            string forestDn = "DC=" + forest.Name.Replace(".", ",DC=");


            //////////////////////Basic Info

            Console.WriteLine("\n[-] Current Domain:        {0}\n", domain.Name);

            Console.WriteLine("\n[-] Current Forest:        {0}\n", forest.Name);

            Console.WriteLine("\n[-] Domains in the current forest:\n");

            GetDomains(forest);

            Console.WriteLine("\n[-] Domain Controllers in the current domain:\n");

            GetDCs(domain);


            var connection = GetConnection(domain.Name, ldaps);

            string TDOFilter = @"(objectClass=TrustedDomain)";


            Console.WriteLine();
            Console.WriteLine("[-] Trusted Domain Objects in the current domain:");
            Console.WriteLine();
            string[] forattrsToReturn = { "name" };
            string TDOdomainDn = "CN=System," + rootDn;
            GetResponse(connection, TDOFilter, SearchScope.Subtree, forattrsToReturn, TDOdomainDn, "single");


            Console.WriteLine();
            Console.WriteLine("[-] Domain Trust Relationships:");
            Console.WriteLine();
            GetDomainTrusts(domain);


            Console.WriteLine();
            Console.WriteLine("[-] Trusted Domain Objects in the current forest root domain:");
            Console.WriteLine();
            string[] domattrsToReturn = { "name" };
            string TDOforestDn = "CN=System," + forestDn;
            GetResponse(connection, TDOFilter, SearchScope.Subtree, domattrsToReturn, TDOforestDn, "single");


            Console.WriteLine();
            Console.WriteLine("[-] Forest Trust Relationships:");
            Console.WriteLine();
            GetForestTrusts(forest);


            Console.WriteLine();
            Console.WriteLine("[-] Unconstrained Delegation Accounts in the current domain:");
            Console.WriteLine();
            string unconstrainedFilter = @"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))";
            string[] unconAttrs = { "distinguishedName" };
            GetResponse(connection, unconstrainedFilter, SearchScope.Subtree, unconAttrs, rootDn, "single");


            Console.WriteLine();
            Console.WriteLine("[-] Privileged Accounts in the current domain:");
            Console.WriteLine();
            string adminsFilter = @"(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))";
            string[] AdminsAttrs = { "member" };
            GetResponse(connection, adminsFilter, SearchScope.Subtree, AdminsAttrs, forestDn, "multi");


            Console.WriteLine();
            Console.WriteLine("[-] MSSQL SPNs in the current domain:");
            Console.WriteLine();
            string mssqlFilter = @"(servicePrincipalName=MSSQL*)";
            string[] mssqlAttrs = { "sAMAccountName", "servicePrincipalName" };
            GetResponse(connection, mssqlFilter, SearchScope.Subtree, mssqlAttrs, rootDn, "mssql");



            Console.WriteLine();
            Console.WriteLine("[-] Confidential Attributes:");
            Console.WriteLine();
            string confidentialFilter = @"(searchFlags:1.2.840.113556.1.4.803:=128)";
            string schemaDn = "CN=Schema,CN=Configuration," + forestDn;
            string[] confidentialAttrs = { "name" };
            GetResponse(connection, confidentialFilter, SearchScope.Subtree, confidentialAttrs, schemaDn, "single");


            Console.WriteLine();
            Console.WriteLine("[-] Group Policies in the current domain:");
            Console.WriteLine();
            string gpoFilter = @"(objectClass=groupPolicyContainer)";
            string gpoDn = "CN=Policies,CN=System," + rootDn;
            string[] gpoAttrs = { "displayName", "cn" };
            GetResponse(connection, gpoFilter, SearchScope.OneLevel, gpoAttrs, gpoDn);


            //string dnsfilter = @"(&(objectClass=dnsZone)(!(DC=*arpa))(!(DC=RootDNSServers))(!(DC=..TrustAnchors)))";
            //var dnsrequest = GetRequest(dnsfilter, subtree, attrsToReturn, "DC=ForestDnsZones,DC=corpdir,DC=net");
            //GetResponse(connection, dnsrequest);

            Console.WriteLine();
        }


        public static void GetDomains(Forest currentForest)
        {
            foreach (Domain domain in currentForest.Domains)
            {
                try
                {
                    Console.WriteLine(" * {0}", domain.Name);

                    DirectoryEntry domainEntry = domain.GetDirectoryEntry();

                    using (domainEntry)
                    {

                        var domainSID = new SecurityIdentifier((byte[])domainEntry.Properties["objectSid"][0], 0);

                        Console.WriteLine("   Domain SID:   {0}\n", domainSID);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.GetType().Name + " : " + e.Message);
                }

            }
        }



        public static void GetDCs(Domain currentDomain)
        {
            //foreach (DomainController dc in currentDomain.FindAllDomainControllers())
            foreach (DomainController dc in currentDomain.FindAllDiscoverableDomainControllers())
            {
                try
                {
                    string DCType = "";

                    if (dc.IsGlobalCatalog())
                    {
                        DCType += "[Global Catalog] ";
                    }

                    using (DirectoryEntry dcServerEntry = dc.GetDirectoryEntry())
                    {
                        //Console.WriteLine(dcEntry.Properties["primaryGroupID"].Value);
                        //Exception: Object reference not set to an instance of an object

                        //https://stackoverflow.com/questions/34925136/why-property-primarygroupid-missing-for-domain-controller
                        //dc.GetDirectoryEntry() returns a server object, not the computer object of DC
                        //primaryGroupID does not exist on server object

                        using (DirectoryEntry dcEntry = new DirectoryEntry("LDAP://" + dcServerEntry.Properties["serverReference"].Value))
                        {
                            //Check if the primaryGroupID attribute has a value of 521 (Read-Only Domain Controller)
                            if ((int)dcEntry.Properties["primaryGroupID"].Value == 521)
                            {
                                DCType += "[Read-Only Domain Controller]";
                            }
                        }
                    }

                    Console.WriteLine(" * {0}  {1}", dc.Name, DCType);
                    Console.WriteLine("   IPAddress\t\t\t:  {0}", dc.IPAddress);
                    Console.WriteLine("   OS\t\t\t\t:  {0}", dc.OSVersion);
                    Console.WriteLine("   Site\t\t\t\t:  {0}", dc.SiteName);

                    string roles = "";

                    foreach (var role in dc.Roles)
                    {
                        roles += role + "   ";
                    }
                    Console.WriteLine("   Roles\t\t\t:  {0}", roles);

                    Console.WriteLine();

                }
                catch (Exception)
                {
                    Console.WriteLine(" * {0}:  RPC server is unavailable.", dc.Name);
                }
            }
        }




        public static void GetDomainTrusts(Domain currentDomain)
        {
            string sidStatus;

            Console.WriteLine("    {0,-30}{1,-30}{2,-15}{3,-20}\n", "Source", "Target", "TrustType", "TrustDirection");

            foreach (TrustRelationshipInformation trustInfo in currentDomain.GetAllTrustRelationships())
            {
                if (currentDomain.GetSidFilteringStatus(trustInfo.TargetName))
                {
                    sidStatus = "[SID Filtering is enabled]\n";
                }
                else
                {
                    sidStatus = "[Not Filtering SIDs]\n";
                }

                Console.WriteLine("    {0,-30}{1,-30}{2,-15}{3,-20}{4,-10}", trustInfo.SourceName, trustInfo.TargetName, trustInfo.TrustType, trustInfo.TrustDirection, sidStatus);
            }
        }



        public static void GetForestTrusts(Forest currentForest)
        {
            string sidStatus = "";

            Console.WriteLine("    {0,-30}{1,-30}{2,-15}{3,-20}\n", "Source", "Target", "TrustType", "TrustDirection");

            foreach (TrustRelationshipInformation trustInfo in currentForest.GetAllTrustRelationships())
            {
                try
                {
                    if (currentForest.GetSidFilteringStatus(trustInfo.TargetName))
                    {
                        sidStatus = "[SID Filtering is enabled]\n";
                    }
                    else
                    {
                        sidStatus = "[Not Filtering SIDs]\n";
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Something wrong with SID filtering");

                    Console.WriteLine("Error: {0}\n", e.Message);
                }

                Console.WriteLine("    {0,-30}{1,-30}{2,-15}{3,-20}{4,-10}", trustInfo.SourceName, trustInfo.TargetName, trustInfo.TrustType, trustInfo.TrustDirection, sidStatus);
            }
        }




        public static LdapConnection GetConnection(string domainName, bool ldaps)
        {
            var port = ldaps ? 636 : 389;

            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainName, port);

            var conn = new LdapConnection(identifier)
            {
                Timeout = new TimeSpan(0, 0, 5, 0)
            };

            if (ldaps)
            {
                conn.SessionOptions.ProtocolVersion = 3;
                conn.SessionOptions.SecureSocketLayer = true;
            }
            //Console.WriteLine("\n * LDAP Server is Connected");
            return conn;
        }


        public static void GetResponse(LdapConnection conn, string filter, SearchScope scope, string[] attrsToReturn, string dn, string printOption = null)
        {

            var request = new SearchRequest(dn, filter, scope, attrsToReturn);

            // the size of each page
            var pageReqControl = new PageResultRequestControl(500);

            // turn off referral chasing so that data 
            // from other partitions is not returned
            var searchControl = new SearchOptionsControl(SearchOption.DomainScope);

            request.Controls.Add(pageReqControl);
            request.Controls.Add(searchControl);


            SearchResponse response;
            PageResultResponseControl pageResControl = null;

            // loop through each page
            while (true)
            {
                try
                {
                    response = (SearchResponse)conn.SendRequest(request);

                    if (response.Controls.Length != 1 || !(response.Controls[0] is PageResultResponseControl))
                    {
                        Console.WriteLine("The server does not support this advanced search operation");
                        return;
                    }
                    pageResControl = (PageResultResponseControl)response.Controls[0];

                    //Console.WriteLine("\nThis page contains {0} response entries:\n", response.Entries.Count);

                    switch (printOption)
                    {
                        //if there's only one attribute needs to be returned
                        //and this attribute is a single-valued attribute
                        case "single":
                            PrintSingle(response, attrsToReturn[0]);
                            break;

                        //if there's only one attribute needs to be returned
                        //and this attribute is a multi-valued attribute
                        case "multi":
                            PrintMulti(response, attrsToReturn[0]);
                            break;

                        case "mssql":
                            PrintMSSQL(response);
                            break;

                        //default: print all attributesToReturned
                        default:
                            PrintAll(response);
                            break;
                    }


                    if (pageResControl.Cookie.Length == 0) { break; }

                    pageReqControl.Cookie = pageResControl.Cookie;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Unexpected error:  {0}", e.Message);
                    break;
                }
            }
        }



        public static void PrintSingle(SearchResponse response, string attr)
        {
            foreach (SearchResultEntry entry in response.Entries)
            {
                if (entry.Attributes[attr][0] is string)
                {
                    Console.WriteLine("  * {0}", entry.Attributes[attr][0]);
                }
                else if (entry.Attributes[attr][0] is byte[])
                {
                    Console.WriteLine("  * {0}", BitConverter.ToString((byte[])entry.Attributes[attr][0]).Replace("-", ""));
                }
                else
                {
                    Console.WriteLine("Unexpected single-valued type: {0}", entry.Attributes[attr][0].GetType().Name);
                }

            }
        }

        public static void PrintMulti(SearchResponse response, string attr)
        {
            foreach (SearchResultEntry entry in response.Entries)
            {
                Console.WriteLine("  {0}\n", entry.DistinguishedName);

                if (entry.Attributes[attr][0] is string)
                {
                    for (int i = 0; i < entry.Attributes[attr].Count; i++)
                    {
                        Console.WriteLine("  *  {0}: {1}", attr.ToUpper(), entry.Attributes[attr][i]);
                    }
                }
                else if (entry.Attributes[attr][0] is byte[])
                {
                    for (int i = 0; i < entry.Attributes[attr].Count; i++)
                    {
                        Console.WriteLine("  *  {0}: {1}", attr.ToUpper(), BitConverter.ToString((byte[])entry.Attributes[attr][i]).Replace("-", ""));
                    }
                }
                else
                {
                    Console.WriteLine("Unexpected multi-valued type {0}", entry.Attributes[attr][0].GetType().Name);
                }
                Console.WriteLine();
            }
        }

        public static void PrintAll(SearchResponse response)//, string[] attrsList)
        {
            foreach (SearchResultEntry entry in response.Entries)
            {
                var attrs = entry.Attributes;

                foreach (DirectoryAttribute attr in attrs.Values)
                {
                    Console.WriteLine("  * {0} : {1}", attr.Name.ToUpper(), entry.Attributes[attr.Name][0]);
                }

                Console.WriteLine();
            }

        }


        public static void PrintMSSQL(SearchResponse response)
        {
            foreach (SearchResultEntry entry in response.Entries)
            {

                Console.WriteLine("sAMAccountName:  {0}", entry.Attributes["sAMAccountName"][0]);

                var SPNs = entry.Attributes["servicePrincipalName"];

                var spnCount = SPNs.Count;

                if (spnCount > 1)
                {
                    for (int i = 0; i < spnCount; i++)
                    {
                        if (SPNs[i].ToString().Contains("MSSQL"))
                        {
                            Console.WriteLine(SPNs[i]);
                        }
                    }

                }
                else
                {
                    Console.WriteLine(SPNs[0]);
                }
                Console.WriteLine();
            }
        }


        public static void PrintBanner()
        {
            Console.WriteLine();
            Console.WriteLine(@"      _    ____   ____      _ _             _             ");
            Console.WriteLine(@"     / \  |  _ \ / ___|___ | | | ___  ___ _| |_ ___  _ __ ");
            Console.WriteLine(@"    / _ \ | | | | |   / _ \| | |/ _ \/ __|_  __/ _ \| '__|");
            Console.WriteLine(@"   / ___ \| |_| | |__| (_) | | |  __/ (__  | || (_) | |   ");
            Console.WriteLine(@"  /_/   \_\____/ \____\___/|_|_|\___|\___| |__/\___/|_|   ");
            Console.WriteLine();
            Console.WriteLine("   v2.0.0  by dev2null\r\n");
        }

        ////userAccountControl attribute ([MS-ADTS] section 2.2.16) TD flag 
        //[Flags]
        //public enum UACFlags
        //{
        //    SCRIPT = 0x1,
        //    ACCOUNT_DISABLE = 0x2,
        //    HOMEDIR_REQUIRED = 0x8,
        //    LOCKOUT = 0x10,
        //    PASSWD_NOTREQD = 0x20,
        //    PASSWD_CANT_CHANGE = 0x40,
        //    ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80,
        //    NORMAL_ACCOUNT = 0x200,
        //    INTERDOMAIN_TRUST_ACCOUNT = 0x800,
        //    WORKSTATION_TRUST_ACCOUNT = 0x1000,
        //    SERVER_TRUST_ACCOUNT = 0x2000,
        //    DONT_EXPIRE_PASSWD = 0x10000,
        //    SMARTCART_REQUIRED = 0x40000,
        //    TRUSTED_FOR_DELEGATION = 0x80000,
        //    NOT_DELEGATED = 0x100000,
        //    USE_DES_KEY_ONLY = 0x200000,
        //    DONT_REQUIRE_PREAUTH = 0x400000,
        //    PASSWORD_EXPIRED = 0x800000,
        //    TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000,
        //    NO_AUTH_DATA_REQUIRED = 0x2000000,
        //    PARTIAL_SECRETS_ACCOUNT = 0x4000000
        //}


        //// ([MS-ADTS] section 6.1.6.7.9) trustAttributes
        //[Flags]
        //public enum TrustAttributes
        //{
        //    NON_TRANSITIVE = 1,
        //    UPLEVEL_ONLY = 2,
        //    QUARANTINED_DOMAIN = 4,
        //    FOREST_TRANSITIVE = 8,
        //    CROSS_ORGANIZARION = 16,
        //    WITHIN_FOREST = 32,
        //    TREAT_AS_EXTERNAL = 64
        //}

        //// ([MS-ADTS] section 6.1.6.7.12) trustDirection
        //[Flags]
        //public enum TrustDirection
        //{
        //    DISABLE = 0,
        //    INBOUND = 1,
        //    OUTBOUND = 2,
        //    BIDIRECTIONAL =3
        //}

    }
}
