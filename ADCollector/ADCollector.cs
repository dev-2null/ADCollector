using System;
using System.DirectoryServices.ActiveDirectory;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;
using System.DirectoryServices;
using System.Collections.Generic;
using CommandLine;
using CommandLine.Text;


namespace ADCollector2
{
    class ADCollector
    {
        private static Domain domain;
        private static Forest forest;
        private static bool ldaps;


        public class Options
        {
            [Option('d', "Domain", DefaultValue = null, HelpText = "Domain to enumerate", MutuallyExclusiveSet = "DomainOption")]
            public string Domain { get; set; }

            [Option('s', "Ldaps", DefaultValue = false, HelpText = "LDAP over SSL/TLS")]
            public bool Ldaps { get; set; }

            [HelpOption]
            public string GetHelp()
            {
                var help = @"ADCollector v2.0.1
Usage: ADCollector.exe <options>
    
    -d , --Domain (Default: current domain)
           Enumerate the specified domain

    -s , --Ldaps (Default: use LDAP)
           Use LDAP over SSL/TLS
                ";
                return help;
            }

        }


        public static void Main(string[] args)
        {
            //if (args == null)
            //    throw new ArgumentNullException(nameof(args));

            var options = new Options();

            if (!Parser.Default.ParseArguments(args, options))
            {
                return;
            }

            if (options.Domain != null)
            {
                try
                {
                    var context = new DirectoryContext(DirectoryContextType.Domain, options.Domain);
                    domain = Domain.GetDomain(context);
                    forest = domain.Forest;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Domain \"{0}\" does not exist!", options.Domain);
                    Console.WriteLine(e.Message);
                }
            }
            else
            {
                domain = Domain.GetCurrentDomain();
                forest = Forest.GetCurrentForest();
            }

            ldaps |= options.Ldaps;


            PrintBanner();



            var rootDSE = new DirectoryEntry("LDAP://rootDSE");

            //CN = Schema,CN = Configuration,
            string schemaNamingContext = rootDSE.Properties["schemaNamingContext"].Value.ToString();

            //CN = Configuration,
            string configurationNamingContext = rootDSE.Properties["configurationNamingContext"].Value.ToString();

            //forest root domain
            string rootDomainNamingContext = rootDSE.Properties["rootDomainNamingContext"].Value.ToString();

            //Domain DN: DC=child,DC=domain,DC=local
            string rootDn = "DC=" + domain.Name.Replace(".", ",DC=");

            //Forest DN: DC=domain,DC=local
            string forestDn = rootDomainNamingContext;

            //foreach(var version in rootDSE.Properties["supportedControl"])
            //{
            //    Console.WriteLine("   SupportedVersion: {0}",version);
            //}
            //Console.WriteLine();

            Console.WriteLine();
            Console.WriteLine("[-] LDAP basic Info:");
            Console.WriteLine();

            foreach (var mech in rootDSE.Properties["supportedSASLMechanisms"])
            {
                Console.WriteLine("    SupportedSASLMechanisms: {0}", mech);
            }
            Console.WriteLine();


            var domainFunc = Enum.Parse(typeof(Functionality), rootDSE.Properties["domainFunctionality"].Value.ToString());
            Console.WriteLine("    DomainFunctionality:              {0}", domainFunc);
            var forestFunc = Enum.Parse(typeof(Functionality), rootDSE.Properties["forestFunctionality"].Value.ToString());
            Console.WriteLine("    ForestFunctionality:              {0}", forestFunc);
            var dcFunc = Enum.Parse(typeof(Functionality), rootDSE.Properties["domainControllerFunctionality"].Value.ToString());
            Console.WriteLine("    DomainControllerFunctionality:    {0}", dcFunc);


            ////////////////////Basic Info

            Console.WriteLine("\n[-] Current Domain:        {0}\n", domain.Name);

            Console.WriteLine("\n[-] Current Forest:        {0}\n", forest.Name);

            Console.WriteLine("\n[-] Domains in the current forest:\n");

            Functions.GetDomains(forest);

            Console.WriteLine("\n[-] Domain Controllers in the current domain:\n");

            Functions.GetDCs(domain);


            var connection = Functions.GetConnection(domain.Name, ldaps);

            string TDOFilter = @"(objectCategory=TrustedDomain)";

            Console.WriteLine();
            Console.WriteLine("[-] Trusted Domain Objects in the current domain:");
            Console.WriteLine();
            string[] forattrsToReturn = { "name" };
            string TDOdomainDn = "CN=System," + rootDn;
            Functions.GetResponse(connection, TDOFilter, SearchScope.Subtree, forattrsToReturn, TDOdomainDn, "single");


            Console.WriteLine();
            Console.WriteLine("[-] Domain Trust Relationships:");
            Console.WriteLine();
            Functions.GetDomainTrusts(domain);


            Console.WriteLine();
            Console.WriteLine("[-] Trusted Domain Objects in the current forest root domain:");
            Console.WriteLine();
            string[] domattrsToReturn = { "name" };
            string TDOforestDn = "CN=System," + forestDn;
            Functions.GetResponse(connection, TDOFilter, SearchScope.Subtree, domattrsToReturn, TDOforestDn, "single");


            Console.WriteLine();
            Console.WriteLine("[-] Forest Trust Relationships:");
            Console.WriteLine();
            Functions.GetForestTrusts(forest);


            Console.WriteLine();
            Console.WriteLine("[-] Unconstrained Delegation Accounts in the current domain:");
            Console.WriteLine();
            string unconstrainedFilter = @"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))";
            string[] unconAttrs = { "distinguishedName" };
            Functions.GetResponse(connection, unconstrainedFilter, SearchScope.Subtree, unconAttrs, rootDn, "single");


            Console.WriteLine();
            Console.WriteLine("[-] Privileged Accounts in the current domain:");
            Console.WriteLine();
            string adminsFilter = @"(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))";
            string[] AdminsAttrs = { "member" };
            Functions.GetResponse(connection, adminsFilter, SearchScope.Subtree, AdminsAttrs, forestDn, "multi");


            Console.WriteLine();
            Console.WriteLine("[-] MSSQL SPNs in the current domain:");
            Console.WriteLine();
            string mssqlFilter = @"(servicePrincipalName=MSSQL*)";
            string[] mssqlAttrs = { "sAMAccountName", "servicePrincipalName" };
            Functions.GetResponse(connection, mssqlFilter, SearchScope.Subtree, mssqlAttrs, rootDn, "mssql");


            Console.WriteLine();
            Console.WriteLine("[-] DontRequirePreauth accounts in the current domain:");
            Console.WriteLine();
            string noPreAuthFilter = @"(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
            string[] noPreAuthAttrs = { "sAMAccountName" };
            Functions.GetResponse(connection, noPreAuthFilter, SearchScope.Subtree, noPreAuthAttrs, rootDn, "single");


            Console.WriteLine();
            Console.WriteLine("[-] AdminSDHolder protected accounts in the current domain:");
            Console.WriteLine();
            string adminSDHolderFilter = @"(&(adminCount=1)(objectCategory=person))";
            string[] adminSDHolderAttrs = { "sAMAccountName" };
            Functions.GetResponse(connection, adminSDHolderFilter, SearchScope.Subtree, adminSDHolderAttrs, rootDn, "single");


            Console.WriteLine();
            Console.WriteLine("[-] Confidential Attributes:");
            Console.WriteLine();
            string confidentialFilter = @"(searchFlags:1.2.840.113556.1.4.803:=128)";
            string[] confidentialAttrs = { "name" };
            Functions.GetResponse(connection, confidentialFilter, SearchScope.Subtree, confidentialAttrs, schemaNamingContext, "single");


            /*
             * Not printing it since there could be thousands
             * of GPOs            
             * Just cache CN with DisplayName in a dictionary
             * for future usage (PrintGplink)          
            Console.WriteLine();
            Console.WriteLine("[-] Group Policies in the current domain:");
            Console.WriteLine();
            */
            string gpoFilter = @"(objectCategory=groupPolicyContainer)";
            string gpoDn = "CN=Policies,CN=System," + rootDn;
            string[] gpoAttrs = { "displayName", "cn" };
            Functions.GetResponse(connection, gpoFilter, SearchScope.OneLevel, gpoAttrs, gpoDn, "gpo");



            Console.WriteLine();
            Console.WriteLine("[-] Current Domain attributes:");
            Console.WriteLine();
            string domainFilter = @"(objectCategory=domain)";
            string[] domainAttrs = { "minPWDLength", "maxPWDAge", "lockoutThreshold", "gplink", "ms-DS-MachineAccountQuota" };
            Functions.GetResponse(connection, domainFilter, SearchScope.Subtree, domainAttrs, rootDn, "domain");



            Console.WriteLine();
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
            Console.WriteLine("   v2.0.1  by dev2null\r\n");
        }


        [Flags]
        public enum Functionality
        {
            DS_BEHAVIOR_WIN2000 = 0,
            DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS = 1,
            DS_BEHAVIOR_WIN2003 = 2,
            DS_BEHAVIOR_WIN2008 = 3,
            DS_BEHAVIOR_WIN2008R2 = 4,
            DS_BEHAVIOR_WIN2012 = 5,
            DS_BEHAVIOR_WIN2012R2 = 6,
            DS_BEHAVIOR_WIN2016 = 7
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
