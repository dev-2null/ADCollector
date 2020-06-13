using System;
using System.DirectoryServices.ActiveDirectory;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;
using System.DirectoryServices;
using CommandLine;
using System.Collections.Generic;

namespace ADCollector2
{
    public class ADCollector
    {
        private static Domain domain;
        private static Forest forest;
        private static bool ldaps;
        public static List<String> trustdomains = new List<String>();


        public class Options
        {
            [Option("Domain", DefaultValue = null, HelpText = "Domain to enumerate", MutuallyExclusiveSet = "DomainOption")]
            public string Domain { get; set; }

            [Option("Ldaps", DefaultValue = false, HelpText = "LDAP over SSL/TLS")]
            public bool Ldaps { get; set; }

            [Option("Spns", DefaultValue = null, HelpText = "Enumearte interesting SPNs")]
            public bool Spns { get; set; }

            [Option("Term", DefaultValue = null, HelpText = "Term to search in user description field")]
            public string Term { get; set; }

            [Option("Acls", DefaultValue = null, HelpText = "Enumearte interesting ACLs on an object")]
            public string Acls { get; set; }

            //[Option('a', "Attributes", DefaultValue = null, HelpText = "User/Computer attributes enumerate")]
            //public string Attributes { get; set; }

            //[Option('p', "Path", DefaultValue = null, HelpText = "LDAP path (distinguishedName) of specified object")]
            //public string Path { get; set; }


            [HelpOption]
            public string GetHelp()
            {
                var help = @"
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

Example: .\ADCollector.exe --SPNs --Term key --Acls 'CN=Domain Admins,CN=Users,DC=lab,DC=local'
                ";
                return help;
            }

        }


        public static void Main(string[] args)
        {
            //if (args == null)
            //    throw new ArgumentNullException(nameof(args));

            PrintBanner();

            var options = new Options();

            if (!Parser.Default.ParseArguments(args, options)){ return;}

            //LDAPS
            ldaps |= options.Ldaps;

            //Domain
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
                    Console.WriteLine(e.Message);
                    return;
                }
            }
            else
            {
                try
                {
                    domain = Domain.GetCurrentDomain();
                    forest = Forest.GetCurrentForest();
                }
                catch(Exception e)
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(e.Message);
                }
                
            }


            
            try
            {
                Collector(options.Spns, options.Term, options.Acls);
            }
            catch
            {
                Console.WriteLine("Connection failed, Please check if you are using a domain account\n");
                Console.ResetColor();
            }
        }





        public static void Collector(bool spns, string term, string aclObject)
        {

            foreach (TrustRelationshipInformation trustInfo in Domain.GetCurrentDomain().GetAllTrustRelationships())
            {
                trustdomains.Add(trustInfo.TargetName);
            }

            foreach (TrustRelationshipInformation trustInfo in Forest.GetCurrentForest().GetAllTrustRelationships())
            {
                trustdomains.Add(trustInfo.TargetName);
            }


            //root DSE entry
            var rootDSE = new DirectoryEntry("LDAP://" + domain.Name + "/rootDSE");

            //CN = Schema,CN = Configuration,
            string schemaNamingContext = rootDSE.Properties["schemaNamingContext"].Value.ToString();

            //CN = Configuration,
            string configurationNamingContext = rootDSE.Properties["configurationNamingContext"].Value.ToString();

            //forest root domain
            string rootDomainNamingContext = rootDSE.Properties["rootDomainNamingContext"].Value.ToString();

            //Domain DN: DC=child,DC=domain,DC=local
            string rootDn = "DC=" + domain.Name.Replace(".", ",DC=");

            //Forest DN: DC=domain,DC=local
            string forestDn = "DC=" + forest.Name.Replace(".", ",DC=");

            

            var connection = Functions.GetConnection(domain.Name, ldaps);


            ////////////////Basic Info
            Console.WriteLine();
            PrintGreen("[-] Current Domain:        " + domain.Name);
            Console.WriteLine();

            Console.WriteLine();
            PrintGreen("[-] Current Forest:        " + forest.Name);
            Console.WriteLine();



            Console.WriteLine();
            PrintGreen("[-] LDAP basic Info:");
            Console.WriteLine();

            string[] rootDSEAttrs = { "supportedLDAPVersion", "supportedSASLMechanisms" };// "supportedLDAPPolicies", 

            foreach (string rootDSEAttr in rootDSEAttrs)
            {
                foreach (var attr in rootDSE.Properties[rootDSEAttr])
                {
                    Console.WriteLine("    {0}:    {1}", rootDSEAttr, attr);
                }
                Console.WriteLine();
            }

            var domainFunc = Enum.Parse(typeof(Helper.Functionality), rootDSE.Properties["domainFunctionality"].Value.ToString());
            Console.WriteLine("    DomainFunctionality:              {0}", domainFunc);

            var forestFunc = Enum.Parse(typeof(Helper.Functionality), rootDSE.Properties["forestFunctionality"].Value.ToString());
            Console.WriteLine("    ForestFunctionality:              {0}", forestFunc);

            var dcFunc = Enum.Parse(typeof(Helper.Functionality), rootDSE.Properties["domainControllerFunctionality"].Value.ToString());
            Console.WriteLine("    DomainControllerFunctionality:    {0}", dcFunc);

            rootDSE.Dispose();



            Console.WriteLine();
            PrintGreen("[-] Kerberos Policy & System Access:");
            Console.WriteLine();
            Functions.GetDomainPolicy(domain.Name);



            /*
            // * Not printing it since there could be thousands
            // * of GPOs            
            // * Just cache CN with DisplayName in a dictionary
            // * for future usage (PrintSearchResGplink)          
            Console.WriteLine();
            PrintGreen("[-] Group Policies");
            Console.WriteLine();
            */

            string gpoFilter = @"(objectCategory=groupPolicyContainer)";
            string gpoDn = "CN=Policies,CN=System," + rootDn;
            string[] gpoAttrs = { "displayName", "cn" };
            Functions.GetResponse(connection, gpoFilter, SearchScope.OneLevel, gpoAttrs, gpoDn, "gpo");



            Console.WriteLine();
            PrintGreen("[-] Current Domain attributes:");
            Console.WriteLine();
            string domainFilter = @"(objectCategory=domain)";
            string[] domainAttrs = { "minPWDLength", "maxPWDAge", "lockoutThreshold", "lockoutDuration", "gplink", "ms-DS-MachineAccountQuota" };
            Functions.GetResponse(connection, domainFilter, SearchScope.Subtree, domainAttrs, rootDn, "domain");




            Console.WriteLine();
            PrintGreen("[-] Discoverable Domain Controllers");
            Console.WriteLine();
            Functions.GetDCs(domain);



            Console.WriteLine();
            PrintGreen("[-] Domain Controllers:");
            Console.WriteLine();
            string dcFilter = @"(primaryGroupID=516)";
            string[] distinguishedName = { "distinguishedName" };
            Functions.GetResponse(connection, dcFilter, SearchScope.Subtree, distinguishedName, rootDn, "single");



            Console.WriteLine();
            PrintGreen("[-] Read-Only Domain Controllers:");
            Console.WriteLine();
            string gcFilter = @"(primaryGroupID=521)";
            string[] rodcAttrs = { "managedBy", "sAMAccountName" };
            Functions.GetResponse(connection, gcFilter, SearchScope.Subtree, rodcAttrs, rootDn, "multi");



            Console.WriteLine();
            PrintGreen("[-] Trust Accounts in the current domain");
            Console.WriteLine();
            string trustFilter = @"(userAccountControl:1.2.840.113556.1.4.803:=2048)";
            string[] trustAttrs = { "sAMAccountName" };
            Functions.GetResponse(connection, trustFilter, SearchScope.Subtree, trustAttrs, rootDn, "single");



            string TDOFilter = @"(objectCategory=TrustedDomain)";
            Console.WriteLine();
            PrintGreen("[-] Trusted Domain Objects in the current domain:");
            Console.WriteLine();
            string[] forattrsToReturn = { "name" };
            string TDOdomainDn = "CN=System," + rootDn;
            Functions.GetResponse(connection, TDOFilter, SearchScope.Subtree, forattrsToReturn, TDOdomainDn, "single");



            Console.WriteLine();
            PrintGreen("[-] Domain Trust Relationships:");
            Console.WriteLine();
            Functions.GetDomainTrusts(domain);


            if (ADCollector.trustdomains.Contains(forest.Name) || forest.Name == Forest.GetCurrentForest().Name)
            //If enumerating the target forest root domain but without any relationship
            {

                Console.WriteLine();
                PrintGreen("[-] Domains in the current forest:");
                Console.WriteLine();
                Functions.GetDomains(forest);


                Console.WriteLine();
                PrintGreen("[-] Trusted Domain Objects in the current forest root domain:");
                Console.WriteLine();
                string[] domattrsToReturn = { "name" };
                string TDOforestDn = "CN=System," + forestDn;
                Functions.GetResponse(connection, TDOFilter, SearchScope.Subtree, domattrsToReturn, TDOforestDn, "single");


                Console.WriteLine();
                PrintGreen("[-] Forest Trust Relationships:");
                Console.WriteLine();
                Functions.GetForestTrusts(forest);



                Console.WriteLine();
                PrintGreen("[-] Effective GPOs On the Current Computer:");
                Console.WriteLine();
                string pcName = Environment.GetEnvironmentVariable("COMPUTERNAME");
                Functions.GetAppliedGPOs(connection, rootDn, pcName, true);



                Console.WriteLine();
                PrintGreen("[-] Effective GPOs On the Current User:");
                Console.WriteLine();
                string uName = Environment.GetEnvironmentVariable("USERNAME");
                bool isPC = uName.Contains("$");
                uName =  isPC ? uName.Replace("$", string.Empty) : uName;
                Functions.GetAppliedGPOs(connection, rootDn, uName, isPC);
                


                Console.WriteLine();
                PrintGreen("[-] Nested Group Membership For the Current User:");
                Console.WriteLine();
                Functions.GetNestedGroupMem(connection, rootDn, uName, isPC);
            }




            Console.WriteLine();
            PrintGreen("[-] Restricted Groups:");
            Console.WriteLine();
            Functions.GetRestrictedGroup(rootDn);


            Console.WriteLine();
            PrintGreen("[-] Unconstrained Delegation Accounts");
            Console.WriteLine();
            //TRUSTED_FOR_DELEGATION
            //By default, DCs are configured to allow Kerberos Unconstrained Delegation.
            //So excluding DCs here
            string unconstrFilter = @"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))";
            string[] unconstrAttrs = { "", "sAMAccountName" };
            Functions.GetResponse(connection, unconstrFilter, SearchScope.Subtree, unconstrAttrs, rootDn, "multi");



            Console.WriteLine();
            PrintGreen("[-] Constrained Delegation [with S4U2Self enabled] Accounts (Any Authentication Protocol):");
            Console.WriteLine();
            //TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
            //By default, RODCs are configured to allow Kerberos Constrained Delegation with Protocol Transition.
            //So excluding RODCs here
            string s4u2sFilter = @"(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(!primaryGroupID=521))";
            string[] s4u2sAttrs = { "sAMAccountName" };
            Functions.GetResponse(connection, s4u2sFilter, SearchScope.Subtree, s4u2sAttrs, rootDn, "single");



            Console.WriteLine();
            PrintGreen("[-] Constrained Delegation Accounts with associated services:");
            Console.WriteLine();
            string constrFilter = @"(msDS-AllowedToDelegateTo=*)";
            string[] constrAttrs = { "msDS-AllowedToDelegateTo", "sAMAccountName" };
            Functions.GetResponse(connection, constrFilter, SearchScope.Subtree, constrAttrs, rootDn, "multi");



            Console.WriteLine();
            PrintGreen("[-] Resources-based Constrained Delegation Accounts:");
            Console.WriteLine();
            string rbconstrFilter = @"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
            string[] rbconstrAttrs = { "msDS-AllowedToActOnBehalfOfOtherIdentity", "sAMAccountName" };
            Functions.GetResponse(connection, rbconstrFilter, SearchScope.Subtree, rbconstrAttrs, rootDn, "multi");



            if (spns)
            {
                Console.WriteLine();
                PrintGreen("[-] Accounts with MSSQL SPNs:");
                Console.WriteLine();
                string mssqlFilter = @"(servicePrincipalName=mssql*)";
                string[] spnAttrs = { "sAMAccountName", "servicePrincipalName" };
                Functions.GetResponse(connection, mssqlFilter, SearchScope.Subtree, spnAttrs, rootDn, "spn", "mssql");


                Console.WriteLine();
                PrintGreen("[-] Accounts with Exchange SPNs:");
                Console.WriteLine();
                string exchangeFilter = @"(servicePrincipalName=exchange*)";
                Functions.GetResponse(connection, exchangeFilter, SearchScope.Subtree, spnAttrs, rootDn, "spn", "exchange");


                Console.WriteLine();
                PrintGreen("[-] Accounts with RDP SPNs:");
                Console.WriteLine();
                string termservFilter = @"(servicePrincipalName=term*)";
                Functions.GetResponse(connection, termservFilter, SearchScope.Subtree, spnAttrs, rootDn, "spn", "term");


                Console.WriteLine();
                PrintGreen("[-] Accounts with PS Remoting SPNs:");
                Console.WriteLine();
                string wsmanFilter = @"(servicePrincipalName=wsman*)";
                Functions.GetResponse(connection, wsmanFilter, SearchScope.Subtree, spnAttrs, rootDn, "spn", "wsman");

            }



            Console.WriteLine();
            PrintGreen("[-] Privileged Accounts:");
            Console.WriteLine();
            //string adminsFilter = @"(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))";
            //1.2.840.113556.1.4.1941 is the OID for LDAP_MATCHING_RULE_IN_CHAIN and LDAP_MATCHING_RULE_TRANSITIVE_EVAL
            string adminsFilter = "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users," + rootDn + "))";
            string[] AdminsAttrs = {  "sAMAccountName", "memberOf", };
            Functions.GetResponse(connection, adminsFilter, SearchScope.Subtree, AdminsAttrs, rootDn, "all");



            Console.WriteLine();
            PrintGreen("[-] Sensitive & Not Delegated Accounts:");
            Console.WriteLine();
            string sensiFilter = @"(userAccountControl:1.2.840.113556.1.4.803:=1048576)";
            string[] SensiAttrs = { "sAMAccountName" };
            Functions.GetResponse(connection, sensiFilter, SearchScope.Subtree, SensiAttrs, rootDn, "single");



            Console.WriteLine();
            PrintGreen("[-] AdminSDHolder Protected Accounts:");
            Console.WriteLine();
            string adminSDHolderFilter = @"(&(adminCount=1)(objectCategory=person))";
            string[] adminSDHolderAttrs = { "sAMAccountName" };
            Functions.GetResponse(connection, adminSDHolderFilter, SearchScope.Subtree, adminSDHolderAttrs, rootDn, "single");



            Console.WriteLine();
            PrintGreen("[-] User Accounts With SPN Set:");
            Console.WriteLine();
            string userSPNFilter = @"(&(sAMAccountType=805306368)(servicePrincipalName=*))";
            string[] spnAcountAttrs = { "sAMAccountName", "servicePrincipalName", "userAccountControl" };
            Functions.GetResponse(connection, userSPNFilter, SearchScope.Subtree, spnAcountAttrs, rootDn, "spn", "null");



            Console.WriteLine();
            PrintGreen("[-] Password Does Not Expire Accounts:");
            Console.WriteLine();
            string notExpireFilter = @"(userAccountControl:1.2.840.113556.1.4.803:=65536)";
            string[] notExpireAttrs = { "sAMAccountName" };
            Functions.GetResponse(connection, notExpireFilter, SearchScope.Subtree, notExpireAttrs, rootDn, "single");



            Console.WriteLine();
            PrintGreen("[-] DontRequirePreauth Accounts:");
            Console.WriteLine();
            string noPreAuthFilter = @"(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
            string[] noPreAuthAttrs = { "sAMAccountName" };
            Functions.GetResponse(connection, noPreAuthFilter, SearchScope.Subtree, noPreAuthAttrs, rootDn, "single");


            Console.WriteLine();
            PrintGreen("[-] Interesting Descriptions on User Objects:");
            Console.WriteLine();
            Functions.GetInterestingDescription(connection, rootDn, term);
            

            Console.WriteLine();
            PrintGreen("[-] Group Policy Preference Passwords in SYSVOL/Cache:");
            Console.WriteLine();
            string gppPath = "\\\\" + domain.Name + "\\SYSVOL\\" + domain.Name + "\\Policies\\";
            Functions.GetGPPP(Functions.GetGPPXml(gppPath));
            Functions.GetGPPP(Functions.GetCachedGPP());



            Console.WriteLine();
            if (aclObject != null)
            {
                PrintGreen("[-] Interesting ACLs on the object:");
                Console.WriteLine();
                Functions.GetInterestingAcls(aclObject, forestDn);
            }
            else
            {
                PrintGreen("[-] Interesting ACLs on the domain object:");
                Console.WriteLine();
                Functions.GetInterestingAcls(rootDn, forestDn);
            }



            Console.WriteLine();
            PrintGreen("[-] Unusual DCSync Accounts:");
            Console.WriteLine();
            Functions.GetDCSync();



            Console.WriteLine();
            PrintGreen("[-] Interesting ACLs on Group Policy Objects:");
            Console.WriteLine();
            Functions.GetInterestingGPOAcls(gpoDn, forestDn);


            Console.WriteLine();
            PrintGreen("[-] Confidential Attributes:");
            Console.WriteLine();
            string confidentialFilter = @"(searchFlags:1.2.840.113556.1.4.803:=128)";
            string[] confidentialAttrs = { "name" };
            Functions.GetResponse(connection, confidentialFilter, SearchScope.Subtree, confidentialAttrs, schemaNamingContext, "single");



            Console.WriteLine();
            PrintGreen("[-] LAPS Password View Access:");
            Console.WriteLine();
            string ouFilter = "(objectClass=organizationalUnit)";
            Functions.GetResponse(connection, ouFilter, SearchScope.Subtree, confidentialAttrs, rootDn, "ou");
            Functions.GetLAPSView(forestDn);




            connection.Dispose();

            Console.WriteLine();
        }




        public static void PrintGreen(string output)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(output);
            Console.ResetColor();
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
            Console.WriteLine("   v1.1.4  by dev2null\r\n");
        }


        

    }
}
