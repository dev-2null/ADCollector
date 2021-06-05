using System;
using static ADCollector.Helper;
using static ADCollector.Collector;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using static ADCollector.Natives;
using System.DirectoryServices;

namespace ADCollector
{
    public class Printer
    {

        public static void PrintMenu()
        {
            Helper.PrintYellow("===================================");
            Helper.PrintYellow("          Interative Menu          ");
            Console.WriteLine("0.  - EXIT");
            Console.WriteLine("1.  - Collect LDAP DNS Records");
            Console.WriteLine("2.  - Find Single LDAP DNS Record");
            Console.WriteLine("3.  - SPN Scan");
            Console.WriteLine("4.  - Find Nested Group Membership");
            Console.WriteLine("5.  - Search Interesting Term on Users");
            Console.WriteLine("6.  - Enumerate Interesting ACLs on an Object");
            Console.WriteLine("7.  - NetSessionEnum");
            Console.WriteLine("8.  - NetLocalGroupGetMembers");
            Console.WriteLine("9.  - NetWkstaUserEnum");
            Helper.PrintYellow("===================================");

        }


        public static void PrintBasicInfo()
        {
            
            PrintGreen("\n[-] Current Domain:        " + domainName.ToUpper());

            PrintGreen("\n[-] Current Forest:        " + forestName.ToUpper());

            PrintGreen("\n[-] LDAP basic Info:\n");


            string[] attrs = { "serverName", "isSynchronized", "isGlobalCatalogReady", "dnsHostName", "ldapServiceName" };

            foreach (string name in attrs)
            {
                Console.WriteLine("    {0,-23}  {1,-20}", name + ":", rootDSE.Properties[name][0]);
            }
            Console.WriteLine();

            string[] rootDSEAttrs = { "supportedLDAPVersion", "supportedSASLMechanisms", "namingContexts" };

            foreach (string rootDSEAttr in rootDSEAttrs)
            {
                foreach (var attr in rootDSE.Properties[rootDSEAttr])
                {
                    Console.WriteLine("    {0}:    {1}", rootDSEAttr, attr);
                }
                Console.WriteLine();
            }


            string[] domainFuncName = {"domainFunctionality", "forestFunctionality", "domainControllerFunctionality" };

            foreach (string name in domainFuncName)
            {
                string domFunc = (Enum.Parse(typeof(Functionality), rootDSE.Properties[name].Value.ToString())).ToString();
                Console.WriteLine("    {0,-32}  {1,-20}", (name + ":"), domFunc);
            }
        }



        public static void PrintKerberosPolicy(string domName)
        {
            PrintGreen("\n[-] Kerberos Policy & System Access:\n");

            try
            {
                var policies = Utilities.GetDomainPolicy(domName);

                foreach (var policy in policies)
                {
                    Console.WriteLine("    {0, -25}  {1,-8}", (policy.Key + " :"), policy.Value);
                }
            }
            catch { }
        }


        public static void PrintDomainAttr(string rootDN, Dictionary<string, string> GPOs)
        {
            PrintGreen("\n[-] Current Domain attributes:\n");

            try
            {
                using (var entry = GetSingleEntry(rootDN))
                {
                    var sid = new SecurityIdentifier((byte[])entry.Properties["objectSid"][0], 0);

                    // Days or Minutes
                    bool useDay = true;
                    var maxPwdAge = ConvertLargeInteger(entry.Properties["maxPwdAge"][0], useDay);

                    var lockoutDuration = ConvertLargeInteger(entry.Properties["LockoutDuration"][0], !useDay);

                    Console.WriteLine("    {0, -25}  {1,-3}", "WhenCreated", entry.Properties["whenCreated"][0]);
                    Console.WriteLine("    {0, -25}  {1,-3}", "WhenChanged", entry.Properties["whenChanged"][0]);
                    Console.WriteLine("    {0, -25}  {1,-3}", "ObjectSID", sid.ToString());
                    Console.WriteLine("    {0, -25}  {1,-3}", "MachineAccountQuota", entry.Properties["ms-DS-MachineAccountQuota"][0]);
                    Console.WriteLine("    {0, -25}  {1,-3}", "MinPwdLength", entry.Properties["minPwdLength"][0]);
                    Console.WriteLine("    {0, -25}  {1,-3} Days", "MaxPwdAge", maxPwdAge);
                    Console.WriteLine("    {0, -25}  {1,-3}", "LockoutThreshold", entry.Properties["lockoutThreshold"][0]);
                    Console.WriteLine("    {0, -25}  {1,-3} Minutes", "LockoutDuration", lockoutDuration);
                    Console.WriteLine("\n  * Group Policies linked to the domain object\n");

                    //non-greedy search
                    Regex rx = new Regex(@"\{.+?\}", RegexOptions.Compiled);

                    string gplinks = (string)entry.Properties["gplink"][0];

                    MatchCollection matches = rx.Matches(gplinks);

                    foreach (Match match in matches)
                    {
                        Console.WriteLine("     - {0}", GPOs[match.Value]);
                        Console.WriteLine("       {0}", match.Value);
                        Console.WriteLine();
                    }
                }
            }
            catch (Exception e) {PrintYellow("[x] ERROR: " + e.Message); }
            
        }



        public static void PrintNestedGroupMem(bool onComputer = false, string customUser = null)
        {
            if (customUser != null)
            {
                if (customUser.Contains("$")) { onComputer = true; }
            }

            var groupList = Utilities.GetNestedGroupMem(out string guser, onComputer, customUser);

            PrintGreen("\n[-] Nested Group Membership for " + guser + "\n");

            foreach (var group in groupList)
            {
                Console.WriteLine("     {0,-60}  {1}", group, ConvertSIDToName(group) );
            }

        }



        public static void PrintDNS()
        {
            
            PrintGreen("\n[-] DNS Records in the Domain:\n");

            var ddnsDict = Utilities.GetDNS(false);

            foreach (var zone in ddnsDict)
            {
                Console.WriteLine("    * Zone: {0}", zone.Key);
                foreach(var dns in zone.Value)
                {
                    Console.WriteLine("      - {0,-20}  {1,-25}", dns.Value, dns.Key);
                }
            }

            PrintGreen("\n[-] DNS Records in the Forest:\n");

            var fdnsDict = Utilities.GetDNS(true);

            foreach (var zone in fdnsDict)
            {
                Console.WriteLine("    * Zone: {0}", zone.Key);
                foreach (var dns in zone.Value)
                {
                    Console.WriteLine("      - {0,-20}  {1,-25}", dns.Value, dns.Key);
                }
            }
        }




        public static void PrintDC(bool rodc = false)
        {
            if (!rodc)
            {
                PrintGreen("\n[-] Domain Controllers:\n");
            }
            else
            {
                PrintGreen("\n[-] Read-Only Domain Controllers:\n");
            }

            var dcList = Utilities.GetDC(rodc);

            if (dcList == null) { return; }

            foreach (var dc in dcList)
            {
                //If have permission
                if (!dc.Attributes.Contains("name")) { continue; }

                Console.WriteLine("  * DN: {0}",dc.DistinguishedName);

                foreach (string attr in dc.Attributes.AttributeNames)
                {
                    if (attr.ToLower() == "whencreated" || attr.ToLower() == "whenchanged")
                    {
                        Console.WriteLine("    {0, -25}  {1,-3}", attr + " : ", Helper.ConvertWhenCreated(dc.Attributes[attr][0].ToString()).ToString());
                    }
                    else
                    {
                        Console.WriteLine("    {0, -25}  {1,-3}", attr + " : ", dc.Attributes[attr][0]);
                    }
                }
                Console.WriteLine();
            }
        }



        public static void PrintTDO(string rootDN)
        {
            PrintGreen("\n[-] Trusted Domain Objects in the Current Domain:\n");

            var tdoList =  Utilities.GetTDO(rootDN);

            foreach (var trust in tdoList)
            {
                foreach (string name in trust.Attributes.AttributeNames)
                {
                    var value = trust.Attributes[name][0];

                    if (name.ToLower() == "trusttype")
                    {
                        value = (Enum.Parse(typeof(LDAPTrustType), value.ToString())).ToString();
                    }
                    else if (value is byte[])
                    {
                        value = new SecurityIdentifier((byte[])value, 0);
                    }
                    Console.WriteLine("    {0, -25}  {1,-3}", name + " : ", value);
                }
                Console.WriteLine();
            }
        }



        public static void PrintTrust(string domName)
        {
            PrintGreen("\n[-] Domain Trusts:\n");

            var trustResults = Utilities.GetDsEnumerateDomainTrusts(domName);
            if (trustResults == null)
            {
                return;
            }
            var trustList = Utilities.TrustEnum(trustResults);

            foreach (var trust in trustList)
            {
                foreach (var t in typeof(Trust).GetFields())
                {
                    Console.WriteLine("    {0, -25}  {1,-3}", t.Name, t.GetValue(trust));
                }
                Console.WriteLine();
            }
        }




        public static void PrintNetSession(string hostname)
        {
            PrintGreen("\n[-] Session Enum on " + hostname.ToUpper() + ":\n");

            var Results = Utilities.GetNetSessionEnum(hostname);

            if (Results == null) { }
            else
            {
                foreach (var info in Results)
                {
                    Console.WriteLine("    ------------------------------");
                    foreach (var t in info.GetType().GetFields())
                    {
                        Console.WriteLine("    {0, -25}  {1,-3}", t.Name.ToUpper() + " : ", t.GetValue(info));
                    }
                }
            }
        }




        public static void PrintNetWkstaUserEnum(string hostname)
        {
            PrintGreen("\n[-] User Enum on " + hostname.ToUpper() + ":\n");

            var Results = Utilities.GetNetWkstaUserEnum(hostname);

            if (Results == null) { }
            else
            {
                foreach (var info in Results)
                {
                    Console.WriteLine("    ------------------------------");
                    foreach (var t in info.GetType().GetFields())
                    {
                        Console.WriteLine("    {0, -25}  {1,-3}", t.Name.ToUpper() + " : ", t.GetValue(info));
                    }
                }
            }
        }




        public static void PrintNetLocalGroupGetMembers(string hostname, string localgroup = "administrators")
        {
            PrintGreen("\n[-] Local Group (Administrators) Enum on " + hostname.ToUpper() + ":\n");

            var Results = Utilities.GetNetLocalGroupGetMembers(hostname, localgroup);

            if (Results == null) { }
            else
            {
                foreach (var info in Results)
                {
                    Console.WriteLine("    ------------------------------");
                    foreach (var t in info.GetType().GetFields())
                    {
                        Console.WriteLine("    {0, -25}  {1,-3}", t.Name.ToUpper() + " : ", t.GetValue(info));
                    }
                }
            }
        }



        public static void PrintAppliedGPOs(string accountDn, List<AppliedGPOs> myGPOs, bool isComputer = false)
        {
            if (myGPOs == null) { return; }

            string title = isComputer ? "Computer" : "User";

            PrintGreen("\n[-] Effective GPOs Applied on the Current " + title + ":\n");

            Console.WriteLine("    * DN: {0}\n", accountDn);

            bool lowerOUBlocking = false;

            foreach (var gpo in myGPOs)
            {
                Console.Write("    - {0}  ", gpo.OUDn);

                if (gpo.IsBlocking)
                {
                    lowerOUBlocking = true;

                    PrintYellow(" [Blocking Inheritance]");
                }
                else { Console.WriteLine(); }


                foreach (var gpoAttr in gpo.LinkedGPOs)
                {
                    string gponame = gpoAttr.GPOName;

                    if (gpoAttr.isEnforced)
                    {
                        gponame += " [Enforced]";
                    }
                    else
                    {
                        if (lowerOUBlocking)
                        {
                            gponame += " [X Not Applied]";
                        }
                    }
                    Console.Write("      {0} - {1}  \n", gpoAttr.GPOID, gponame);
                }
                Console.WriteLine();
            }
            Console.WriteLine();
        }





        public static void PrintSingleAttribute(List<string> myList, string banner)
        {
            PrintGreen(string.Format("\n[-] {0}:\n", banner));

            foreach (string attr in myList)
            {
                Console.WriteLine("    * {0}", attr);
            }

        }






        public static void PrintDirectoryAttrDict(Dictionary<string,DirectoryAttribute> myDict, string banner)
        {
            PrintGreen(string.Format("\n[-] {0}:\n", banner));

            if (myDict == null) { return; }

            foreach (var obj in myDict)
            {
                Console.WriteLine("    * {0}", obj.Key);


                if (obj.Value[0] is string)
                {
                    for (int i = 0; i < obj.Value.Count; i++)
                    {
                        Console.WriteLine("      - {0}", obj.Value[i]);
                    }
                }
                else if (obj.Value[0] is byte[])
                {
                    //Resolve Security Descriptor
                    //From The .Net Developer Guide to Directory Services Programming Listing 8.2. Listing the DACL

                    for (int i = 0; i < obj.Value.Count; i++)
                    {
                        ActiveDirectorySecurity ads = new ActiveDirectorySecurity();

                        ads.SetSecurityDescriptorBinaryForm((byte[])obj.Value[i]);

                        var rules = ads.GetAccessRules(true, true, typeof(NTAccount));

                        foreach (ActiveDirectoryAccessRule rule in rules)
                        {
                            string name = rule.IdentityReference.ToString();

                            if (name.ToUpper().Contains("S-1-5")) { name = ConvertSIDToName(name); }

                            Console.WriteLine("      - {0} ([ControlType: {1}] Rights: {2})",
                                name,
                                rule.AccessControlType.ToString(),
                                rule.ActiveDirectoryRights.ToString());
                        }
                    }
                }
                Console.WriteLine();
            }

        }


       

        public static void PrintGPPPass(List<GPP> myGPP, bool inSYSVOL = true)
        {
            string banner = inSYSVOL ? "SYSVOL" : "Cache";

            PrintGreen(string.Format("\n[-] Group Policy Preference Passwords in {0}:\n", banner));

            if (myGPP == null) { return; }

            foreach (var gpp in myGPP)
            {
                Console.WriteLine("      * {0}", gpp.Path);

                foreach (var p in typeof(GPP).GetFields())
                {
                    if (p.Name != "Path")
                    {
                        Console.WriteLine("        {0, -22}, {1}", p.Name, p.GetValue(gpp));
                    }
                        
                }
                Console.WriteLine();
            }
        }





        public static void PrintACLs(List<ACLs> myACL, string banner)
        {

            PrintGreen(string.Format("\n[-] {0}:\n", banner));

            if (myACL == null) { return; }

            foreach (var acl in myACL)
            {
                Console.WriteLine("    * {0}", acl.ObjectDN);

                foreach (var p in typeof(ACLs).GetFields())
                {
                    if (p.Name != "ObjectDN")
                    {
                        Console.WriteLine("      {0, -22}  {1}", p.Name, p.GetValue(acl));
                    }
                }
                Console.WriteLine();
            }
        }



        public static void PrintDCSync(Dictionary<string, int> dcSyncList)
        {

            PrintGreen(string.Format("\n[-] Unusual DCSync Accounts:\n"));
            if (dcSyncList == null) { return; }
            foreach (var user in dcSyncList)
            {
                if (user.Value == 3)
                {
                    Console.WriteLine("    * {0}", user.Key);
                }
            }
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

    }
}
