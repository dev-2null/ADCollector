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



        public static void PrintKerberosPolicy()
        {
            PrintGreen("\n[-] Kerberos Policy & System Access:\n");

            try
            {
                var policies = Utilities.GetDomainPolicy();

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
                using (var entry = GetSingleDirectoryEntry(rootDN))
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
                        if (GPOs.ContainsKey(match.Value))
                        {
                            Console.WriteLine("     - {0}", GPOs[match.Value]);
                            Console.WriteLine("       {0}", match.Value);
                            Console.WriteLine();
                        }
                        else
                        {
                            Console.WriteLine("     - [X: Probably No Permission to View]");
                            Console.WriteLine("       {0}", match.Value);
                            Console.WriteLine();
                        }
                        
                    }
                }
            }
            catch (Exception e) {PrintYellow("[x] ERROR: " + e.Message); }
            
        }



        public static void PrintNestedGroupMem(List<string> groupList, string guser, string customUser = null)
        {
 
            if (guser == null) { return; }

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




        public static void PrintDC(List<SearchResultEntry> dcList, string banner)
        {
            PrintGreen(string.Format("\n[-] {0}:\n", banner));

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
        }





        public static void PrintSingleAttribute(List<string> myList, string banner)
        {
            PrintGreen(string.Format("\n[-] {0}:\n", banner));

            foreach (string attr in myList)
            {
                Console.WriteLine("    * {0}", attr);
            }
        }


        public static void PrintSingleEntryAttribute(PropertyValueCollection entryProperty, string banner)
        {
            PrintGreen(string.Format("\n[-] {0}:\n", banner));

            foreach (string attr in entryProperty)
            {
                Console.WriteLine("    * {0}", attr);
            }
        }


        public static void PrintDirectoryAttrsDict(Dictionary<string, Dictionary<string, DirectoryAttribute>> myDict, string banner)
        {
            if (banner != null) { PrintGreen(string.Format("\n[-] {0}:\n", banner)); }

            if (myDict == null) { return; }

            foreach (var obj in myDict)
            {
                Console.WriteLine("    * {0}", obj.Key);

                foreach(var attr in obj.Value)
                {
                    foreach (var secDescription in Utilities.ResolveSecurityDescriptors(attr.Value))
                    {
                        Console.WriteLine("      - {0, -20}  {1}", attr.Key+":", secDescription);
                    }
                }

                Console.WriteLine();
            }

        }



        public static void PrintGPPPass(List<GPP> myGPP, bool inSYSVOL = true)
        {
            string banner = inSYSVOL ? "SYSVOL" : "Cache";

            PrintGreen(string.Format("\n[-] Group Policy Preference Passwords in {0}:\n", banner));

            if (myGPP == null|| myGPP.Count == 0) { return; }

            foreach (var gpp in myGPP)
            {
                Console.WriteLine("      * {0}", gpp.Path);

                foreach (var p in typeof(GPP).GetFields())
                {
                    if (p.Name != "Path")
                    {
                        Console.WriteLine("        {0, -22}  {1}", p.Name, p.GetValue(gpp));
                    }
                        
                }
                Console.WriteLine();
            }
        }





        public static void PrintACLs(List<ACLs> myACL, string banner)
        {

            PrintGreen(string.Format("\n[-] {0}:\n", banner));

            if (myACL == null || myACL.Count == 0) { return; }
            var targetEntry = GetSingleDirectoryEntry(myACL[0].ObjectDN);
            var targetName = targetEntry.Properties.Contains("displayName") ? targetEntry.Properties["displayName"][0].ToString() : targetEntry.Properties["name"][0].ToString();

            
            Console.WriteLine("    * {0}", targetName);
            Console.WriteLine("      {0}", myACL[0].ObjectDN);
            Console.WriteLine("      Interesting DACL:");
            foreach (var acl in myACL)
            {
                Console.WriteLine("      {0}{1}", acl.IdentityReference + " - ", acl.ActiveDirectoryRights.Replace("ExtendedRight", acl.ObjectType));
            }
        }


        public static void PrintACLs(List<List<ACLs>> myACL)
        {

            PrintGreen(string.Format("\n[-] ACL Scan Results:\n"));

            if (myACL == null || myACL.Count == 0) { return; }
            foreach(var aclList in myACL)
            {
                var targetEntry = GetSingleDirectoryEntry(aclList[0].ObjectDN);
                var targetName = targetEntry.Properties.Contains("displayName") ? targetEntry.Properties["displayName"][0].ToString() : targetEntry.Properties["name"][0].ToString();
                Console.WriteLine("    * {0}", targetName);
                Console.WriteLine("      {0}", aclList[0].ObjectDN);
                Console.WriteLine("      Interesting DACL:");
                foreach (var acl in aclList)
                {
                    Console.WriteLine("      {0}{1}", acl.IdentityReference + " - ", acl.ActiveDirectoryRights.Replace("ExtendedRight", acl.ObjectType));
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
        }


        public static void PrintRestrictedGroups(List<RestictedGroups> RestrictedGroups)
        {
            PrintGreen(string.Format("\n[-] Restricted Groups:\n"));
            if (RestrictedGroups == null || RestrictedGroups.Count == 0) { return; }
            foreach (var rGroup in RestrictedGroups)
            {
                Console.WriteLine("\n    * GPO:           {0} {1}", rGroup.GPOName, rGroup.GPOID);
                Console.WriteLine("      OU:            {0}", rGroup.OUDN);
                foreach (var gMembership in rGroup.GroupMembership)
                {
                    Console.WriteLine("      Group:         {0}", gMembership.Key.Split('.')[0]);
                    foreach (var membership in gMembership.Value)
                    {
                        Console.WriteLine("      {0}:       {1}", membership.Key, membership.Value);

                    }
                    
                }
                
            }

        }


        public static void PrintADCS(List<ADCS> certsrvs)
        {
            PrintGreen(string.Format("\n[-] Certificate Services:\n"));
            if (certsrvs == null || certsrvs.Count== 0) { return; }
            foreach(var certsrv in certsrvs)
            {
                Console.WriteLine("    * CA Name:                 {0}", certsrv.CAName);
                Console.WriteLine("      DNSHostName:             {0}", certsrv.dnsHostName);
                Console.WriteLine("      WhenCreated:             {0}", certsrv.whenCreated);
                Console.WriteLine("      Flags:                   {0}", certsrv.flags);
                Console.WriteLine("      Enrollment Servers:      {0}", certsrv.enrollServers);
                Console.WriteLine("      Certificate Templates:   {0}", string.Join(",",certsrv.certTemplates));
                Console.WriteLine("      Enrollment Endpoints:    {0}", string.Join(",", certsrv.enrollmentEndpoints));
                Console.WriteLine("      Supplied SAN Enabled:    {0}", certsrv.allowUserSuppliedSAN.ToString().ToUpper());
                Console.WriteLine("      Owner:                   {0}", certsrv.owner);
                Console.WriteLine("      DACL:");
                if (certsrv.securityDescriptors != null && certsrv.securityDescriptors.Count != 0)
                {
                    foreach (var acl in certsrv.securityDescriptors)
                    {
                        Console.WriteLine("                               {0}{1}", acl.IdentityReference + " - ", acl.ActiveDirectoryRights.Replace("ExtendedRight", acl.ObjectType));
                    }
                }
 
                foreach(var cert in certsrv.caCertificates)
                {
                    Console.WriteLine("      Cert SubjectName:        {0}", cert.SubjectName.Name);
                    Console.WriteLine("      Cert Thumbprint:         {0}", cert.Thumbprint);
                    Console.WriteLine("      Cert Start Date:         {0}", cert.NotBefore);
                    Console.WriteLine("      Cert End Date:           {0}", cert.NotAfter);
                }
                Console.WriteLine();
            }
        }




        public static void PrintCertTemplates(List<CertificateTemplates> certTemplates)
        {
            PrintGreen(string.Format("\n[-] Interesting Certificate Templates:\n"));
            if (certTemplates == null || certTemplates.Count == 0) { return; }

            
            foreach (var template in certTemplates)
            {
                if (template.isPublished)
                {
                    Console.WriteLine("    * CertTemplate:            {0}", template.templateDisplayName);
                    Console.WriteLine("      CA Name:                 {0}", template.publishedBy);
                    Console.WriteLine("      CN:                      {0}", template.templateCN);
                    Console.WriteLine("      Enrollment Flag:         {0}", template.enrollFlag);
                    Console.WriteLine("      Cert Name Flag:          {0}", template.certNameFlag);
                    Console.WriteLine("      Extended Key Usage:      {0}", string.Join(",", template.extendedKeyUsage));
                    Console.WriteLine("      RA Signatures:           {0}", template.raSigature);
                    Console.WriteLine("      Owner:                   {0}", template.owner);
                    Console.WriteLine("      DACL:");
                    if (template.securityDescriptors != null && template.securityDescriptors.Count != 0)
                    {
                        foreach (var acl in template.securityDescriptors)
                        {
                            Console.WriteLine("                               {0}{1}", acl.IdentityReference + " - ", acl.ActiveDirectoryRights.Replace("ExtendedRight", acl.ObjectType));
                        }
                    }
                    Console.WriteLine();
                } 
            }
            foreach(var template in certTemplates)
            {
                if (!template.isPublished)
                {
                    Console.WriteLine("    * The Certificate Template [{0}] is vulnerable but it is not published by any CA ", template.templateDisplayName);
                    Console.WriteLine("      Interesting DACL:");
                    if (template.securityDescriptors != null && template.securityDescriptors.Count != 0)
                    {
                        foreach (var acl in template.securityDescriptors)
                        {
                            Console.WriteLine("                               {0}{1}", acl.IdentityReference + " - ", acl.ActiveDirectoryRights.Replace("ExtendedRight", acl.ObjectType));
                        }
                    }
                    Console.WriteLine();
                }
                
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
            Console.WriteLine("   v2.1.1  by dev2null\r\n");
        }

    }
}
