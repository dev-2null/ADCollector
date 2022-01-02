using CommandLine;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace ADCollector3
{
    public class ADCollector
    {
        BuildSearchString buildSearchString;
        static bool CanConnectSYSVOL;
        public ADCollector()
        {
            Searcher searcher = new Searcher();
            searcher.Init();
            
            GPO.GetAllGPOs();
            buildSearchString = new BuildSearchString();

            Rights.BuildExtendedRightsDict();
            Rights.BuildSchemaDict();

        }


        public void Run()
        {
            GetLDAPBasicInfo(new List<Dictionary<string, List<string>>> { Searcher.BasicLDAPInfo });

            GetTypeObject(typeof(Trust));

            GetLDAP();

            GetNGAGP();

            GetACL();

            GetADCS();

            CanConnectSYSVOL = CollectSYSVOL.CanConnectSYSVOL();

            GetSMB();

            GetGPP();

            GetADIDNS();
        }



        public void GetLDAPBasicInfo(List<Dictionary<string, List<string>>> dl)
        {
            IDisplay displayer = new DisplayDL();
            displayer.DisplayTitle("Basic LDAP Information");
            IResult result = new DLResult { Result = dl };
            displayer.DisplayResult(result);

        }


        public void GetNGAGP(List<string> userList = null)
        {
            if (userList == null || userList.Count == 0 || (userList.Count==1 && userList[0] == null))
            {
                userList = new List<string>
                {
                Environment.GetEnvironmentVariable("USERNAME"),
                Environment.GetEnvironmentVariable("COMPUTERNAME")+"$"
                };
            }
            List<SearchString> nestedGMSearchStringList = buildSearchString.GetNestedGMSearchString(userList);
            List<SearchString> appliedGPOSearchStringList = buildSearchString.GetAppliedGPOSearchString(userList);
            Collect(nestedGMSearchStringList);
            Collect(appliedGPOSearchStringList);
        }


        public void GetLDAP()
        {
            List<SearchString> ldapSearchStringList = buildSearchString.GetLDAPSearchString();
            Collect(ldapSearchStringList);
        }


        public void GetSMB()
        {
            List<SearchString> smbSearchStringList = buildSearchString.GetSMBSearchString();

            foreach (var smbSearchString in smbSearchStringList)
            {
                IDisplay displayer = new DisplayFileObjects();
                displayer.DisplayTitle(smbSearchString.Title);
                if (!CanConnectSYSVOL) { continue; }

                var sysvol = AsyncCollection.GetSYSVOLAsync(smbSearchString).Result;
                
                if (sysvol.Count == 0) { continue; }
                foreach (var file in sysvol)
                {
                    displayer.DisplayResult(file);
                }
            }
        }


        public void GetACL(string targetDn = null)
        {
            IDisplay displayer = new DisplayDACL();
            DACLResult result = new DACLResult();

            if (targetDn == null)
            {
                displayer.DisplayTitle("Interesting ACL on the Domain Object");
                var domainAcl = DACL.GetInterestingACLOnObject(Searcher.LdapInfo.RootDN);
                result.Result = new List<DACL> { domainAcl };
                displayer.DisplayResult(result);

                displayer.DisplayTitle("Interesting ACL on Group Policy Objects");
                var gposDN = GPO.GetAllGPODNList();
                result.Result = AsyncCollection.GetInterestingACLAsync(gposDN).Result;
                displayer.DisplayResult(result);

                displayer.DisplayTitle("LAPS Password View Access");
                result.Result = DACL.GetLAPSACL();
                displayer.DisplayResult(result);
            }
            else
            {
                displayer.DisplayTitle($"DACL on {targetDn.ToUpper()}");
                result.Result = new List<DACL> { DACL.GetACLOnObject(targetDn) };
                displayer.DisplayResult(result);
            }
        }



        public void GetGPP()
        {
            IDisplay displayer = new DisplayFileObjects();
            var gppSearchString = new SMBSearchString
            {
                Title = "Group Policy Preference Passwords",
                FileAttributes = new List<string> { "cpassword" }
            };
            displayer.DisplayTitle(gppSearchString.Title);
            if (!CanConnectSYSVOL) { return; }

            var xmlFileList = AsyncCollection.GetGPPXML().Result;
            gppSearchString.FilePathList = xmlFileList;
            var sysvol = AsyncCollection.GetSYSVOLAsync(gppSearchString).Result;
            
            if (sysvol.Count == 0) { return; }
            foreach (var file in sysvol)
            {
                displayer.DisplayResult(file);
            }

        }


        public static void Collect(string title, List<DACL> dacl)
        {
            IDisplay displayer = new DisplayDACL();
            displayer.DisplayTitle(title);
            IResult result = new DACLResult { Result = dacl };
            displayer.DisplayResult(result);

        }



        public void Collect(List<SearchString> searchStringList)
        {
            ICollector collector = null;
            IDisplay displayer = null;

            if (searchStringList.FirstOrDefault() is LDAPSearchString)
            {
                collector = new CollectWithFilter();
                displayer = new DisplayLDAPObjects();
            }
            else if (searchStringList.FirstOrDefault() is NestedGMSearchString)
            {
                collector = new CollectNestedGroupMembership();
                displayer = new DisplayList();
            }
            else if (searchStringList.FirstOrDefault() is AppliedGPOSearchString)
            {
                collector = new CollectAppliedGPO();
                displayer = new DisplayDD();
            }

            foreach (SearchString searchString in searchStringList)
            {
                displayer.DisplayTitle(searchString.Title);
                IResult result = collector.Collect(searchString);
                displayer.DisplayResult(result);
            }
        }



        public void GetTypeObject(Type t)
        {
            IDisplay displayer = new Display();

            if (t == typeof(Trust))
            {
                displayer.DisplayTitle("Domain Trusts");
                var domainTrust = new Trust();
                var trustResult = NativeMethod.GetDsEnumerateDomainTrusts();
                var domainTrusts = domainTrust.AnalyzeTrust(trustResult);
                DisplayType.DisplayTrust(domainTrusts);
                Console.WriteLine();
            }
        }


        public void GetADCS()
        {
            var displayer = new DisplayADCS();

            displayer.DisplayTitle("Certificate Services");
            ADCS.CertificateServices = AsyncCollection.GetADCSAsync().Result;
            displayer.DisplayResult(ADCS.CertificateServices);


            displayer.DisplayTitle("Interesting Certificate Templates");
            var certicateTemplates = AsyncCollection.GetInterestingCertTemplatesAsync().Result;
            displayer.DisplayResult(certicateTemplates);
        }


        public void GetADIDNS()
        {
            var displayer = new DisplayADIDNS();
            displayer.DisplayTitle("DNS Records in the Domain");
            var domainDNS = ADIDNS.GetDNS(false);
            displayer.DisplayResult(domainDNS);

            displayer.DisplayTitle("DNS Records in the Forest");
            var forestDNS = ADIDNS.GetDNS(true);
            displayer.DisplayResult(forestDNS);
        }


        public static void GetHostSession(string host)
        {
            var displayer = new DisplayNativeMethod();
            displayer.DisplayTitle($"Session Enum on {host}");
            var Results = NativeMethod.GetNetSessionEnum(host);
            displayer.DisplayNetSession(Results);
        }


        public static void GetHostUser(string host)
        {
            var displayer = new DisplayNativeMethod();
            displayer.DisplayTitle($"User Enum on {host}");
            var Results = NativeMethod.GetNetWkstaUserEnum(host);
            displayer.DisplayNetWkstaUserEnum(Results);
        }


        public static void GetHostGroupMember(string host, string group = "Administrators")
        {
            var displayer = new DisplayNativeMethod();
            displayer.DisplayTitle($"Local Group Members Enum on {host} for {group}");
            var Results = NativeMethod.GetNetLocalGroupGetMembers(host, group);
            displayer.DisplayNetLocalGroupGetMembers(Results);
        }


        public void InvokeACLScan(string user)
        {
            if (user == null) { return; }
            var displayer = new DisplayDACL();
            displayer.DisplayTitle($"Interesting ACL for {user.ToUpper()}");
            DACLResult result = new DACLResult();

            var groups = new CollectNestedGroupMembership();
            groups.Collect(new NestedGMSearchString { SAMAccountName = user });
            var groupSIDs = CollectNestedGroupMembership.UserSIDNameDictionary[user.ToUpper()].Keys.ToList();
            result.Result = DACL.ACLScan(user, groupSIDs);

            displayer.DisplayResult(result);
        }
    }

}
