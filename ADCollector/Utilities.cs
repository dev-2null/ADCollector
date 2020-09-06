using System;
using System.Collections.Generic;
using IniParser;
using IniParser.Model;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using static ADCollector.Collector;
using static ADCollector.Natives;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Xml;
using System.IO;
using System.Linq;

namespace ADCollector
{
    public class Utilities
    {


        public static List<SearchResultEntry> GetDC(bool rodc = false)
        {
            List<SearchResultEntry> dcList = new List<SearchResultEntry>();

            var dcFilter =  rodc ? @"(primaryGroupID=521)" : @"(primaryGroupID=516)";

            string[] dcAttrs = { "cn", "name", "dNSHostName", "logonCount", "operatingsystem", "operatingsystemversion", "whenCreated", "whenChanged", "managedBy", "dnsRecord"};

            foreach(var result in GetResponses(rootDn, dcFilter, SearchScope.Subtree, dcAttrs, false))
            {
                dcList.Add(result);
            }
            return dcList;
        }






        //Kerberos policy
        //reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0fce5b92-bcc1-4b96-9c2b-56397c3f144f
        public static Dictionary<string, string> GetDomainPolicy(string domainName)
        {
            Dictionary<string, string> policies = new Dictionary<string, string>();

            var parser = new FileIniDataParser();

            try
            {
                string gptPath = @"\\" + domainName + @"\SYSVOL\" + domainName + @"\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf";

                IniData data = parser.ReadFile(gptPath);

                string[] kPolicies = { "MaxServiceAge", "MaxTicketAge", "MaxRenewAge", "MaxClockSkew", "TicketValidateClient" };

                foreach (var policy in kPolicies)
                {
                    policies.Add(policy, data["Kerberos Policy"][policy]);
                }

                string[] sAccess = { "MinimumPasswordAge", "MaximumPasswordAge", "MinimumPasswordLength", "PasswordComplexity", "PasswordHistorySize" };

                foreach (var access in sAccess)
                {
                    policies.Add(access, data["System Access"][access]);
                }

                string[] lockAccess = { "LockoutBadCount", "LockoutDuration", "ResetLockoutCount" };
                if (!string.IsNullOrEmpty(data["System Access"]["LockoutBadCount"]))
                {
                    foreach (var access in lockAccess)
                    {
                        policies.Add(access, data["System Access"][access]);
                    }
                }

                return policies;
            }
            catch (Exception e)
            {
                Helper.PrintYellow(string.Format("[x] ERROR: {0}\n", e.Message));
                return null;
            }
        }




        public static List<string> GetNestedGroupMem(out string guser, bool onComputer =  false, string customUser = null)
        {
            List<string> SIDList = new List<string>();

            string userDn = GetDN(onComputer, out string getdnuser, customUser);

            if (userDn == null)
            {
                guser = null;
            }
            else
            {
                guser = getdnuser.ToUpper();
            }
            

            if (!string.IsNullOrEmpty(userDn))
            {
                try
                {
                    using (var userEntry = GetSingleEntry(userDn))
                    {
                        //https://www.morgantechspace.com/2015/08/active-directory-tokengroups-vs-memberof.html
                        //Use RefreshCach to get the constructed attribute tokenGroups.
                        userEntry.RefreshCache(new string[] { "tokenGroups" });

                        foreach (byte[] sid in userEntry.Properties["tokenGroups"])
                        {
                            string groupSID = new SecurityIdentifier(sid, 0).ToString();

                            SIDList.Add(groupSID.ToUpper());
                        }
                    }

                    //NT AUTHORITY\Authenticated Users
                    SIDList.Add("S-1-5-11");
                    //NT AUTHORITY\This Organization
                    SIDList.Add("S-1-5-15");
                }
                catch(Exception e)
                {
                    Console.WriteLine("[X] ERROR: {0}", e.Message);
                }
                
            }

            return SIDList;
        }











        public static Dictionary<string, string> GetWMIPolicies()
        {

            Dictionary<string, string> wmiPolicies = new Dictionary<string, string>();

            string wmiDn = "CN=SOM,CN=WMIPolicy,CN=System," + rootDn;

            string wmiFilter = @"(objectClass=msWMI-Som)";

            string[] wmiAttrs = { "msWMI-Name", "msWMI-ID" };

            try
            {
                foreach (var entry in GetResponses(wmiDn, wmiFilter, SearchScope.OneLevel, wmiAttrs, false))
                {
                    wmiPolicies.Add(entry.Attributes["msWMI-ID"][0].ToString().ToUpper(), entry.Attributes["msWMI-Name"][0].ToString());
                }
                return wmiPolicies;
            }
            catch (Exception e)
            {
                Helper.PrintYellow("[x] ERROR: " + e.Message);
                return null;
            }
           
        }





        public static Dictionary<string, string> GetGPO()
        {
            var WMIPolicies = GetWMIPolicies();

            Regex filterRx = new Regex(@";(\{.+?\});", RegexOptions.Compiled);

            Dictionary<string, string> groupPolicies = new Dictionary<string, string>();

            string gpoDn = "CN =Policies,CN=System," + rootDn;//"CN=System," + rootDn;

            string gpoFilter = @"(objectCategory=groupPolicyContainer)";

            string[] gpoAttrs = { "displayName", "cn", "gPCWQLFilter", "nTSecurityDescriptor" };

            //string extrightsDn = "CN=Extended-Rights,CN=Configuration," + forestDn;

            try
            {
                foreach (var entry in GetResponses(gpoDn, gpoFilter, SearchScope.OneLevel, gpoAttrs, false))
                {
                    string dn = entry.Attributes["cn"][0].ToString().ToUpper();

                    string displayname = entry.Attributes["displayName"][0].ToString().ToUpper();

                    //WMI Filtering
                    if (entry.Attributes.Contains("gPCWQLFilter"))
                    {
                        string filterAttr = entry.Attributes["gPCWQLFilter"][0].ToString();

                        Match filterM = filterRx.Match(filterAttr);

                        string filter = filterM.Groups[1].ToString();

                        string wmiName = WMIPolicies[filter];

                        displayname += "   [* EvaluateWMIPolicy: " + wmiName + " - " + filter + "]";
                    }

                    groupPolicies.Add(dn, displayname);
                }
                return groupPolicies;
            }
            catch (Exception e)
            {
                Helper.PrintYellow("[x] ERROR: " + e.Message);
                return null;
            }
            
        }




        




        //Retrieve IP from LDAP dnsRecord only
        public static Dictionary<string, Dictionary<string, string>> GetDNS(bool searchForest = false)
        {
            Dictionary<string, Dictionary<string, string>> dnsDict = new Dictionary<string, Dictionary<string, string>>();

            //domain dns Dn
            string dDnsDn = "DC=DomainDnsZones," + rootDn;//not searching from "CN=MicrosoftDNS,DC=DomainDnsZones,";

            //forest dns Dn
            string fDnsDn = "DC=ForestDnsZones," + forestDn;

            //Find DNS Zones
            string queryZones = @"(&(objectClass=dnsZone)(!(DC=*arpa))(!(DC=RootDNSServers)))";

            string[] dnsZoneAttrs = { "name" };

            var dnsZoneSearchResult = searchForest ?
                GetResponses(fDnsDn, queryZones, SearchScope.Subtree, dnsZoneAttrs, false) :
                GetResponses(dDnsDn, queryZones, SearchScope.Subtree, dnsZoneAttrs, false);

            //excluding objects that have been removed
            string queryRecord = @"(&(objectClass=*)(!(DC=@))(!(DC=*DnsZones))(!(DC=*arpa))(!(DC=_*))(!dNSTombstoned=TRUE))";

            string[] dnsAttrs = { "dnsRecord"};

            byte[] dnsByte = null;
            string ip = null;
            string hostname = null;

            foreach (var dnsZone in dnsZoneSearchResult)
            {
                Dictionary<string, string> dnsRecordDict = new Dictionary<string, string>();

                var dnsResponse = GetResponses(dnsZone.DistinguishedName, queryRecord, SearchScope.OneLevel, dnsAttrs, false);

                foreach (var dnsResult in dnsResponse)
                {
                    //If have permission to view the record
                    if (dnsResult.Attributes.Contains("dnsRecord"))
                    {
                        dnsByte = ((byte[])dnsResult.Attributes["dnsRecord"][0]);

                        ip = Helper.ResolveDNSRecord(dnsByte);

                        hostname = dnsResult.DistinguishedName;

                        if (!dnsRecordDict.ContainsKey(hostname.ToUpper()))
                        {
                            dnsRecordDict.Add(hostname.ToUpper(), ip);
                        }
                    }
                }
                if (!dnsDict.ContainsKey(dnsZone.DistinguishedName.ToUpper()))
                {
                    dnsDict.Add(dnsZone.DistinguishedName.ToUpper(), dnsRecordDict);
                }
            }
            return dnsDict;
        }






        //Retrieve Single dnsRecord with a hostname
        public static string GetSingleDNSRecord(string hostname, bool searchForest = true)
        {
            //domain dns Dn
            string dDnsDn = "DC=DomainDnsZones," + rootDn;//not searching from "CN=MicrosoftDNS,DC=DomainDnsZones,";

            //forest dns Dn
            string fDnsDn = "DC=ForestDnsZones," + forestDn;

            //Find DNS Zones
            string queryZones = @"(&(objectClass=dnsZone)(!(DC=*arpa))(!(DC=RootDNSServers)))";

            string[] dnsZoneAttrs = { "name" };

            var dnsZoneSearchResult = searchForest ?
                GetResponses(fDnsDn, queryZones, SearchScope.Subtree, dnsZoneAttrs, false) :
                GetResponses(dDnsDn, queryZones, SearchScope.Subtree, dnsZoneAttrs, false);


            string queryRecord = @"(&(objectClass=*)(!(DC=@))(!(DC=*DnsZones))(!(DC=*arpa))(!(DC=_*))(name=" + hostname+ "))";

            string[] dnsAttrs = { "dnsRecord", "name" };

            foreach (var dnsZone in dnsZoneSearchResult)
            {
                var hostResult = GetSingleResponse(dnsZone.DistinguishedName, queryRecord, SearchScope.OneLevel, dnsAttrs, false);

                if (hostResult == null) { continue; }

                if (hostResult.Attributes.Contains("dnsRecord"))
                {
                    string ip = Helper.ResolveDNSRecord(((byte[])hostResult.Attributes["dnsRecord"][0]));

                    return ip;
                }
                
            }
            return null;
        }






        public static List<SearchResultEntry> GetTDO(string rootDN)
        {
            List<SearchResultEntry> tdoList = new List<SearchResultEntry>();

            var trustAccFilter = @"(objectCategory=TrustedDomain)";

            string[] trustAccAttrs = { "cn", "securityidentifier", "trustType" };

            string TDOdomainDn = "CN=System," + rootDN;

            foreach (var result in GetResponses(TDOdomainDn, trustAccFilter, SearchScope.Subtree, trustAccAttrs, false))
            {
                tdoList.Add(result);
            }

            return tdoList;
        }



        //public static List<Trust> GetTrusts(List<SearchResultEntry> tdoList)
        //{
        //    List<Trust> trustList = new List<Trust>();

        //    foreach (var tdo in tdoList)
        //    {

        //        var trustDirection = (TrustDirection)int.Parse(tdo.Attributes["trustdirection"][0].ToString());
        //        var trustAttributes = (TrustAttributes)int.Parse(tdo.Attributes["trustattributes"][0].ToString());
        //        var transitive = (trustAttributes & TrustAttributes.NonTransitive) == 0;
        //        var targetName = tdo.Attributes["cn"][0].ToString().ToUpper();
        //        var flatName = tdo.Attributes["flatName"][0].ToString().ToUpper();
        //        var sidFiltering = trustAttributes.HasFlag(TrustAttributes.FilterSids);// trustAttributes & TrustAttributes.FilterSids) != 0;

        //        var domainSid = (new SecurityIdentifier((byte[])tdo.Attributes["securityidentifier"][0], 0)).ToString();

        //        TrustType trustType;

        //        // parentChild occure only when one of the domain is the forest root
        //        // Check is trusted domain is the current forest root or if trusted domain's parent is current enumerated domain
        //        if (targetName == forestName.ToUpper() || targetName.Contains(domainName.ToUpper()))
        //        {
        //            trustType = TrustType.ParentChild;
        //        }
        //        else if ((trustAttributes & TrustAttributes.WithinForest) != 0)
        //        {
        //            trustType = TrustType.ShortCut;
        //        }
        //        else if ((trustAttributes & TrustAttributes.ForestTransitive) != 0)
        //        {
        //            trustType = TrustType.Forest;
        //        }
        //        //else if ((trustAttributes & TrustAttributes.TreatAsExternal) != 0 ||
        //        //         (trustAttributes & TrustAttributes.CrossOrganization) != 0)
        //        //{
        //        //    trustType = TrustType.External;
        //        //}
        //        else
        //        {
        //            trustType = TrustType.External;
        //        }

        //        trustList.Add(new Trust
        //        {
        //            NetbiosName = flatName,
        //            TargetDomainName = targetName,
        //            DomainSid = domainSid,
        //            IsTransitive = transitive,
        //            TrustDirection = trustDirection,
        //            TrustType = trustType,
        //            FilteringSID = sidFiltering
        //        });
        //    }
        //    return trustList;
        //}



        public static SESSION_INFO_10[] GetNetSessionEnum(string hostname)
        {
            int EntriesRead, TotalEntries, ResumeHandle;

            EntriesRead = TotalEntries = ResumeHandle = 0;

            try
            {
                var result = NetSessionEnum(hostname, null, null, 10, out IntPtr BufferPtr, -1, ref EntriesRead, ref TotalEntries, ref ResumeHandle);

                if (result != 0)
                {
                    return null;
                }
                else
                {
                    var BufferOffset = BufferPtr;

                    var sessResults = new SESSION_INFO_10[EntriesRead];

                    SESSION_INFO_10 sessionInfo10 = new SESSION_INFO_10();

                    for (int i = 0; i < EntriesRead; i++)
                    {
                        sessResults[i] = (SESSION_INFO_10)Marshal.PtrToStructure(BufferOffset, sessionInfo10.GetType());

                        BufferOffset = (IntPtr)(BufferOffset.ToInt64() + Marshal.SizeOf(sessionInfo10));
                    }

                    NetApiBufferFree(BufferPtr);

                    return sessResults;
                }
            }
            catch (Exception e)
            {
                Helper.PrintYellow("[x] ERROR:" + e.Message);

                return null;
            }
            
        }





        public static WKSTA_USER_INFO_1[] GetNetWkstaUserEnum(string hostname)
        {
            int EntriesRead, TotalEntries, ResumeHandle;

            EntriesRead = TotalEntries = ResumeHandle = 0;

            try
            {
                var result = NetWkstaUserEnum(hostname, 1, out IntPtr BufferPtr, -1, out EntriesRead, out TotalEntries, ref ResumeHandle);

                if (result != 0)
                {
                    return null;
                }
                else
                {
                    var BufferOffset = BufferPtr;

                    var wkResults = new WKSTA_USER_INFO_1[EntriesRead];

                    WKSTA_USER_INFO_1 userInfo1 = new WKSTA_USER_INFO_1();


                    for (int i = 0; i < EntriesRead; i++)
                    {
                        wkResults[i] = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(BufferOffset, userInfo1.GetType());

                        BufferOffset = (IntPtr)(BufferOffset.ToInt64() + Marshal.SizeOf(userInfo1));
                    }

                    NetApiBufferFree(BufferPtr);

                    return wkResults;
                }
            }
            catch (Exception e)
            {
                Helper.PrintYellow("[x] ERROR:" + e.Message);

                return null;
            }

        }





        public static LOCALGROUP_MEMBERS_INFO_2[] GetNetLocalGroupGetMembers(string hostname, string localgroup)
        {
            int EntriesRead, TotalEntries;

            IntPtr ResumeHandle = IntPtr.Zero;

            

            try
            {
                var result = NetLocalGroupGetMembers(hostname, localgroup, 2, out IntPtr BufferPtr, -1, out EntriesRead, out TotalEntries, ResumeHandle);

                if (EntriesRead > 0)
                {
                    var BufferOffset = BufferPtr;

                    var Results = new LOCALGROUP_MEMBERS_INFO_2[EntriesRead];

                    LOCALGROUP_MEMBERS_INFO_2 groupInfo = new LOCALGROUP_MEMBERS_INFO_2();

                    for (int i = 0; i < EntriesRead; i++)
                    {
                        Results[i] = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(BufferOffset, groupInfo.GetType());

                        BufferOffset = (IntPtr)(BufferOffset.ToInt64() + Marshal.SizeOf(groupInfo));
                    }

                    NetApiBufferFree(BufferPtr);

                    return Results;
                }
                else
                {
                    return null;
                }
                
            }
            catch (Exception e)
            {
                Helper.PrintYellow("[x] ERROR:" + e.Message);

                return null;
            }

        }




        public static DS_DOMAIN_TRUSTS[] GetDsEnumerateDomainTrusts(string domName)
        {
            uint domainCount = 0;

            IntPtr BufferPtr = new IntPtr();

            try
            {
                var result = DsEnumerateDomainTrusts(domName, 63, out BufferPtr, out domainCount);

                if ((domainCount > 0) && (result == 0))
                {

                    var BufferOffset = BufferPtr;
                    var trustResults = new DS_DOMAIN_TRUSTS[domainCount];

                    for (int i = 0; i < domainCount; i++)
                    {
                        trustResults[i] = (DS_DOMAIN_TRUSTS)Marshal.PtrToStructure(BufferOffset, typeof(DS_DOMAIN_TRUSTS));

                        BufferOffset = (IntPtr)(BufferOffset.ToInt64() + (long)Marshal.SizeOf(typeof(DS_DOMAIN_TRUSTS)));
                    }

                    NetApiBufferFree(BufferPtr);

                    return trustResults;
                }
                return null;
            }
            catch (Exception e)
            {
                Helper.PrintYellow("[x] ERROR:" + e.Message);

                return null;
            }
        }






        public static string GetMySite(string computerName)
        {
            IntPtr pBuffer;

            uint result = DsGetSiteName(computerName, out pBuffer);

            if (result == 0)
            {
                string mySiteName = Marshal.PtrToStringAuto(pBuffer);

                NetApiBufferFree(pBuffer);

                return mySiteName;
            }

            return null;
        }










        public static List<Trust> TrustEnum(DS_DOMAIN_TRUSTS[] trustResults)
        {

            if (trustResults == null) { return null; }

            List<Trust> trustList = new List<Trust>();

            DS_DOMAIN_TRUSTS currentDomain = new DS_DOMAIN_TRUSTS();

            foreach (var domain in trustResults)
            {
                if (domain.DnsDomainName.ToUpper() == domainName.ToUpper())
                {
                    currentDomain = domain;
                    break;
                }
            }

            foreach (var trust in trustResults)
            {
                var dnsDomainName = trust.DnsDomainName;

                if (dnsDomainName.ToUpper() == domainName.ToUpper()) { continue; }

                var trustAttributes = (TrustAttributes)trust.TrustAttributes;
                var trustFlags = (TrustFlags)trust.Flags;
                var netbiosName = trust.NetbiosDomainName;
                //var domainSid = (new SecurityIdentifier(trust.DomainSid)).ToString();
                bool sidFiltering = trustAttributes.HasFlag(TrustAttributes.FilterSids) ? true : false;
                bool isTransitive = trustAttributes.HasFlag(TrustAttributes.NonTransitive) ? false : true;

                TrustDirection trustDirection;

                if (trustFlags.HasFlag(TrustFlags.DirectInBound) && trustFlags.HasFlag(TrustFlags.DirectOutBound))
                {
                    trustDirection = TrustDirection.BiDirectional;

                }
                else if (trustFlags.HasFlag(TrustFlags.DirectInBound))
                {
                    trustDirection = TrustDirection.InBound;
                }
                else if (trustFlags.HasFlag(TrustFlags.DirectOutBound))
                {
                    trustDirection = TrustDirection.OutBound;
                }
                else
                {
                    trustDirection = TrustDirection.Disable;
                }

                TrustType trustType;

                //If the target domain is the current tree root or if target domain is a child domain of the current domain
                if ((trustFlags.HasFlag(TrustFlags.TreeRoot) &&
                    trustFlags.HasFlag(TrustFlags.InForest) &&
                    (currentDomain.DnsDomainName.ToUpper().Contains(dnsDomainName.ToUpper()))) ||
                    (trustResults[trust.ParentIndex].DnsDomainName.ToUpper() == domainName.ToUpper()))
                {
                    trustType = TrustType.ParentChild;
                }
                else if (trustFlags.HasFlag(TrustFlags.TreeRoot) && trustFlags.HasFlag(TrustFlags.InForest))
                {
                    trustType = TrustType.TreeRoot;
                }
                else if (trustFlags.HasFlag(TrustFlags.InForest))
                {
                    trustType = TrustType.ShortCut;
                }
                else if (trustAttributes.HasFlag(TrustAttributes.ForestTransitive))
                {
                    trustType = TrustType.Forest;
                }
                else
                {
                    trustType = TrustType.External;
                }


                trustList.Add(new Trust
                {
                    SourceDomainName = domainName,
                    NetbiosName = netbiosName,
                    TargetDomainName = dnsDomainName,
                    //DomainSid = domainSid,
                    IsTransitive = isTransitive,
                    TrustDirection = trustDirection,
                    TrustType = trustType,
                    FilteringSID = sidFiltering
                });
            }
            return trustList;
        }






        public static List<string> GetMyOUs(string uname, string dn, bool onComputer = false)
        {
            List<string> ouList = new List<string>();
            try
            {
                dn = dn.ToUpper();

                while (dn.Contains(",OU"))
                {
                    if (dn.Contains(("CN=" + uname + ",")))
                    {
                        dn = dn.Replace(("CN=" + uname + ",").ToUpper(), string.Empty);
                    }
                    else
                    {
                        dn = dn.Substring(dn.IndexOf(",OU") + 1);
                    }
                    ouList.Add(dn);
                }
                //add Domain DN
                dn = dn.Substring(dn.IndexOf(",DC=") + 1);
                ouList.Add(dn);

                if (onComputer)
                {
                    //add Site DN
                    string site = GetMySite(uname);
                    if (site == null) { return null; }

                    string siteDn = "CN=" + site + ",CN=Sites,CN=Configuration," + forestDn;

                    ouList.Add(siteDn);
                }


                return ouList;

            }catch(Exception e)
            {
                Console.WriteLine("[X] ERROR: {0}", e.Message);
                return null;
            }
            
        }
        



        //1. Iterate each OU/Domain/Site: "gplink" & "gpoptions"
        //2. Find GPOs that are linked to each OU/Domain/Site
        //3. Iterate each GPO to find out if they have WMI filters: "gPCWQLFilter"
        //4. Find the WMI policy and check if the policy is filtered out: "msWMI-Parm2"
        public static List<AppliedGPOs> GetAppliedGPOs(List<string> ouList, Dictionary<string, string> GPOs, bool onComputer = false, string customUser = null)
        {
            if (ouList == null) { return null; }
            var SIDList = GetNestedGroupMem(out _, onComputer, customUser);

            List<AppliedGPOs> AppliedGPOsList = new List<AppliedGPOs>();

            Regex gpoRx = new Regex(@"=(\{.+?\}),", RegexOptions.Compiled);

            Regex gpoptionRx = new Regex(@";(\d)", RegexOptions.Compiled);

            
            foreach (var ou in ouList)
            {
                bool isBlocking = false;
                bool isEnforced = false;
                bool isDenied = true;
                string gPOID = null;
                string gPOName = null;

                var ouEntry = GetSingleEntry(ou);

                if (ouEntry == null) { return null; }

                var linkedGPOAttr = new GPOAttributes();

                var linkedGPOs = new List<GPOAttributes>();

                //Linked GPOs & Enforcement
                if (ouEntry.Properties.Contains("gplink"))
                {
                    string[] gplinkArrary = Regex.Split(ouEntry.Properties["gplink"][0].ToString(), @"\]\[");

                    foreach (var gplinkString in gplinkArrary)
                    {
                        Match matchGPO = gpoRx.Match(gplinkString);

                        Match matchGpoption = gpoptionRx.Match(gplinkString);

                        gPOID = matchGPO.Groups[1].ToString().ToUpper();

                        //[LDAP://cn={E8D8C72C-3AAB-496C-90CD-C5F44F0AF10C},cn=policies,cn=system,DC=corplab,DC=local;0]
                        //0: Default: The GPO Link is not ignored and is not an enforced GPO.
                        //1: The GPO Link MUST be ignored.
                        //2: The GPO Link is an enforced GPO.
                        isEnforced = int.Parse(matchGpoption.Groups[1].ToString()) == 2;
                        string gpoDn = "CN=" + gPOID + ",CN=Policies,CN=System," + rootDn;
                        gPOName = GPOs[gPOID];
                        //SecurityFiltering: Check if the target GPO applied to the current user
                        isDenied = IsDeniedPolicy(gpoDn, SIDList);

                        if (isDenied)
                        {
                            gPOName += "  [X Denied]";
                        }

                        linkedGPOAttr.GPOID = gPOID;
                        linkedGPOAttr.GPOName = gPOName;
                        linkedGPOAttr.isEnforced = isEnforced;

                        linkedGPOs.Add(linkedGPOAttr);
                    }
                }
                //If a OU blocks inheritance
                if (ouEntry.Properties.Contains("gpOptions"))
                {
                    //OUs that block inheritance will only ignore non-enforecd GPO
                    //OU Attribute: gPOptions=1  Block Inheritance
                    isBlocking = (int)ouEntry.Properties["gpOptions"][0] == 1;
                }


                AppliedGPOsList.Add(new AppliedGPOs
                {
                    LinkedGPOs = linkedGPOs,
                    IsBlocking = isBlocking,
                    OUDn = ou
                });

            }

            return AppliedGPOsList;
        }





        public static bool IsDeniedPolicy(string gpoDn, List<string> SIDList)
        {
            var rules = GetAuthorizationRules(gpoDn);

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                //Security Filtering
                //Apply-Group-Policy: edacfd8f-ffb3-11d1-b41d-00a0c968f939
                if ((rule.ActiveDirectoryRights.ToString().ToLower() == "extendedright") &&
                    (rule.ObjectType.ToString().ToUpper() == "EDACFD8F-FFB3-11D1-B41D-00A0C968F939"))
                {
                    string groupSID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString().ToUpper();

                    //If the target GPO applys to the current user's security groups
                    if (SIDList.Contains(groupSID))
                    {
                        return false;
                    }
                }
            }


            return true;
        }




        internal static string GetDN(bool onComputer, out string name, string customUser = null)
        {
            string uname = customUser;

            if (uname == null)
            {
                if (username == null)
                {
                    uname = onComputer ? Environment.GetEnvironmentVariable("COMPUTERNAME") : Environment.GetEnvironmentVariable("USERNAME");
                }
                else
                {
                    uname = onComputer ? Environment.GetEnvironmentVariable("COMPUTERNAME") :username;
                }
                
            }

            //If running as a machine account
            if (uname.Contains("$"))
            {
                onComputer = true;
            }
            if (onComputer)
            {
                //add $ for the current machine
                uname += "$";
            }

            name = onComputer ? uname.Replace("$", string.Empty) : uname;

            string nFilter = onComputer ?
                @"(&(sAMAccountType=805306369)(sAMAccountName=" + uname + "))" :
                @"(&(sAMAccountType=805306368)(sAMAccountName=" + uname + "))";

            string[] nAttrs = { "distingushiedName" };

            var resultEntry = GetSingleResponse(rootDn, nFilter, SearchScope.Subtree, nAttrs, false);

            if (resultEntry == null) { name = null; return null; }

            return resultEntry.DistinguishedName;

        }




        public static void RunAs(string domain, string username, string password, Action action)
        {
            using (var accessToken = GetUserAccessToken(domain, username, password))
            {
                WindowsIdentity.RunImpersonated(accessToken, action);
            }
        }




        internal static SafeAccessTokenHandle GetUserAccessToken(string domain, string username, string password)
        {
            const int LOGON32_PROVIDER_DEFAULT = 0;
            const int LOGON32_LOGON_NETONLY = 9;

            bool isLogonSuccessful = LogonUser(username, domain, password, LOGON32_LOGON_NETONLY, LOGON32_PROVIDER_DEFAULT, out var safeAccessTokenHandle);
            if (!isLogonSuccessful)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return safeAccessTokenHandle;
        }




        public static List<string> GetGPPXML(string mydir = null)
        {
            string gppPath = mydir ?? "\\\\" + domainName + "\\SYSVOL\\" + domainName + "\\Policies\\";

            var xmlList = new List<string> { "Groups.xml", "Services.xml", "Scheduledtasks.xml", "Datasources.xml", "Printers.xml", "Drives.xml" };

            var files = new List<string>();
            try
            {
                foreach (string file in Directory.GetFiles(gppPath))
                {
                    try
                    {
                        if (xmlList.Any(file.Contains))
                        {
                            files.Add(file);
                        }
                    }
                    catch { }
                }

                foreach (string directory in Directory.GetDirectories(gppPath))
                {
                    try
                    {
                        GetGPPXML(directory);
                    }
                    catch { }
                }
                
            }
            catch { }

            return files;
        }






        public static List<string> GetCachedGPP()
        {
            string allUser = Environment.GetEnvironmentVariable("ALLUSERSPROFILE");

            return allUser.Contains("ProgramData") ? GetGPPXML(allUser) : GetGPPXML(allUser + @"\Application Data");

        }




        //https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
        //Search for groups.xml, scheduledtasks.xml, services.xml, datasources.xml, printers.xml and drives.xml
        //findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
        public static List<GPP> GetGPPPass(List<string> files)
        {
            var GPPPassList = new List<GPP>();

            var gppDict = new Dictionary<string, string>();

            gppDict.Add("Groups.xml", "/Groups/User/Properties");
            gppDict.Add("Services.xml", "/NTServices/NTService/Properties");
            gppDict.Add("Scheduledtasks.xml", "/ScheduledTasks/Task/Properties");
            gppDict.Add("Datasources.xml", "/DataSources/DataSource/Properties");
            gppDict.Add("Printers.xml", "/Printers/SharedPrinter/Properties");
            gppDict.Add("Drives.xml", "/Drives/Drive/Properties");

            XmlDocument doc = new XmlDocument();

            foreach (string path in files)
            {
                try { doc.Load(path); } catch { continue; }

                foreach (var gppXml in gppDict)
                {
                    doc.Load(path);

                    if (doc.InnerXml.Contains("cpassword"))
                    {
                        var nodes = doc.DocumentElement.SelectNodes(gppXml.Value);

                        switch (path.Split('\\').Last())
                        {
                            case "Groups.xml":
                                foreach (XmlNode node in nodes)
                                {
                                    try
                                    {
                                        GPPPassList.Add(new GPP
                                        {
                                            UserName = node.Attributes["userName"].Value,
                                            NewName = node.Attributes["newName"].Value,
                                            CPassword = node.Attributes["cpassword"].Value,
                                            Changed = node.ParentNode.Attributes["changed"].Value,
                                            Path = path
                                        });
                                    }
                                    catch { }
                                }
                                break;

                            case "Services.xml":
                                foreach (XmlNode node in nodes)
                                {
                                    try
                                    {
                                        GPPPassList.Add(new GPP
                                        {
                                            AccountName = node.Attributes["accountName"].Value,
                                            CPassword = node.Attributes["cpassword"].Value,
                                            Changed = node.ParentNode.Attributes["changed"].Value,
                                            Path = path
                                        });
                                    }
                                    catch { }
                                }
                                break;

                            case "Scheduledtasks":
                                foreach (XmlNode node in nodes)
                                {
                                    try
                                    {
                                        GPPPassList.Add(new GPP
                                        {
                                            RunAs = node.Attributes["runAs"].Value,
                                            CPassword = node.Attributes["cpassword"].Value,
                                            Changed = node.ParentNode.Attributes["changed"].Value,
                                            Path = path
                                        });
                                    }
                                    catch { }
                                }
                                break;

                            default:
                                foreach (XmlNode node in nodes)
                                {
                                    try
                                    {
                                        GPPPassList.Add(new GPP
                                        {
                                            UserName = node.Attributes["userName"].Value,
                                            CPassword = node.Attributes["cpassword"].Value,
                                            Changed = node.ParentNode.Attributes["changed"].Value,
                                            Path = path
                                        });
                                    }
                                    catch { }

                                }
                                break;
                        }
                    }
                }
            }
            return GPPPassList;
        }







        public static AuthorizationRuleCollection GetAuthorizationRules(string targetDn)
        {
            try
            {
                using (var aclEntry = GetSingleEntry(targetDn))
                {
                    ActiveDirectorySecurity sec = aclEntry.ObjectSecurity;

                    AuthorizationRuleCollection rules = null;

                    rules = sec.GetAccessRules(true, true, typeof(NTAccount));

                    return rules;
                }

            }
            catch { return null; }
        }




        public static List<ACLs> GetInterestingACLs(List<string> targetDnList,  out Dictionary<string, int> dcSyncList)
        {
            var aclList = new List<ACLs>();

            dcSyncList = new Dictionary<string, int>();

            //Adapted from https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L3746

            Regex rights = new Regex(@"(GenericAll)|(.*Write.*)|(.*Create.*)|(.*Delete.*)", RegexOptions.Compiled);
            //Regex replica = new Regex(@"(.*Replication.*)", RegexOptions.Compiled);

            string[] dcsync = { "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set" };

            foreach (string targetDn in targetDnList)
            {
                var rules = GetAuthorizationRules(targetDn);

                if (rules == null) { dcSyncList = null; return null; }

 
                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    var sid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString();

                    if (int.Parse(sid.Split('-').Last()) > 1000)
                    {
                        //Sometimes the identity reference cannot be resolved
                        string IR = null;
                        try
                        {
                            IR = rule.IdentityReference.ToString();
                            if (IR == rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString())
                            {
                                IR = Helper.ConvertSIDToName(IR);
                            }
                        }
                        catch { }

                        if (rights.IsMatch(rule.ActiveDirectoryRights.ToString()))
                        {
                            aclList.Add(new ACLs
                            {
                                ObjectDN = targetDn,
                                IdentityReference = IR,
                                IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
                                ActiveDirectoryRights = rule.ActiveDirectoryRights.ToString()
                            });
                        }
                        else if (rule.ActiveDirectoryRights.ToString() == "ExtendedRight" && rule.AccessControlType.ToString() == "Allow")
                        {


                            //The ObjectType GUID maps to an extended right registered in the current forest schema, then that specific extended right is granted
                            //Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf

                            string objType = ResolveRightsGuid(rule.ObjectType.ToString());

                            aclList.Add(new ACLs
                            {
                                ObjectDN = targetDn,
                                IdentityReference = IR,
                                IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
                                ActiveDirectoryRights = rule.ActiveDirectoryRights.ToString(),
                                ObjectType = objType
                            });

                            if (dcsync.Contains(objType))
                            {
                                if (dcSyncList.ContainsKey(IR))
                                {
                                    dcSyncList[IR] += 1;
                                }
                                else
                                {
                                    dcSyncList.Add(IR, 1);
                                }
                            }
                        }
                    }


                }
            }

            return aclList;

        }






        public static List<ACLs> GetLAPSViewACLs(List<string> targetDnList)
        {
            var aclList = new List<ACLs>();

            Regex rights = new Regex(@"(.*Read.*)", RegexOptions.Compiled);

            foreach (string targetDn in targetDnList)
            {
                var rules = GetAuthorizationRules(targetDn);

                if (rules == null) { return null; }

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    var sid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString();

                    if (int.Parse(sid.Split('-').Last()) > 1000)
                    {
                        //Sometimes the identity reference cannot be resolved
                        string IR = null;
                        try
                        {
                            IR = rule.IdentityReference.ToString();
                            if (IR == rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString())
                            {
                                IR = Helper.ConvertSIDToName(IR);
                            }
                        }
                        catch { }

                        //FALSE for resolving Schema attribute instead of extended rights
                        string objType =ResolveRightsGuid(rule.ObjectType.ToString(), false);
                        if (rights.IsMatch(rule.ActiveDirectoryRights.ToString())
                            && objType == "ms-Mcs-AdmPwd")
                        {
                            aclList.Add(new ACLs
                            {
                                ObjectDN = targetDn,
                                IdentityReference = IR,
                                IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
                                ActiveDirectoryRights = rule.ActiveDirectoryRights.ToString(),
                                ObjectType = objType
                            });
                        }
                    }
                }
            }

            return aclList;

        }








        public static string ResolveRightsGuid(string rightsGuid, bool isRights = true)
        {
            string partition = isRights ? "CN=Extended-Rights,CN=Configuration," : "CN=Schema,CN=Configuration,";
            //No SPACE near "="
            //From The .Net Developer Guide to Directory Services Programming Searching for Binary Data

            //resolve schema attributes / extended rights
            string searchFilter = isRights ? @"(rightsGuid=" + rightsGuid + @")" :
                @"(schemaIDGUID=" + Helper.BuildFilterOctetString(new Guid(rightsGuid).ToByteArray()) + @")";

            var rightsDn = partition + forestDn;

            var rightsAttrs = new string[] { "cn" };

            var rightsResult = GetSingleResponse(rightsDn, searchFilter, SearchScope.OneLevel, rightsAttrs, false);

            if (rightsResult == null) { return null; }

            return rightsResult.Attributes["cn"][0].ToString();

        }















        public static Dictionary<string, DirectoryAttribute> GetGeneral(string searchDn, string myFilter,  string attribute = null)
        {
            string[] myAttrs = new string[2];

            myAttrs[0] = "sAMAccountName";

            var myDict = new Dictionary<string, DirectoryAttribute>();

            myAttrs[1] = attribute ?? string.Empty;

            var myResults = GetResponses(searchDn, myFilter, SearchScope.Subtree, myAttrs, false);

            if (myResults == null) { return null; }

            foreach (var result in myResults)
            {
                if (attribute == null)
                {
                    myDict.Add(result.DistinguishedName, result.Attributes["sAMAccountName"]);
                }
                else
                {
                    myDict.Add((string)result.Attributes["sAMAccountName"][0], result.Attributes[attribute]);
                }
            }

            return myDict;
        }







        public static List<string> GetSingleAttr(string searchDn, string myFilter, string attribute)
        {

            var myList = new List<string>();

            var myAttrs = new string[] { attribute };

            var myResults = GetResponses(searchDn, myFilter, SearchScope.Subtree, myAttrs, false);

            if (myResults == null) { return null; }

            foreach (var result in myResults)
            {
                myList.Add(result.Attributes[attribute][0].ToString());
                
            }

            return myList;
        }












    }
}
