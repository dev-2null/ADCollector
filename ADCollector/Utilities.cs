using System;
using System.Collections.Generic;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using static ADCollector.Collector;
using static ADCollector.Natives;
using static ADCollector.Helper;
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
using System.Text;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ADCollector
{
    public class Utilities
    {


        public static List<SearchResultEntry> GetDC(bool rodc = false)
        {
            List<SearchResultEntry> dcList = new List<SearchResultEntry>();

            var dcFilter =  rodc ? @"(primaryGroupID=521)" : @"(primaryGroupID=516)";

            string[] dcAttrs = { "cn", "name", "dNSHostName", "logonCount", "operatingsystem", "operatingsystemversion", "whenCreated", "whenChanged", "managedBy", "dnsRecord"};

            foreach(var result in GetResultEntries(rootDn, dcFilter, SearchScope.Subtree, dcAttrs, false))
            {
                dcList.Add(result);
            }
            return dcList;
        }






        //Kerberos policy
        //reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0fce5b92-bcc1-4b96-9c2b-56397c3f144f
        public static Dictionary<string, string> GetDomainPolicy()
        {
            Dictionary<string, string> policies = new Dictionary<string, string>();

            //var parser = new FileIniDataParser();
            
            try
            {
                string gptPath = @"\\" + accessDC + @"\SYSVOL\" + domainName + @"\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf";

                var inf = ReadInf(gptPath);

                string[] kPolicies = { "MaxServiceAge", "MaxTicketAge", "MaxRenewAge", "MaxClockSkew", "TicketValidateClient" };

                string[] sAccess = { "MinimumPasswordAge", "MaximumPasswordAge", "MinimumPasswordLength", "PasswordComplexity", "PasswordHistorySize"};

                string[] lockAccess = { "LockoutBadCount", "LockoutDuration", "ResetLockoutCount" };

                foreach (var policy in kPolicies)
                {
                    policies.Add(policy, inf["Kerberos Policy"][policy]);
                }

                foreach (var access in sAccess)
                {
                    policies.Add(access, inf["System Access"][access]);
                }

                foreach (var access in lockAccess)
                {
                    if (inf["System Access"].ContainsKey(access))
                    {
                        policies.Add(access, inf["System Access"][access]);
                    }
                }

                return policies;
            }
            catch
            {
                PrintYellow($"[x] Unable Access SYSVOL on {accessDC}");
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
                if (customUser == "Authenticated Users") { SIDList.Add("S-1-5-11"); return SIDList; }
                return null;
            }
            else
            {
                guser = getdnuser.ToUpper();
            }
            

            try
            {
                using (var userEntry = GetSingleDirectoryEntry(userDn))
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
                SIDList.Add("S-1-5-11");/*
                //NT AUTHORITY\This Organization
                SIDList.Add("S-1-5-15");*/
            }
            catch(Exception e)
            {
                Debug.WriteLine($"[x] Cannot find {customUser}");
                Console.WriteLine("[X] ERROR: {0}", e.Message);
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
                foreach (var entry in GetResultEntries(wmiDn, wmiFilter, SearchScope.OneLevel, wmiAttrs, false))
                {
                    wmiPolicies.Add(entry.Attributes["msWMI-ID"][0].ToString().ToUpper(), entry.Attributes["msWMI-Name"][0].ToString());
                }
                return wmiPolicies;
            }
            catch (Exception e)
            {
                PrintYellow("[x] ERROR: " + e.Message);
                return null;
            }
           
        }





        public static Dictionary<string, string> GetGPO()
        {
            var WMIPolicies = GetWMIPolicies();

            Regex filterRx = new Regex(@";(\{.+?\});", RegexOptions.Compiled);

            Dictionary<string, string> groupPolicies = new Dictionary<string, string>();

            string gporootDn = "CN=Policies,CN=System," + rootDn;//"CN=System," + rootDn;
            string gpoforestDn = "CN=Policies,CN=System," + forestDn;

            string[] gpoDns;
            if (rootDn == forestDn)
            {
                gpoDns = new string[] { gporootDn, gpoforestDn };
            }
            else
            {
                gpoDns = new string[] { gporootDn };
            }

            string gpoFilter = @"(objectCategory=groupPolicyContainer)";

            string[] gpoAttrs = { "displayName", "cn", "gPCWQLFilter", "nTSecurityDescriptor" };

            //string extrightsDn = "CN=Extended-Rights,CN=Configuration," + forestDn;

            try
            {
                foreach(string gpodn in gpoDns)
                {
                    foreach (var entry in GetResultEntries(gpodn, gpoFilter, SearchScope.OneLevel, gpoAttrs, false))
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

                        if (!groupPolicies.ContainsKey(dn)) { groupPolicies.Add(dn, displayname); }
                        
                    }
                }
                return groupPolicies;
            }
            catch (Exception e)
            {
                PrintYellow("[x] ERROR: " + e.Message);
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
                GetResultEntries(fDnsDn, queryZones, SearchScope.Subtree, dnsZoneAttrs, false) :
                GetResultEntries(dDnsDn, queryZones, SearchScope.Subtree, dnsZoneAttrs, false);

            //excluding objects that have been removed
            string queryRecord = @"(&(objectClass=*)(!(DC=@))(!(DC=*DnsZones))(!(DC=*arpa))(!(DC=_*))(!dNSTombstoned=TRUE))";

            string[] dnsAttrs = { "dnsRecord"};

            byte[] dnsByte = null;
            string ip = null;
            string hostname = null;

            foreach (var dnsZone in dnsZoneSearchResult)
            {
                Dictionary<string, string> dnsRecordDict = new Dictionary<string, string>();

                var dnsResponse = GetResultEntries(dnsZone.DistinguishedName, queryRecord, SearchScope.OneLevel, dnsAttrs, false);

                foreach (var dnsResult in dnsResponse)
                {
                    //If have permission to view the record
                    if (dnsResult.Attributes.Contains("dnsRecord"))
                    {
                        dnsByte = ((byte[])dnsResult.Attributes["dnsRecord"][0]);

                        ip = ResolveDNSRecord(dnsByte);

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
                GetResultEntries(fDnsDn, queryZones, SearchScope.Subtree, dnsZoneAttrs, false) :
                GetResultEntries(dDnsDn, queryZones, SearchScope.Subtree, dnsZoneAttrs, false);


            string queryRecord = @"(&(objectClass=*)(!(DC=@))(!(DC=*DnsZones))(!(DC=*arpa))(!(DC=_*))(name=" + hostname+ "))";

            string[] dnsAttrs = { "dnsRecord", "name" };

            foreach (var dnsZone in dnsZoneSearchResult)
            {
                var hostResult = GetSingleResultEntry(dnsZone.DistinguishedName, queryRecord, SearchScope.OneLevel, dnsAttrs, false);

                if (hostResult == null) { continue; }

                if (hostResult.Attributes.Contains("dnsRecord"))
                {
                    string ip = ResolveDNSRecord(((byte[])hostResult.Attributes["dnsRecord"][0]));

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

            foreach (var result in GetResultEntries(TDOdomainDn, trustAccFilter, SearchScope.Subtree, trustAccAttrs, false))
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
                PrintYellow("[x] ERROR:" + e.Message);

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
                PrintYellow("[x] ERROR:" + e.Message);

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
                PrintYellow("[x] ERROR:" + e.Message);

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
                PrintYellow("[x] ERROR:" + e.Message);

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
        public static List<AppliedGPOs> GetAppliedGPOs(List<string> groupList, List<string> ouList, Dictionary<string, string> GPOs, bool onComputer = false, string customUser = null)
        {
            if (ouList == null) { return null; }

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

                var ouEntry = GetSingleDirectoryEntry(ou);

                if (ouEntry == null) { return null; }

                var linkedGPOAttr = new GPOAttributes();

                var linkedGPOs = new List<GPOAttributes>();

                //Linked GPOs & Enforcement
                if (ouEntry.Properties.Contains("gplink"))
                {
                    string[] gplinkArrary = Regex.Split(ouEntry.Properties["gplink"][0].ToString(), @"\]\[");
                    if (gplinkArrary == null) { break; }

                    foreach (var gplinkString in gplinkArrary)
                    {
                        if (gplinkString.Replace(" ","") == string.Empty) { continue; }

                        Match matchGPO = gpoRx.Match(gplinkString);

                        Match matchGpoption = gpoptionRx.Match(gplinkString);

                        gPOID = matchGPO.Groups[1].ToString().ToUpper();

                        //[LDAP://cn={E8D8C72C-3AAB-496C-90CD-C5F44F0AF10C},cn=policies,cn=system,DC=corplab,DC=local;0]
                        //0: Default: The GPO Link is not ignored and is not an enforced GPO.
                        //1: The GPO Link MUST be ignored.
                        //2: The GPO Link is an enforced GPO.
                        isEnforced = int.Parse(matchGpoption.Groups[1].ToString()) == 2;
                        string gpoDn = "CN=" + gPOID + ",CN=Policies,CN=System," + rootDn;

                        try//in case the gpo was deleted
                        {
                            gPOName = GPOs[gPOID];
                            //SecurityFiltering: Check if the target GPO applied to the current user
                            isDenied = IsDeniedPolicy(gpoDn, groupList);

                            if (isDenied)
                            {
                                gPOName += "  [X Denied]";
                            }

                            linkedGPOAttr.GPOID = gPOID;
                            linkedGPOAttr.GPOName = gPOName;
                            linkedGPOAttr.isEnforced = isEnforced;

                            linkedGPOs.Add(linkedGPOAttr);
                        }
                        catch { }

                        //gPOName = GPOs[gPOID];
                        ////SecurityFiltering: Check if the target GPO applied to the current user
                        //isDenied = IsDeniedPolicy(gpoDn, SIDList);

                        //if (isDenied)
                        //{
                        //    gPOName += "  [X Denied]";
                        //}

                        //linkedGPOAttr.GPOID = gPOID;
                        //linkedGPOAttr.GPOName = gPOName;
                        //linkedGPOAttr.isEnforced = isEnforced;

                        //linkedGPOs.Add(linkedGPOAttr);
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


        //Retrieve OU linked GPOs
        public static async Task<List<AppliedGPOs?>> GetOUGPOsAsync(Dictionary<string, string> GPOs)
        {
            var allOUEntries = GetResultEntries(ouDn, "(ObjectCategory=organizationalunit)", SearchScope.Subtree, new string[] { "distinguishedName","gplink" });
            if (allOUEntries == null) { return null; }

            Regex gpoRx = new Regex(@"=(\{.+?\}),", RegexOptions.Compiled);

            List<Task<AppliedGPOs?>> tasks = new List<Task<AppliedGPOs?>>();

            foreach (var ouEntry in allOUEntries)
            {
                tasks.Add(Task.Run(() => GetOUGPOs(GPOs, ouEntry, gpoRx)));
            }

            var appliedGPOsList = (await Task.WhenAll(tasks)).ToList();
            return appliedGPOsList;
        }



        public static AppliedGPOs? GetOUGPOs(Dictionary<string, string> GPOs, SearchResultEntry ouEntry, Regex gpoRx)
        {
            string gPOID = null;
            string gPOName = null;
            var linkedGPOAttr = new GPOAttributes();
            var linkedGPOs = new List<GPOAttributes>();

            if (ouEntry.Attributes.Contains("gplink"))
            {
                string[] gplinkArrary = Regex.Split(ouEntry.Attributes["gplink"][0].ToString(), @"\]\[");
                if (gplinkArrary == null) { return null; }

                foreach (var gplinkString in gplinkArrary)
                {
                    if (gplinkString.Replace(" ", "") == string.Empty) { continue; }

                    Match matchGPO = gpoRx.Match(gplinkString);

                    gPOID = matchGPO.Groups[1].ToString().ToUpper();

                    string gpoDn = "CN=" + gPOID + ",CN=Policies,CN=System," + rootDn;

                    try//in case the gpo was deleted
                    {
                        gPOName = GPOs[gPOID];
                        linkedGPOAttr.GPOID = gPOID;
                        linkedGPOAttr.GPOName = gPOName;

                        linkedGPOs.Add(linkedGPOAttr);
                    }
                    catch { }
                }
            }

            return new AppliedGPOs
            {
                LinkedGPOs = linkedGPOs,
                OUDn = ouEntry.DistinguishedName
            };
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

            if (uname.Contains('$')) { onComputer = true; }
            if (onComputer)
            {
                //If running as a machine account
                if (uname.Contains("$")) { name = uname; return null; }
                uname += "$";
            }

            name = uname.Replace("$","");

            string nFilter = $"(sAMAccountName={uname})";
;           
            string[] nAttrs = { "distingushiedName" };

            SearchResultEntry resultEntry = null;

            try
            {
                resultEntry = GetSingleResultEntry(rootDn, nFilter, SearchScope.Subtree, nAttrs, false);
            }
            catch { Debug.WriteLine($"[x] No Result Entry can be found for {customUser}"); return null; }
            
 
            if (resultEntry == null) { return null; }

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




        public static async Task<List<string>> GetGPPXML(string mydir = null)
        {
            string gppPath = mydir ?? "\\\\" + accessDC + "\\SYSVOL\\" + domainName + "\\Policies\\";

            var xmlList = new List<string> { "Groups.xml", "Services.xml", "Scheduledtasks.xml", "Datasources.xml", "Printers.xml", "Drives.xml" };

            List<Task<string>> tasks = new List<Task<string>>();
            /*
             * List<Task<List<ACLs>>> tasks = new List<Task<List<ACLs>>>();

            foreach (string targetDn in targetDnList)
            {
                tasks.Add(Task.Run(() => GetInterestingACLs(targetDn)));
            }

            var aclList = (await Task.WhenAll(tasks)).ToList();
             */
            try
            {
                foreach (string file in Directory.GetFiles(gppPath, "*.*", System.IO.SearchOption.AllDirectories))
                {
                     tasks.Add(Task.Run(() => CheckFile(xmlList, file)));
                }
                //foreach (string directory in Directory.GetDirectories(gppPath))
                //{
                //    try
                //    {
                //        GetGPPXML(directory);
                //    }
                //    catch { }
                //}
            }
            catch { }

            var files = (await Task.WhenAll(tasks)).ToList();
            return files;
        }



        public static string CheckFile(List<string>xmlList, string file)
        {
            try
            {
                if (xmlList.Any(file.Contains))
                {
                    return file;
                }
            }
            catch { }
            return null;
        }


        //public static List<string> GetCachedGPP()
        //{
        //    string allUser = Environment.GetEnvironmentVariable("ALLUSERSPROFILE");

        //    return allUser.Contains("ProgramData") ? GetGPPXML(allUser).Result : GetGPPXML(allUser + @"\Application Data").Result;
        //}




        //https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
        //Search for groups.xml, scheduledtasks.xml, services.xml, datasources.xml, printers.xml and drives.xml
        //findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
        public static async Task<List<GPP?>> GetGPPAsync(List<string> files)
        {
            var gppDict = new Dictionary<string, string>();

            gppDict.Add("Groups.xml", "/Groups/User/Properties");
            gppDict.Add("Services.xml", "/NTServices/NTService/Properties");
            gppDict.Add("Scheduledtasks.xml", "/ScheduledTasks/Task/Properties");
            gppDict.Add("Datasources.xml", "/DataSources/DataSource/Properties");
            gppDict.Add("Printers.xml", "/Printers/SharedPrinter/Properties");
            gppDict.Add("Drives.xml", "/Drives/Drive/Properties");

            XmlDocument doc = new XmlDocument();

            List<Task<GPP?>> tasks = new List<Task<GPP?>>();

            foreach (string path in files)
            {
                tasks.Add(Task.Run(() => GetGPP(doc, gppDict, path)));
            }
            var GPPPassList = (await Task.WhenAll(tasks)).ToList();
            return GPPPassList;
        }


        public static GPP? GetGPP(XmlDocument doc, Dictionary<string, string> gppDict, string path)
        {
            try { doc.Load(path); } catch { return null; }

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
                                    return new GPP
                                    {
                                        UserName = node.Attributes["userName"].Value,
                                        NewName = node.Attributes["newName"].Value,
                                        CPassword = node.Attributes["cpassword"].Value,
                                        Changed = node.ParentNode.Attributes["changed"].Value,
                                        Path = path
                                    };
                                }
                                catch { }
                            }
                            break;

                        case "Services.xml":
                            foreach (XmlNode node in nodes)
                            {
                                try
                                {
                                    return new GPP
                                    {
                                        AccountName = node.Attributes["accountName"].Value,
                                        CPassword = node.Attributes["cpassword"].Value,
                                        Changed = node.ParentNode.Attributes["changed"].Value,
                                        Path = path
                                    };
                                }
                                catch { }
                            }
                            break;

                        case "Scheduledtasks":
                            foreach (XmlNode node in nodes)
                            {
                                try
                                {
                                    return new GPP
                                    {
                                        RunAs = node.Attributes["runAs"].Value,
                                        CPassword = node.Attributes["cpassword"].Value,
                                        Changed = node.ParentNode.Attributes["changed"].Value,
                                        Path = path
                                    };
                                }
                                catch { }
                            }
                            break;

                        default:
                            foreach (XmlNode node in nodes)
                            {
                                try
                                {
                                    return new GPP
                                    {
                                        UserName = node.Attributes["userName"].Value,
                                        CPassword = node.Attributes["cpassword"].Value,
                                        Changed = node.ParentNode.Attributes["changed"].Value,
                                        Path = path
                                    };
                                }
                                catch { }

                            }
                            break;
                    }
                }
            }
            return null;
        }

        public static AuthorizationRuleCollection GetAuthorizationRules(string targetDn)
        {
            try
            {
                using (var aclEntry = GetSingleDirectoryEntry(targetDn))
                {
                    ActiveDirectorySecurity sec = aclEntry.ObjectSecurity;

                    AuthorizationRuleCollection rules = sec.GetAccessRules(true, true, typeof(NTAccount));

                    return rules;
                }

            }
            catch { return null; }
        }

        public static string GetOwner(string targetDn)
        {
            return GetSingleDirectoryEntry(targetDn).ObjectSecurity.GetOwner(typeof(SecurityIdentifier)).Value;
        }


        //public static List<ACLs> GetInterestingACLs(List<string> targetDnList)
        //{
        //    var aclList = new List<ACLs>();

        //    //Adapted from https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L3746

        //    Regex rights = new Regex(@"(GenericAll)|(.*Write.*)|(.*Create.*)|(.*Delete.*)", RegexOptions.Compiled);
        //    //Regex replica = new Regex(@"(.*Replication.*)", RegexOptions.Compiled);

        //    //string[] dcsync = { "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set" };

        //    foreach (string targetDn in targetDnList)
        //    {
        //        var owner = ConvertSIDToName(GetOwner(targetDn));

        //        var rules = GetAuthorizationRules(targetDn);

        //        if (rules == null) {return null; }

 
        //        foreach (ActiveDirectoryAccessRule rule in rules)
        //        {
        //            var sid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString();

        //            if (int.Parse(sid.Split('-').Last()) > 1000)
        //            {
        //                //Sometimes the identity reference cannot be resolved
        //                string IR = null;
        //                try
        //                {
        //                    IR = rule.IdentityReference.ToString();
        //                    if (IR == rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString())
        //                    {
        //                        IR = ConvertSIDToName(IR);
        //                    }
        //                }
        //                catch { }

        //                if (rights.IsMatch(rule.ActiveDirectoryRights.ToString())|| (rule.ActiveDirectoryRights.ToString() == "ExtendedRight" && rule.AccessControlType.ToString() == "Allow"))
        //                {
        //                    //The ObjectType GUID maps to an extended right registered in the current forest schema, then that specific extended right is granted
        //                    //Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf

        //                    string objType = ResolveRightsGuid(rule.ObjectType.ToString());

        //                    aclList.Add(new ACLs
        //                    {
        //                        ObjectDN = targetDn,
        //                        IdentityReference = IR,
        //                        IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
        //                        ActiveDirectoryRights = rule.ActiveDirectoryRights.ToString(),
        //                        ObjectType = objType
        //                    });
        //                }
        //            }
        //        }
        //    }

        //    return aclList;

        //}


        public static List<ACLs> GetInterestingACLs(string targetDn)
        {
            var aclList = new List<ACLs>();

            var rules = GetAuthorizationRules(targetDn);

            if (rules == null) { return aclList; }

            //Adapted from https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L3746
            Regex rights = new Regex(@"(GenericAll)|(.*Write.*)|(.*Create.*)|(.*Delete.*)", RegexOptions.Compiled);
            //Regex replica = new Regex(@"(.*Replication.*)", RegexOptions.Compiled);

            //string[] dcsync = { "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set" };

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
                            IR = ConvertSIDToName(IR);
                        }
                    }
                    catch { }
                    string objType = "";
                    if (rule.ActiveDirectoryRights.ToString().Contains("ExtendedRight") && rule.AccessControlType.ToString() == "Allow")
                    {
                        //The ObjectType GUID maps to an extended right registered in the current forest schema, then that specific extended right is granted
                        //Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf
                        objType = ResolveRightsGuid(rule.ObjectType.ToString(), true);
                    }

                    if (rights.IsMatch(rule.ActiveDirectoryRights.ToString()) || (rule.ActiveDirectoryRights.ToString() == "ExtendedRight" && rule.AccessControlType.ToString() == "Allow"))
                    {
                        aclList.Add(new ACLs
                        {
                            ObjectDN = targetDn,
                            IdentityReference = IR,
                            IdentitySID = sid,
                            ActiveDirectoryRights = rule.ActiveDirectoryRights.ToString().Replace("ExtendedRight", objType),
                            ObjectType = objType
                        });
                    }
                }
            }

            return aclList.Distinct().ToList();
        }


        public static async Task<List<List<ACLs>>> GetInterestingACLsAsync(List<string> targetDnList)
        {
            List<Task<List<ACLs>>> tasks = new List<Task<List<ACLs>>>();

            foreach (string targetDn in targetDnList)
            {
                tasks.Add(Task.Run(() => GetInterestingACLs(targetDn)));
            }

            var aclList = (await Task.WhenAll(tasks)).ToList();

            return aclList;
        }



        //First identify computers with LAPS enabled, then enumerate DACL of the parent OU
        public static List<ACLs> GetLAPSViewACLs()
        {
            var lapsComputers = GetSingleAttr(ouDn, "(ms-Mcs-AdmPwdExpirationTime=*)", "distinguishedName");

            if (lapsComputers == null || lapsComputers.Count == 0) { return null; }

            Regex ous = new Regex(@",(CN=.*|OU=.*)", RegexOptions.Compiled);

            var lapsOUs = lapsComputers.Select(ou => ous.Match(ou).Groups[1].Value).ToList();

            var aclList = new List<ACLs>();

            Regex rights = new Regex(@"(.*Read.*)", RegexOptions.Compiled);

            foreach (string targetDn in lapsOUs.Distinct())
            {
                var rules = GetAuthorizationRules(targetDn);

                if (rules == null) { return null; }

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    string IR = rule.IdentityReference.ToString();
                    string sid = "";
                    try { sid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(); }
                    catch { sid = IR; }

                    //Sometimes the identity reference cannot be resolved
                    if (IR == sid){try{ IR = ConvertSIDToName(IR); } catch { } }

                    //FALSE for resolving Schema attribute instead of extended rights
                    string objType = ResolveRightsGuid(rule.ObjectType.ToString(), false);

                    if (rights.IsMatch(rule.ActiveDirectoryRights.ToString())
                        && objType == "ms-Mcs-AdmPwd")
                    {
                        aclList.Add(new ACLs
                        {
                            ObjectDN = targetDn,
                            IdentityReference = IR,
                            IdentitySID = sid,
                            ActiveDirectoryRights = rule.ActiveDirectoryRights.ToString(),
                            ObjectType = objType
                        });
                    }

                }
            }

            return aclList;
        }


        //It does not work well with Task
        public static string ResolveRightsGuid(string rightsGuid, bool isExtendedRights = true)
        {
            if (isExtendedRights)
            {
                if (extendedRightsDict.ContainsKey(rightsGuid.ToLower()))
                {
                    return extendedRightsDict[rightsGuid.ToLower()];
                }
                //ms-TPM-OwnerInformation:aa4e1a6d-550d-4e05-8c35-4afcb917a9fe (this is a schema attribute...)
                else { return null; }
            }

            //string partition = isExtendedRights ? "CN=Extended-Rights,CN=Configuration," : "CN=Schema,CN=Configuration,";
            string partition = "CN=Schema,CN=Configuration,";

            //No SPACE near "="
            //From The .Net Developer Guide to Directory Services Programming Searching for Binary Data

            //resolve schema attributes / extended rights
            //string searchFilter = isExtendedRights ? @"(rightsGuid=" + rightsGuid + @")" :
            //    @"(schemaIDGUID=" + BuildFilterOctetString(new Guid(rightsGuid).ToByteArray()) + @")";
            string searchFilter = @"(schemaIDGUID=" + BuildFilterOctetString(new Guid(rightsGuid).ToByteArray()) + @")";
            var rightsDn = partition + forestDn;
            var rightsAttrs = new string[] { "cn" };

            var rightsResult = GetSingleResultEntry(rightsDn, searchFilter, SearchScope.OneLevel, rightsAttrs, false);

            if (rightsResult == null) {return rightsGuid; }

            return rightsResult.Attributes["cn"][0].ToString();

        }



        //Get all required attributes of the target object under a path
        public static Dictionary<string, Dictionary<string, DirectoryAttribute>> GetGeneral(string searchDn, string myFilter, string[] attributes)
        {
            var objDict = new Dictionary<string, Dictionary<string, DirectoryAttribute>>();

            var myResults = GetResultEntries(searchDn, myFilter, SearchScope.Subtree, attributes, false);

            if (myResults == null) { return null; }

            foreach (var result in myResults)
            {
                var attrDict = new Dictionary<string, DirectoryAttribute>();

                foreach (var attr in attributes)
                {
                    if (result.Attributes[attr]!= null)
                    {
                        attrDict.Add(attr, result.Attributes[attr]);
                    }                
                }

                objDict.Add(result.DistinguishedName, attrDict);
            }

            return objDict;
        }



        public static List<string> GetSingleAttr(string searchDn, string myFilter, string attribute)
        {

            var myList = new List<string>();

            var myAttrs = new string[] { attribute };

            var myResults = GetResultEntries(searchDn, myFilter, SearchScope.Subtree, myAttrs, false);

            if (myResults == null) { return null; }

            foreach (var result in myResults)
            {
                myList.Add(result.Attributes[attribute][0].ToString());
                
            }

            return myList;
        }


        public static PropertyValueCollection GetSingleEntryAttr(string targetDn, string attribute)
        {

            var myList = new List<string>();
            try
            {
                var targetEntry = GetSingleDirectoryEntry(targetDn);

                var entryAttr = targetEntry.Properties[attribute];

                return entryAttr;
            }
            catch { return null; }
        }


        public static string GetGPOLinkedOU(List<AppliedGPOs?> OUGPOs, string gpoID)
        {
            foreach(AppliedGPOs appliedGPO in OUGPOs)
            {
                foreach(var gpo in appliedGPO.LinkedGPOs)
                {
                    if (gpoID == gpo.GPOID)
                    {
                        return appliedGPO.OUDn;
                    }
                }
            }
            return null;
        }



        public static ActiveDirectorySecurity GetLDAPSecurityDescriptor(string targetDn)
        {
            var ntSecDescriptor = (byte[])GetSingleDirectoryEntry(targetDn).Properties["ntsecuritydescriptor"][0];

            if (ntSecDescriptor.Length == 0) { return null; }

            var adRights = new ActiveDirectorySecurity();

            adRights.SetSecurityDescriptorBinaryForm(ntSecDescriptor, AccessControlSections.All);

            return adRights;
        }



        public static List<string> ResolveSecurityDescriptors(DirectoryAttribute secDescriptor)
        {
            List<string> secDescription = new List<string>();
            //String
            if (secDescriptor[0] is string)
            {
                for (int i = 0; i < secDescriptor.Count; i++)
                {
                    secDescription.Add(secDescriptor[i].ToString());
                }
            }
            //Security Descriptors
            else if (secDescriptor[0] is byte[])
            {
                if (secDescriptor.Name.ToLower()== "msds-allowedtoactonbehalfofotheridentity")
                {
                    //Resolve Security Descriptor
                    //From The .Net Developer Guide to Directory Services Programming Listing 8.2. Listing the DACL

                    for (int i = 0; i < secDescriptor.Count; i++)
                    {
                        ActiveDirectorySecurity ads = new ActiveDirectorySecurity();

                        ads.SetSecurityDescriptorBinaryForm((byte[])secDescriptor[i]);

                        var rules = ads.GetAccessRules(true, true, typeof(NTAccount));

                        foreach (ActiveDirectoryAccessRule rule in rules)
                        {
                            string name = rule.IdentityReference.ToString();

                            if (name.ToUpper().Contains("S-1-5")) { name = ConvertSIDToName(name); }

                            secDescription.Add(name + " ([ControlType: " + rule.AccessControlType.ToString() + "] Rights: " + rule.ActiveDirectoryRights.ToString() + ")");
                        }
                    }
                }
                else
                {
                    for (int i = 0; i < secDescriptor.Count; i++)
                    {
                        var sid = new SecurityIdentifier((byte[])secDescriptor[i], 0).ToString();
                        var name = SIDName(sid);
                        if (name == null) 
                        { 
                            secDescription.Add(sid); 
                        } 
                        else
                        {
                            secDescription.Add(SIDName(sid));
                        }
                    }
                }
            }
            return secDescription;
        }




        public static RestictedGroups? GetRestrictedGroup(List<AppliedGPOs?> OUGPOs, Dictionary<string, string> GPOs, KeyValuePair<string,string> gpo)
        {
            var restrictedGroup = new List<RestictedGroups>();
            string ouDn = "";
            string gpoName = "";
            string gpoId = "";
            string groupName = "";

            string gpoDn = "CN=Policies,CN=System," + rootDn;
            string gpoPath = "\\\\" + accessDC + "\\SYSVOL\\" + domainName + "\\Policies\\";
            var groupMemRx = new Regex("__");
            string gpDn = "CN=" + gpo.Key + ',' + gpoDn;
            string gptPath = gpoPath + gpo.Key + "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf";
            string gXmlPath = gpoPath + gpo.Key + "\\MACHINE\\Preferences\\Groups\\Groups.xml";

            //Group Set through Group Policy Restricted Group (GptTmpl.inf) 
            try
            {
                var gpoInf = ReadInf(gptPath);
                if (gpoInf == null) { return null; }

                //IniData groups = groupParser.ReadFile(gptPath);

                gpoName = gpo.Value;
                gpoId = gpo.Key;
                ouDn = GetGPOLinkedOU(OUGPOs, gpo.Key);
                string relation = "";

                if (gpoInf.ContainsKey("Group Membership"))
                {
                    var groupMembership = new Dictionary<string, Dictionary<string, string>>();

                    foreach (var pair in gpoInf["Group Membership"])
                    {
                        var relationship = new Dictionary<string, string>();
                        string membership = "";

                        if (pair.Key.Contains("Member"))
                        {
                            relation = groupMemRx.Split(pair.Key)[1];

                            //KEY
                            //If *  then it's SID, if not it's name
                            if (groupMemRx.Split(pair.Key)[0].Contains('*'))
                            {
                                groupName = ConvertSIDToName(groupMemRx.Split(pair.Key)[0].Trim('*')) + "." + relation;
                            }
                            else
                            {
                                groupName = groupMemRx.Split(pair.Key)[0] + "." + relation;
                            }
                            //VALUE
                            if (!string.IsNullOrEmpty(pair.Value))
                            {
                                if (pair.Value.Contains(','))
                                {
                                    foreach (string m in pair.Value.Split(','))
                                    {
                                        if (m.Contains('*'))
                                        {
                                            membership += ConvertSIDToName(m.Trim()) + ", ";
                                        }
                                        else
                                        {
                                            membership += m.Trim() + ", ";
                                        }
                                    }
                                    membership = membership.Trim(' ', ',');
                                }
                                else
                                {
                                    if (pair.Value.Contains('*'))
                                    {
                                        membership = ConvertSIDToName(pair.Value.Trim());
                                    }
                                    else
                                    {
                                        membership = pair.Value.Trim();
                                    }
                                }
                                if (relation.Equals("Members")) { relationship.Add("Members", membership); };

                                if (relation.Equals("Memberof")) { relationship.Add("Memberof", membership); };

                                groupMembership.Add(groupName, relationship);
                            }
                        }
                    }
                    return new RestictedGroups()
                    {
                        GPOID = gpoId,
                        GPOName = gpoName,
                        OUDN = ouDn,
                        GroupMembership = groupMembership
                    };

                }
            }
            catch (Exception e) { PrintYellow("[x] ERROR: " + e.Message); }
            //Group set through Group Policy Preference (group.xml)
            try
            {
                XmlDocument gXml = new XmlDocument();

                gXml.Load(gXmlPath);

                var gNodes = gXml.SelectNodes("/Groups/Group/Properties");

                var groupMembership = new Dictionary<string, Dictionary<string, string>>();

                foreach (XmlNode gNode in gNodes)
                {
                    var relationship = new Dictionary<string, string>();

                    string members = "";
                    gpoName = gpo.Value;
                    gpoId = gpo.Key;
                    ouDn = GetGPOLinkedOU(OUGPOs, gpo.Key);

                    groupName = gNode.Attributes["groupName"].Value;

                    var mNodes = gNode["Members"].SelectNodes("Member");

                    foreach (XmlNode mNode in mNodes)
                    {
                        members += mNode.Attributes["name"].Value;
                    }

                    relationship.Add("Members", members);

                    groupMembership.Add(groupName, relationship);
                }
                return new RestictedGroups()
                {
                    GPOID = gpoId,
                    GPOName = gpoName,
                    OUDN = ouDn,
                    GroupMembership = groupMembership
                };
            }
            catch { return null; }
        }


        public static async  Task<List<RestictedGroups?>> GetRestrictedGroupAsync(List<AppliedGPOs?> OUGPOs, Dictionary<string, string> GPOs)
        {
            var tasks = new List<Task<RestictedGroups?>>();

            foreach (var gpo in GPOs)
            {
                tasks.Add(Task.Run(() => GetRestrictedGroup(OUGPOs, GPOs, gpo)));
            }

            var restrictedGroup = (await Task.WhenAll(tasks)).ToList();

            return restrictedGroup;
        }


        public static List<X509Certificate2> GetCaCertificate(DirectoryAttribute caCert)
        {
            var certs = new List<X509Certificate2>();
            foreach (var certBytes in caCert)
            {
                var cert = new X509Certificate2((byte[])certBytes);
                certs.Add(cert);
            }
            return certs;
        }


/*        public static void GetDACL(DirectoryAttribute attribute)
        {
            //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
            const string CERTENROLLMENT_GUID = "{0e10c968-78fb-11d2-90d4-00c04f79dc55}";

            ActiveDs.ADsSecurityUtility secUtility = new ActiveDs.ADsSecurityUtility();
            ActiveDs.IADsSecurityDescriptor sd = (IADsSecurityDescriptor)secUtility.ConvertSecurityDescriptor((byte[])attribute[0], (int)ADS_SD_FORMAT_ENUM.ADS_SD_FORMAT_RAW, (int)ADS_SD_FORMAT_ENUM.ADS_SD_FORMAT_IID);
            ActiveDs.IADsAccessControlList acl = (ActiveDs.IADsAccessControlList)sd.DiscretionaryAcl;

            foreach (ActiveDs.IADsAccessControlEntry ace in acl)
            {
                if ((ace.ObjectType != null) && (ace.ObjectType.ToUpper() == CERTENROLLMENT_GUID.ToUpper()))
                {
                    Console.WriteLine($"AccessMask:   {ace.AccessMask}");
                    Console.WriteLine($"AceFlags:     {ace.AceFlags}");
                    Console.WriteLine($"AceType:      {ace.AceType}");
                    Console.WriteLine($"Flags:        {ace.Flags}");
                    Console.WriteLine($"Trustee:      {ace.Trustee}");
                }
            }
        }*/




        public static async Task<List<ADCS>> GetADCSAsync()
        {
            string csFilter = @"(objectCategory=pKIEnrollmentService)";

            string csDn = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + configDn;

            List<Task<ADCS>> tasks = new List<Task<ADCS>>();

            foreach (SearchResultEntry csEntry in GetResultEntries(csDn, csFilter, SearchScope.Subtree, null, false))
            {
                tasks.Add(Task.Run(() => GetADCS(csEntry)));
            }

            var caList = (await Task.WhenAll(tasks)).ToList();

            return caList;
        }



        public static ADCS GetADCS(SearchResultEntry csEntry)
        {
            Debug.WriteLine("[*] Collecting ADCS Result Entry...");

            string enrollServers = null;
            List<ACLs> secDescriptors = new List<ACLs>();
            List<string> certTemplates = new List<string>();
            List<X509Certificate2> caCertificates = new List<X509Certificate2>();

            string caHostname = csEntry.Attributes["dnshostname"][0].ToString();
            string caName = csEntry.Attributes["name"][0].ToString();
            string whenCreated = ConvertWhenCreated(csEntry.Attributes["whencreated"][0].ToString()).ToString();

            var enrollmentEndpoints = TestEnrollmentEndpointsAsync(caName, caHostname).Result;

            PkiCertificateAuthorityFlags flags = (PkiCertificateAuthorityFlags)Enum.Parse(typeof(PkiCertificateAuthorityFlags), csEntry.Attributes["flags"][0].ToString());

            //The target attribute may not exist
            foreach (string attribute in csEntry.Attributes.AttributeNames)
            {
                if (attribute == "certificatetemplates")
                {
                    foreach (var certTemp in csEntry.Attributes[attribute])
                    {
                        certTemplates.Add(Encoding.UTF8.GetString((byte[])certTemp));
                    }
                }
                if (attribute == "mspki-enrollment-servers")
                {
                    enrollServers = csEntry.Attributes[attribute][0].ToString().Replace("\n", ",");
                }
                if (attribute == "cacertificate")
                {
                    caCertificates = GetCaCertificate(csEntry.Attributes[attribute]);
                }
            }


            bool allowSuppliedSAN = false;
            bool usingLDAP;

            var remoteReg = ReadRemoteReg(caHostname,
                RegistryHive.LocalMachine,
                $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy");

            //If the remote registry cannot be accessed, using LDAP to retrieve security descriptor instead
            usingLDAP = remoteReg == null ? true : false;

            if (usingLDAP)
            {
                //Read DACL from LDAP, better than nothing
                byte[] ldapSecBytes;
                ActiveDirectorySecurity adRights;
                ldapSecBytes = (byte[])csEntry.Attributes["ntsecuritydescriptor"][0];
                if (ldapSecBytes.Length != 0)
                {
                    adRights = new ActiveDirectorySecurity();
                    adRights.SetSecurityDescriptorBinaryForm(ldapSecBytes, AccessControlSections.All);
                    secDescriptors = GetDACL(csEntry.DistinguishedName, adRights);
                }
            }
            else
            {
                int editFlags = (remoteReg == null) ? 0 : (int)(remoteReg).GetValue("EditFlags");
                allowSuppliedSAN = ((editFlags & 0x00040000) == 0x00040000);

                //Reading DACL from the remote registry, nTSecurityDescriptor from LDAP does not have the necessary information 
                var regSec = (byte[])(ReadRemoteReg(caHostname,
                RegistryHive.LocalMachine,
                $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}")).GetValue("Security");
                Debug.WriteLine("[*] Remote Registry Value Returned...");

                var regSecDescriptor = new ActiveDirectorySecurity();
                regSecDescriptor.SetSecurityDescriptorBinaryForm(regSec, AccessControlSections.All);
                secDescriptors = GetCSDACL(regSecDescriptor, out _, false);
            }

            Debug.WriteLine("[*] Collected...");

            return new ADCS()
            {
                flags = flags,
                caCertificates = caCertificates,
                allowUserSuppliedSAN = allowSuppliedSAN,
                owner = ConvertSIDToName(GetOwner(csEntry.DistinguishedName)),
                CAName = caName,
                whenCreated = whenCreated,
                dnsHostName = caHostname,
                enrollServers = enrollServers,
                securityDescriptors = secDescriptors,
                certTemplates = certTemplates,
                enrollmentEndpoints = enrollmentEndpoints
            };

        }



        public static async Task<List<string>> TestEnrollmentEndpointsAsync(string caName, string caHostname)
        {
            List<Task<string>> tasks = new List<Task<string>>();

            //Adjusted from PKIAudit
            foreach (var protocol in new string[] { "http://", "https://" })
            {
                foreach (var suffix in new string[] { "/certsrv/",
                            $"/{caName}/_CES_Kerberos/service.svc",
                            $"/{caName}/_CES_Kerberos/service.svc/CES",
                            "/ADPolicyProvider_CEP_Kerberos/service.svc",
                            "/certsrv/mscep/" })
                {
                    var url = protocol + caHostname + suffix;

                    tasks.Add(Task.Run(() => TestWebConnection(url)));
                }
            }
            var enrollmentEndpoints = (await Task.WhenAll(tasks)).ToList();

            return enrollmentEndpoints;
        }




        public static async Task<List<CertificateTemplates?>> GetInterestingCertTemplatesAsync(List<ADCS> adcs)
        {
            var certTemplateResultEntries = GetResultEntries("CN=Certificate Templates,CN=Public Key Services,CN=Services," + configDn,
                @"(objectCategory=pKICertificateTemplate)",
                SearchScope.Subtree,
                new string[] { },
                false);
            List<Task<CertificateTemplates?>> tasks = new List<Task<CertificateTemplates?>>();

            foreach (var certTemplateResultEntry in certTemplateResultEntries)
            {
                tasks.Add(Task.Run(() => GetInterestingCertTemplates(adcs, certTemplateResultEntry)));
            }
            var certTemplateList = (await Task.WhenAll(tasks)).ToList();
            return certTemplateList;
        }



        public static CertificateTemplates? GetInterestingCertTemplates(List<ADCS> adcs, SearchResultEntry certTemplateResultEntry)
        {
            List<ACLs> secDescriptors = new List<ACLs>();

            bool isPublished = false;
            string publishedBy = null;
            bool hasControlRights = false;
            ActiveDirectorySecurity adRights = new ActiveDirectorySecurity();

            if (certTemplateResultEntry.Attributes.Contains("ntsecuritydescriptor"))
            {
                byte[] ldapSecBytes;
                ldapSecBytes = (byte[])certTemplateResultEntry.Attributes["ntsecuritydescriptor"][0];
                if (ldapSecBytes.Length != 0)
                {

                    adRights.SetSecurityDescriptorBinaryForm(ldapSecBytes, AccessControlSections.All);
                    secDescriptors = GetCSDACL(adRights, out hasControlRights, true,  certTemplateResultEntry.Attributes["cn"][0].ToString());
                }
            }

            var enrollFlag = (msPKIEnrollmentFlag)Enum.Parse(typeof(msPKIEnrollmentFlag), certTemplateResultEntry.Attributes["mspki-enrollment-flag"][0].ToString());
            var raSig = int.Parse(certTemplateResultEntry.Attributes["mspki-ra-signature"][0].ToString());
            var certNameFlag = (msPKICertificateNameFlag)Enum.Parse(typeof(msPKICertificateNameFlag), (unchecked((uint)(Convert.ToInt32(certTemplateResultEntry.Attributes["mspki-certificate-name-flag"][0].ToString())))).ToString());
            List<string> ekus = new List<string>();
            List<string> ekuNames = new List<string>();

            if (certTemplateResultEntry.Attributes.Contains("pkiextendedkeyusage"))
            {
                foreach (byte[] eku in certTemplateResultEntry.Attributes["pkiextendedkeyusage"])
                {
                    string ekuStr = Encoding.UTF8.GetString(eku);
                    ekus.Add(ekuStr);
                    ekuNames.Add(new Oid(ekuStr).FriendlyName);
                }
            }

            //If a low priv user has control rights over the templates
            if (hasControlRights)
            {
                foreach (var ca in adcs)
                {
                    var certInCa = ca.certTemplates.FirstOrDefault(caCerts => caCerts.Contains(certTemplateResultEntry.Attributes["name"][0].ToString()));
                    if (certInCa != null)
                    {
                        isPublished = true;
                        publishedBy = ca.CAName;
                    }
                }

                return new CertificateTemplates
                {
                    isPublished = isPublished,
                    publishedBy = publishedBy,
                    certNameFlag = certNameFlag,
                    raSigature = raSig,
                    owner = ConvertSIDToName(GetOwner(certTemplateResultEntry.DistinguishedName)),
                    enrollFlag = enrollFlag,
                    templateCN = certTemplateResultEntry.Attributes["cn"][0].ToString(),
                    templateDisplayName = certTemplateResultEntry.Attributes["displayName"][0].ToString(),
                    extendedKeyUsage = ekuNames,
                    securityDescriptors = GetCertTemplateDACL(certTemplateResultEntry.DistinguishedName, adRights)//secDescriptors
                };
            }

            //If a low priv user can enroll
            else if (secDescriptors.Any())
            {
                Debug.WriteLine("[*] Checking manager approval...");
                //Check if manager approval is enabled
                if (!enrollFlag.HasFlag(msPKIEnrollmentFlag.PEND_ALL_REQUESTS))
                {
                    Debug.WriteLine(certTemplateResultEntry.DistinguishedName);
                    Debug.WriteLine("[*] Checking authorized signatures...");
                    //Check if authorized signatures are required
                    if (raSig <= 0)
                    {
                        Debug.WriteLine(certTemplateResultEntry.DistinguishedName);
                        Debug.WriteLine("[*] Checking EKUs & ENROLLEE_SUPPLIES_SUBJECT ...");
                        //Check if ENROLLEE_SUPPLIES_SUBJECT is enabled and a low priv user can request a cert for authentication 
                        //Check if the template has dangerous EKUs
                        Debug.WriteLine(certTemplateResultEntry.DistinguishedName);
                        if ((certNameFlag.HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT) && HasAuthenticationEKU(ekus)) || HasDanagerousEKU(ekus))
                        {
                            Debug.WriteLine(certTemplateResultEntry.DistinguishedName);
                            foreach (var ca in adcs)
                            {
                                var certInCa = ca.certTemplates.FirstOrDefault(caCerts => caCerts.Contains(certTemplateResultEntry.Attributes["name"][0].ToString()));

                                if (certInCa != null)
                                {
                                    isPublished = true;
                                    publishedBy = ca.CAName;
                                }
                            }
                            if (secDescriptors.Count != 0)
                            {
                                return new CertificateTemplates
                                {
                                    isPublished = isPublished,
                                    publishedBy = publishedBy,
                                    owner = ConvertSIDToName(GetOwner(certTemplateResultEntry.DistinguishedName)),
                                    certNameFlag = certNameFlag,
                                    raSigature = raSig,
                                    enrollFlag = enrollFlag,
                                    templateCN = certTemplateResultEntry.Attributes["cn"][0].ToString(),
                                    templateDisplayName = certTemplateResultEntry.Attributes["displayName"][0].ToString(),
                                    extendedKeyUsage = ekuNames,
                                    securityDescriptors = GetCertTemplateDACL(certTemplateResultEntry.DistinguishedName, adRights)//secDescriptors
                                };
                            }
                        }
                    }
                }
            }

            return null;
        }


        //public static List<CertificateTemplates> GetInterestingCertTemplates(List<ADCS> adcs)
        //{
        //    if(adcs.Count == 0) { return null; }

        //    Debug.WriteLine("[*] Collecting Certificate Templates...");

        //    var certTemplateList = new List<CertificateTemplates>();

        //    List<ACLs> secDescriptors = new List<ACLs>();

        //    var certTemplateResultEntries = GetResultEntries("CN=Certificate Templates,CN=Public Key Services,CN=Services," + configDn,
        //        @"(objectCategory=pKICertificateTemplate)",
        //        SearchScope.Subtree,
        //        new string[] { },
        //        false);

        //    if (certTemplateResultEntries == null) { Debug.WriteLine("[*] No Certificate Template Found..."); return null; }

        //    Debug.WriteLine("[*] Collecting Certificate Templates Attributes...");

        //    foreach (var certTemplateResultEntry in certTemplateResultEntries)
        //    {
        //        bool isPublished = false;
        //        string publishedBy = null;
        //        bool hasControlRights = false;
        //        ActiveDirectorySecurity adRights = new ActiveDirectorySecurity();
        //        if (certTemplateResultEntry.Attributes.Contains("ntsecuritydescriptor"))
        //        {
        //            byte[] ldapSecBytes;
        //            ldapSecBytes = (byte[])certTemplateResultEntry.Attributes["ntsecuritydescriptor"][0];
        //            if (ldapSecBytes.Length != 0)
        //            {
                        
        //                adRights.SetSecurityDescriptorBinaryForm(ldapSecBytes, AccessControlSections.All);
        //                secDescriptors = GetCSDACL(adRights, out hasControlRights, true);
        //            }
        //        }

        //        var enrollFlag = (msPKIEnrollmentFlag)Enum.Parse(typeof(msPKIEnrollmentFlag), certTemplateResultEntry.Attributes["mspki-enrollment-flag"][0].ToString());
        //        var raSig = int.Parse(certTemplateResultEntry.Attributes["mspki-ra-signature"][0].ToString());
        //        var certNameFlag = (msPKICertificateNameFlag)Enum.Parse(typeof(msPKICertificateNameFlag), (unchecked((uint)(Convert.ToInt32(certTemplateResultEntry.Attributes["mspki-certificate-name-flag"][0].ToString())))).ToString());
        //        List<string> ekus = new List<string>();
        //        List<string> ekuNames = new List<string>();
        //        if (certTemplateResultEntry.Attributes.Contains("pkiextendedkeyusage"))
        //        {
        //            foreach (byte[] eku in certTemplateResultEntry.Attributes["pkiextendedkeyusage"])
        //            {
        //                string ekuStr = Encoding.UTF8.GetString(eku);
        //                ekus.Add(ekuStr);
        //                ekuNames.Add(new Oid(ekuStr).FriendlyName);
        //            }
        //        }


        //        //If a low priv user has control rights over the templates
        //        if (hasControlRights)
        //        {
        //            foreach(var ca in adcs)
        //            {
        //                var certInCa = ca.certTemplates.FirstOrDefault(caCerts => caCerts.Contains(certTemplateResultEntry.Attributes["name"][0].ToString()));
        //                if (certInCa != null)
        //                {
        //                    isPublished = true;
        //                    publishedBy = ca.CAName;
        //                }
        //            }
        //            certTemplateList.Add(new CertificateTemplates
        //            {
        //                isPublished = isPublished,
        //                publishedBy = publishedBy,
        //                certNameFlag = certNameFlag,
        //                raSigature = raSig,
        //                owner = ConvertSIDToName(GetOwner(certTemplateResultEntry.DistinguishedName)),
        //                enrollFlag = enrollFlag,
        //                templateCN = certTemplateResultEntry.Attributes["cn"][0].ToString(),
        //                templateDisplayName = certTemplateResultEntry.Attributes["displayName"][0].ToString(),
        //                extendedKeyUsage = ekuNames,
        //                securityDescriptors = GetDACL(certTemplateResultEntry.DistinguishedName, adRights)//secDescriptors
        //            });
        //        }
        //        //If a low priv user can enroll
        //        else if (secDescriptors.Any())
        //        {
        //            Debug.WriteLine("[*] Checking manager approval...");
        //            //Check if manager approval is enabled
        //            if (!enrollFlag.HasFlag(msPKIEnrollmentFlag.PEND_ALL_REQUESTS))
        //            {
        //                Debug.WriteLine(certTemplateResultEntry.DistinguishedName);
        //                Debug.WriteLine("[*] Checking authorized signatures...");
        //                //Check if authorized signatures are required
        //                if (raSig <= 0)
        //                {
        //                    Debug.WriteLine(certTemplateResultEntry.DistinguishedName);
        //                    Debug.WriteLine("[*] Checking EKUs & ENROLLEE_SUPPLIES_SUBJECT ...");
        //                    //Check if ENROLLEE_SUPPLIES_SUBJECT is enabled and a low priv user can request a cert for authentication 
        //                    //Check if the template has dangerous EKUs
        //                    if ((certNameFlag.HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT) && HasAuthenticationEKU(ekus)) || HasDanagerousEKU(ekus))
        //                    {
        //                        Debug.WriteLine(certTemplateResultEntry.DistinguishedName);
        //                        foreach (var ca in adcs)
        //                        {
        //                            var certInCa = ca.certTemplates.FirstOrDefault(caCerts => caCerts.Contains(certTemplateResultEntry.Attributes["name"][0].ToString()));

        //                            if (certInCa != null)
        //                            {
        //                                isPublished = true;
        //                                publishedBy = ca.CAName;
        //                            }
        //                        }
        //                        if (secDescriptors.Count != 0)
        //                        {
        //                            certTemplateList.Add(new CertificateTemplates
        //                            {
        //                                isPublished = isPublished,
        //                                publishedBy = publishedBy,
        //                                owner = ConvertSIDToName(GetOwner(certTemplateResultEntry.DistinguishedName)),
        //                                certNameFlag = certNameFlag,
        //                                raSigature = raSig,
        //                                enrollFlag = enrollFlag,
        //                                templateCN = certTemplateResultEntry.Attributes["cn"][0].ToString(),
        //                                templateDisplayName = certTemplateResultEntry.Attributes["displayName"][0].ToString(),
        //                                extendedKeyUsage = ekuNames,
        //                                securityDescriptors = GetDACL(certTemplateResultEntry.DistinguishedName, adRights)//secDescriptors
        //                            });
        //                        }
        //                    }
        //                }
        //            }
        //        }

        //    }

        //    if (certTemplateList.Count == 0) { Debug.WriteLine("[*] No Certificate Template Found..."); }
        //    Debug.WriteLine("[*] Certificate Templates Collected...");
        //    return certTemplateList;
        //}


        public static List<ACLs> GetCSDACL(ActiveDirectorySecurity adRights, out bool hasControlRights, bool findInteresting = false, string usr = "")
        {
            hasControlRights = false;

            var aclList = new List<ACLs>();
            var rules = adRights.GetAccessRules(true, true, typeof(SecurityIdentifier));

            if (rules == null) { return aclList; }

            var ownerSid = adRights.GetOwner(typeof(SecurityIdentifier)).ToString();

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                string objType = null;
                string IR = rule.IdentityReference.ToString();
                string IRSid = "";
                try { IRSid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(); }
                catch { IRSid = IR; }


                if (IR == IRSid)
                {
                    try
                    {
                        IR = ConvertSIDToName(IR);
                    }
                    catch { }
                }

                if (rule.ActiveDirectoryRights.ToString().Contains("ExtendedRight") && rule.AccessControlType.ToString() == "Allow")
                {
                    //The ObjectType GUID maps to an extended right registered in the current forest schema, then that specific extended right is granted
                    //Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf

                    objType = ResolveRightsGuid(rule.ObjectType.ToString(), true);
                }

                if (findInteresting)
                {
                    if (rule.AccessControlType.ToString() == "Allow" && IsLowPrivSid(IRSid))
                    {
                        //If a low priv user has certain control over the template
                        if (((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                             || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                             || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                             //|| rule.ObjectType.ToString() == "0e10c968-78fb-11d2-90d4-00c04f79dc55" //Certificate-Enrollment
                             || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && rule.ObjectType.ToString() == "00000000-0000-0000-0000-000000000000"))
                        {
                            hasControlRights = true;
                            aclList.Add(new ACLs
                            {
                                IdentityReference = IR,
                                IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
                                ActiveDirectoryRights = (rule.ActiveDirectoryRights).ToString(),
                                ObjectType = objType,
                            });
                        }
                        //If a low priv user can enroll
                        if ((rule.ActiveDirectoryRights.ToString().Contains("ExtendedRight")) && (rule.ObjectType.ToString().ToLower() == "0e10c968-78fb-11d2-90d4-00c04f79dc55" || rule.ObjectType.ToString() == "00000000-0000-0000-0000-000000000000"))
                        {
                            aclList.Add(new ACLs
                            {
                                IdentityReference = IR,
                                IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
                                ActiveDirectoryRights = (rule.ActiveDirectoryRights).ToString(),
                                ObjectType = objType,
                            });
                        }
                    }
                }
                else
                {
                    aclList.Add(new ACLs
                    {
                        IdentityReference = IR,
                        IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
                        ActiveDirectoryRights = ((CertificationAuthorityRights)rule.ActiveDirectoryRights).ToString(),
                        ObjectType = objType,
                    });
                }
            }
           
            return aclList;
        }


        public static List<ACLs> GetDACL(string objDn, ActiveDirectorySecurity adRights, bool findInteresting = false, string targetSid = null)
        {
            var aclList = new List<ACLs>();
            var rules = adRights.GetAccessRules(true, true, typeof(SecurityIdentifier));

            if (rules == null) { return aclList; }

            var ownerSid = adRights.GetOwner(typeof(SecurityIdentifier)).ToString();

            Regex interestingRights = new Regex(@"(GenericAll)|(.*Write.*)|(.*Create.*)|(.*Delete.*)", RegexOptions.Compiled);

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                string objType = null;
                var IRSid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString();

                string IR = rule.IdentityReference.ToString();

                if (IR == IRSid)
                {
                    try
                    {
                        IR = ConvertSIDToName(IR);
                    }
                    catch { }
                }

                if (rule.ActiveDirectoryRights.ToString().Contains("ExtendedRight") && rule.AccessControlType.ToString() == "Allow")
                {
                    //The ObjectType GUID maps to an extended right registered in the current forest schema, then that specific extended right is granted
                    //Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf

                    objType = ResolveRightsGuid(rule.ObjectType.ToString());
                }

                if (findInteresting)
                {
                    string rights = rule.ActiveDirectoryRights.ToString();

                    if (interestingRights.IsMatch(rights) || (rights == "ExtendedRight" && rule.AccessControlType.ToString() == "Allow"))
                    {
                        if (IRSid == targetSid)
                        {
                            aclList.Add(new ACLs
                            {
                                ObjectDN = objDn,
                                IdentityReference = IR,
                                IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
                                ActiveDirectoryRights = (rule.ActiveDirectoryRights).ToString(),
                                ObjectType = objType,
                            });
                        }
                    }

                }
                else
                {
                    aclList.Add(new ACLs
                    {
                        ObjectDN = objDn,
                        IdentityReference = IR,
                        IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
                        ActiveDirectoryRights = (rule.ActiveDirectoryRights).ToString(),
                        ObjectType = objType,
                    });
                }
            }

            return aclList;
        }


        public static List<ACLs> GetCertTemplateDACL(string objDn, ActiveDirectorySecurity adRights)
        {
            var aclList = new List<ACLs>();
            var rules = adRights.GetAccessRules(true, true, typeof(SecurityIdentifier));

            if (rules == null) { return aclList; }

            var ownerSid = adRights.GetOwner(typeof(SecurityIdentifier)).ToString();

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                string objType = null;
                string IRSid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString();

                string IR = rule.IdentityReference.ToString();

                if (IR == IRSid)
                {
                    try
                    {
                        IR = ConvertSIDToName(IR);
                    }
                    catch { }
                }

                //Adjusted from https://www.powershellgallery.com/packages/PSPKI/3.2.7.0/Content/Server%5CGet-CertificateTemplateAcl.ps1
                string rights = rule.ActiveDirectoryRights.ToString();
                string permission = null;

                if(rights.Contains("GenericRead") || rights.Contains("GenericExecute"))
                {
                    permission += "Read ";
                }
                if (rights.Contains("WriteDacl"))
                {
                    permission += "Write ";
                }
                if (rights.Contains("GenericAll"))
                {
                    permission += "FullControll ";
                }
                if (rights.Contains("ExtendedRight") && rule.AccessControlType.ToString() == "Allow")
                {
                    var rightsGuid = rule.ObjectType.ToString().ToUpper();
                    if (rightsGuid == "0E10C968-78FB-11D2-90D4-00C04F79DC55")
                    {
                        permission += "Enroll ";
                    }
                    if (rightsGuid == "A05B8CC2-17BC-4802-A710-E7C15AB866A2")
                    {
                        permission += "AutoEnroll ";
                    }
                }

                aclList.Add(new ACLs
                {
                    ObjectDN = objDn,
                    IdentityReference = IR,
                    IdentitySID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString(),
                    ActiveDirectoryRights = permission,
                    ObjectType = objType,
                });

            }

            return aclList;
        }


        public static List<List<ACLs>> InvokeACLScan(string targetIdentity)
        {
            if (targetIdentity == null) { PrintYellow("[x] Target Identity is required for ACL Scan."); return null; }

            var targetEntry = GetSingleResultEntry(rootDn, $"(sAMAccountName={targetIdentity})", SearchScope.Subtree, null, false);
            if (targetEntry == null) { return null; }
            var targetSid = new SecurityIdentifier((byte[])targetEntry.Attributes["objectsid"][0], 0).ToString();

            var partitions = new string[] { rootDn, configDn, schemaDn };
            
            List<List<ACLs>> allSecDescriptors = new List<List<ACLs>>();

            if (ouDn != rootDn)
            {
                var allObjects = GetResultEntries(ouDn, "(ObjectCategory=*)", SearchScope.Subtree, null, false);
                foreach(var obj in allObjects)
                {
                    List<ACLs> secDescriptors = new List<ACLs>();

                    if (obj.Attributes.Contains("ntsecuritydescriptor"))
                    {
                        ActiveDirectorySecurity adRights;
                        byte[] ldapSecBytes = (byte[])obj.Attributes["ntsecuritydescriptor"][0];
                        if (ldapSecBytes.Length != 0)
                        {
                            adRights = new ActiveDirectorySecurity();
                            adRights.SetSecurityDescriptorBinaryForm(ldapSecBytes, AccessControlSections.All);
                            secDescriptors = GetDACL(obj.DistinguishedName, adRights, true, targetSid);
                            if (secDescriptors.Count != 0)
                            {
                                allSecDescriptors.Add(secDescriptors);
                            }
                        }
                    }
                }
            }
            else
            {
                foreach(var partition in partitions)
                {
                    var allObjects = GetResultEntries(partition, "(ObjectCategory=*)", SearchScope.Subtree, null, false);
                    foreach (var obj in allObjects)
                    {
                        List<ACLs> secDescriptors = new List<ACLs>();

                        if (obj.Attributes.Contains("ntsecuritydescriptor"))
                        {
                            ActiveDirectorySecurity adRights;
                            byte[] ldapSecBytes = (byte[])obj.Attributes["ntsecuritydescriptor"][0];
                            if (ldapSecBytes.Length != 0)
                            {
                                adRights = new ActiveDirectorySecurity();
                                adRights.SetSecurityDescriptorBinaryForm(ldapSecBytes, AccessControlSections.All);
                                secDescriptors = GetDACL(obj.DistinguishedName, adRights, true, targetSid);
                                if (secDescriptors.Count != 0)
                                {
                                    allSecDescriptors.Add(secDescriptors);
                                }
                            }
                        }
                    }
                }
            }

            return allSecDescriptors;
        }

        //Build Extended Rights Dictionary (somehow enum does not work well with threading)
        public static Dictionary<string,string> BuildExtendedRightsDict()
        {
            var extendedRightsDict = new Dictionary<string, string>();
            string extendedRightsDn = "CN=Extended-Rights," + configDn;

            var rightsResult = GetResultEntries(extendedRightsDn, "(rightsGuid=*)", SearchScope.Subtree, new string[] { "rightsGuid","cn" });

            foreach (var rights in rightsResult)
            {
                //Ignore duplicated rightsGuid DNS-Host-Name-Attributes & Validated-DNS-Host-Name: "72e39547-7b18-11d1-adef-00c04fd8d5cd"
                string rightsGuid = rights.Attributes["rightsGuid"][0].ToString().ToLower();

                if (rightsGuid == "72e39547-7b18-11d1-adef-00c04fd8d5cd") { continue; } 

                extendedRightsDict.Add(rightsGuid, rights.Attributes["cn"][0].ToString()); 
                
            }
            extendedRightsDict.Add("72e39547-7b18-11d1-adef-00c04fd8d5cd", "DNS-Host-Name-Attributes & Validated-DNS-Host-Name");
            extendedRightsDict.Add("00000000-0000-0000-0000-000000000000", "");
            return extendedRightsDict;
        }
    }
}
