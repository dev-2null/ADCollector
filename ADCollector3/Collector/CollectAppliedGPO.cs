using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ADCollector3
{
    public class CollectAppliedGPO : ICollector
    {
        Logger _logger { get; set; }
        public Dictionary<string, Dictionary<string, string>> AppliedGPOs { get; set; }

        //Dependency: Nested Group SID of the user
        //It is required to check security filtering with nested security group SID of the user
        public CollectAppliedGPO()
        {
            _logger = LogManager.GetCurrentClassLogger();
        }



        //1. Iterate each OU/Domain/Site: "gplink" & "gpoptions"
        //2. Find GPOs that are linked to each OU/Domain/Site
        //3. Iterate each GPO to find out if they have WMI filters: "gPCWQLFilter"
        //4. Find the WMI policy and check if the policy is filtered out: "msWMI-Parm2"
        public IResult Collect(SearchString searchstring)
        {
            AppliedGPOSearchString searchString = (AppliedGPOSearchString)searchstring;
            
            var ouList = CollectMyOUs(searchString.SAMAccountName);
            if (ouList == null) { return null; }

            AppliedGPOs = new Dictionary<string, Dictionary<string, string>>();
            Regex gpoRx = new Regex(@"=(\{.+?\}),", RegexOptions.Compiled);
            Regex gpoptionRx = new Regex(@";(\d)", RegexOptions.Compiled);

            foreach (string ouDN in ouList)
            {
                bool isBlocking = false;
                bool isEnforced = false;
                bool isDenied = false;
                var linkedGPOs = new Dictionary<string, string>();

                using(var ouEntry = Searcher.GetDirectoryEntry(ouDN))
                {

                    //Linked GPOs & Enforcement
                    if (ouEntry.Properties.Contains("gplink"))
                    {
                        string[] gplinkArrary = Regex.Split(ouEntry.Properties["gplink"][0].ToString(), @"\]\[");
                        if (gplinkArrary == null) { break; }

                        foreach (var gplinkString in gplinkArrary)
                        {
                            if (gplinkString.Replace(" ", "") == string.Empty) { continue; }

                            Match matchGPO = gpoRx.Match(gplinkString);

                            Match matchGpoption = gpoptionRx.Match(gplinkString);

                            string gpoID = matchGPO.Groups[1].ToString().ToUpper();

                            //[LDAP://cn={E8D8C72C-3AAB-496C-90CD-C5F44F0AF10C},cn=policies,cn=system,DC=corplab,DC=local;0]
                            //0: Default: The GPO Link is not ignored and is not an enforced GPO.
                            //1: The GPO Link MUST be ignored.
                            //2: The GPO Link is an enforced GPO.
                            isEnforced = (int.Parse(matchGpoption.Groups[1].ToString()) == 2);

                            string gpoDn = "CN=" + gpoID + ",CN=Policies,CN=System," + Searcher.LdapInfo.RootDN;

                            try//in case the gpo was deleted
                            {
                                string gpoName = GPO.GroupPolicies[gpoID];
                                //SecurityFiltering: Check if the target GPO applied to the current user
                                isDenied = IsDeniedPolicy(searchString.SAMAccountName, gpoDn);
                                gpoName = isDenied ? (gpoName + "  [X Denied]") : gpoName;
                                gpoName = isEnforced ? (gpoName + " [Enforced]") : gpoName;

                                linkedGPOs.Add(gpoID, gpoName);
                            }
                            catch { _logger.Warn($"GPO {gpoID} was probably deleted."); }
                        }
                    }
                    //If a OU blocks inheritance
                    if (ouEntry.Properties.Contains("gpOptions"))
                    {
                        //OUs that block inheritance will only ignore non-enforecd GPO
                        //OU Attribute: gPOptions=1  Block Inheritance
                        isBlocking = (int)ouEntry.Properties["gpOptions"][0] == 1;
                    }
                }

                string ou = isBlocking ? (ouDN + " [Blocking Inheritance]") : ouDN;

                AppliedGPOs.Add(ou, linkedGPOs);
            }
            return new DDResult { Title = searchString.Title, Result = AppliedGPOs};
        }




        public List<string> CollectMyOUs(string sAMAccountName)
        {
            _logger.Debug($"Collecting OUs for {sAMAccountName}");

            List<string> ouList = new List<string>();

            sAMAccountName = sAMAccountName.ToUpper();

            var result = Searcher.GetSingleAttributeValue(Searcher.LdapInfo.RootDN, $"(samaccountname={sAMAccountName})", "distinguishedname");
            if (result == null) { return null; }
            string myDN = (string)result;

            try
            {
                myDN = myDN.ToUpper();

                while (myDN.Contains(",OU"))
                {
                    if (myDN.Contains(("CN=" + sAMAccountName + ",")))
                    {
                        myDN = myDN.Replace(("CN=" + sAMAccountName + ","), string.Empty);
                    }
                    else
                    {
                        myDN = myDN.Substring(myDN.IndexOf(",OU") + 1);
                    }
                    ouList.Add(myDN);
                }
                //add Domain DN
                myDN = myDN.Substring(myDN.IndexOf(",DC=") + 1);
                ouList.Add(myDN);
                //if (sAMAccountName.Contains("$"))
                //{
                //    //add Site DN
                //    string site = CollectMySite(sAMAccountName);
                //    if (site != null)
                //    {
                //        string siteDn = "CN=" + site + ",CN=Sites,CN=Configuration," + Searcher.LdapInfo.ForestDN;
                //        ouList.Add(siteDn);
                //    }
                //}
                return ouList;
            }
            catch (Exception e)
            {
                _logger.Warn(e.Message);
                return null;
            }
        }




        public bool IsDeniedPolicy(string sAMAccountName, string gpoDn)
        {
            _logger.Debug($"Checking if ({gpoDn}) is denied by security filtering");

            var rules = DACL.GetAuthorizationRules(gpoDn, out _);

            bool isDenied = true;
            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                //Security Filtering
                //Apply-Group-Policy: edacfd8f-ffb3-11d1-b41d-00a0c968f939
                if ((rule.ActiveDirectoryRights.ToString().ToLower() == "extendedright") &&
                    (rule.ObjectType.ToString().ToUpper() == "EDACFD8F-FFB3-11D1-B41D-00A0C968F939"))
                {
                    string groupSID = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString().ToUpper();

                    try
                    {
                        //If the target GPO applys to the current user's security groups
                        var userNestedGSID = CollectNestedGroupMembership.UserSIDNameDictionary[sAMAccountName.ToUpper()];
                        
                        if (userNestedGSID.ContainsKey(groupSID))
                        {
                            isDenied = false;
                        }
                    }
                    catch (Exception e)
                    {
                        _logger.Error(e.Message);
                    }
                }
            }

            string deny = isDenied ? string.Empty : " not";
            _logger.Debug($"({gpoDn}) is{deny} denied");
            return isDenied;
        }





        //public static string CollectMySite(string sAMAccountName)
        //{
        //    logger.Debug($"Collecting Site for {sAMAccountName}");
        //    IntPtr pBuffer;
        //    try
        //    {
        //        uint result = Natives.DsGetSiteName(sAMAccountName, out pBuffer);

        //        if (result == 0)
        //        {
        //            string mySiteName = Marshal.PtrToStringAuto(pBuffer);

        //            Natives.NetApiBufferFree(pBuffer);
        //            logger.Debug($"{sAMAccountName} is in {mySiteName}");
        //            return mySiteName;
        //        }
        //        return null;
        //    }
        //    catch (Exception e)
        //    {
        //        logger.Warn(e.Message);
        //        return null;
        //    }

        //}
    }
}
