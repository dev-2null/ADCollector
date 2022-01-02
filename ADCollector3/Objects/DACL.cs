using Microsoft.Win32;
using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static ADCollector3.Enums;
using static ADCollector3.Natives;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace ADCollector3
{
    public class DACL
    {
        public string ObjectName { get; set; }
        public Dictionary<string, List<string>> ACEs { get; set; }
        static Logger logger { get; set; } = LogManager.GetCurrentClassLogger();


        public static AuthorizationRuleCollection GetAuthorizationRules(string targetDn, out string ownerSID)
        {
            logger.Debug($"Getting Authorization Rules for {targetDn}");
            try
            {
                using (var aclEntry = Searcher.GetDirectoryEntry(targetDn))
                {
                    ActiveDirectorySecurity sec = aclEntry.ObjectSecurity;
                    ownerSID = sec.GetOwner(typeof(SecurityIdentifier)).ToString();
                    AuthorizationRuleCollection rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier));
                    return rules;
                }
            }
            catch
            {
                logger.Error($"Cannot get authorization data on {targetDn}");
                ownerSID = null;
                return null;
            }
        }


        //Get DACL for LAPS
        public static List<DACL> GetLAPSACL()
        {
            logger.Debug("Getting ACLs for LAPS");
            var laspDACLList = new List<DACL>();
            var lapsACEs = new Dictionary<string, List<string>>();

            var lapsResults = Searcher.GetResultEntries(new LDAPSearchString { 
                DN = Searcher.LdapInfo.TargetSearchBase,
                Filter = "(ms-Mcs-AdmPwdExpirationTime=*)",
                Scope = SearchScope.Subtree
            }).ToList();

            if (lapsResults == null || lapsResults.Count == 0) 
            {
                logger.Debug("No LAPS enabled machine can be found");
                return null;
            }

            Regex ous = new Regex(@",(CN=.*|OU=.*)", RegexOptions.Compiled);

            //Only target the first degree OU
            var lapsOUs = lapsResults.Select(entry => ous.Match(entry.DistinguishedName).Groups[1].Value).Distinct().ToList();

            Regex rights = new Regex(@"(.*Read.*)", RegexOptions.Compiled);

            foreach (string targetDn in lapsOUs)
            {
                var rules = GetAuthorizationRules(targetDn, out string ownerSID);

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    string sid = rule.IdentityReference.ToString();
                    string adRights = rule.ActiveDirectoryRights.ToString();
                    string objectType = rule.ObjectType.ToString();

                    //{2537B2BE-3CE2-459E-A86A-B7949C1D361C}: ms-Mcs-AdmPwd
                    if (rights.IsMatch(adRights) && 
                        objectType.ToUpper() == "2537B2BE-3CE2-459E-A86A-B7949C1D361C")
                    {
                        string IR = Helper.SIDNameSID(sid);
                        string userRights = $"ms-Mcs-AdmPwd ({adRights})";

                        if (lapsACEs.ContainsKey(IR)){ lapsACEs[IR].Add(userRights); }
                        else{ lapsACEs.Add(IR, new List<string> { userRights }); }
                    }
                }
                string owner = Helper.SIDNameSID(ownerSID);
                if (lapsACEs.ContainsKey(owner)){ lapsACEs[owner].Add("Owner"); }
                else{ lapsACEs.Add(owner, new List<string> { "Owner" }); }

                laspDACLList.Add(new DACL { ObjectName = targetDn, ACEs = lapsACEs });
            }
            return laspDACLList;
        }



        //Get interesting DACL on an object
        public static DACL GetInterestingACLOnObject(string targetDn)
        {
            logger.Debug($"Collecting Interesting ACLs on {targetDn}");

            var interestingACEs = new Dictionary<string, List<string>>();
            Regex gpoRx = new Regex(@"=(\{.+?\}),", RegexOptions.Compiled);


            var rules = GetAuthorizationRules(targetDn, out string ownerSID);
            if (rules == null) { return null; }

            //Adapted from https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L3746
            Regex rights = new Regex(@"(GenericAll)|(.*Write.*)|(.*Create.*)|(.*Delete.*)", RegexOptions.Compiled);
            //Regex replica = new Regex(@"(.*Replication.*)", RegexOptions.Compiled);

            //string[] dcsync = { "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set" };

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                var sid = rule.IdentityReference.ToString();
                //var sid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString();

                if (int.Parse(sid.Split('-').Last()) > 1000)
                {
                    string IR = Helper.SIDNameSID(sid);
                    string objType = rule.ObjectType.ToString();
                    string adRights = rule.ActiveDirectoryRights.ToString();

                    logger.Debug($"{targetDn}:{IR}: ADRights:  {adRights} ObjectType: {objType}");

                    if ((rights.IsMatch(adRights) || adRights == "ExtendedRight") && rule.AccessControlType.ToString() == "Allow")
                    {
                        string userRights = null;

                        if ((adRights == "ExtendedRight") && rule.AccessControlType.ToString() == "Allow")
                        {
                            //The ObjectType GUID maps to an extended right registered in the current forest schema, then that specific extended right is granted
                            //Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf
                            userRights = Rights.ResolveRightsGuid(objType, true);
                        }
                        else
                        {
                            string schemaName = Rights.ResolveRightsGuid(objType, false);
                            userRights = schemaName + $" ({adRights})";
                        }

                        if (interestingACEs.ContainsKey(IR)){ interestingACEs[IR].Add(userRights); }
                        else { interestingACEs.Add(IR, new List<string> { userRights }); }
                    }
                }
            }
            //check owner
            if (int.Parse(ownerSID.Split('-').Last()) > 1000)
            {
                string owner = Helper.SIDNameSID(ownerSID);
                if (interestingACEs.ContainsKey(owner)){ interestingACEs[owner].Add("Owner");}
                else { interestingACEs.Add(owner, new List<string> { "Owner" });}
            }
                

            string key;
            Match matchGPO = gpoRx.Match(targetDn);
            if (matchGPO.Success)
            {
                string gpoID = matchGPO.Groups[1].ToString().ToUpper();
                string gpoName = GPO.GroupPolicies[gpoID];
                key = gpoID + " " + gpoName;
            }
            else
            {
                key = targetDn;
            }
            if (interestingACEs == null || interestingACEs.Count == 0) { return null; }
            return new DACL { ObjectName = key, ACEs = interestingACEs};
        }



        //Get DACL on an object
        public static DACL GetACLOnObject(string targetDn)
        {
            logger.Debug($"Collecting ACLs on {targetDn}");

            var ACEs = new Dictionary<string, List<string>>();
            Regex gpoRx = new Regex(@"=(\{.+?\}),", RegexOptions.Compiled);

            var rules = GetAuthorizationRules(targetDn, out string ownerSID);
            if (rules == null) { return null; }

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                var sid = rule.IdentityReference.ToString();
                string IR = Helper.SIDNameSID(sid);
                string objType = rule.ObjectType.ToString();
                string adRights = rule.ActiveDirectoryRights.ToString();

                logger.Debug($"{targetDn}:{IR}: ADRights: {adRights} ObjectType: {objType} AccessControlType: {rule.AccessControlType}");

                string userRights = null;

                if (adRights.Contains("ExtendedRight"))
                {
                    //The ObjectType GUID maps to an extended right registered in the current forest schema, then that specific extended right is granted
                    //Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf
                    userRights = Rights.ResolveRightsGuid(objType, true) + $" [{rule.AccessControlType}]";
                    userRights = adRights.Replace("ExtendedRight", $"[ExtendedRight: {userRights}]");
                }
                else
                {
                    string schemaName = Rights.ResolveRightsGuid(objType, false);
                    userRights = schemaName + $" ({adRights} [{rule.AccessControlType}])";
                }

                if (ACEs.ContainsKey(IR)) { ACEs[IR].Add(userRights); }
                else { ACEs.Add(IR, new List<string> { userRights }); }
            }
            string owner = Helper.SIDNameSID(ownerSID);
            if (ACEs.ContainsKey(owner))
            {
                ACEs[owner].Add("Owner");
            }
            else
            {
                ACEs.Add(owner, new List<string> { "Owner" });
            }

            string key;
            Match matchGPO = gpoRx.Match(targetDn);
            if (matchGPO.Success)
            {
                string gpoID = matchGPO.Groups[1].ToString().ToUpper();
                string gpoName = GPO.GroupPolicies[gpoID];
                key = gpoID + " " + gpoName;
            }
            else
            {
                key = targetDn;
            }
            return new DACL { ObjectName = key, ACEs = ACEs };
        }


        //Get interesting DACL if a target user has permission on it
        public static DACL GetMyInterestingACLOnObject(string targetDn, List<string> sidList)
        {
            logger.Debug($"Collecting Interesting ACLs on {targetDn}");

            var interestingACEs = new Dictionary<string, List<string>>();
            Regex gpoRx = new Regex(@"=(\{.+?\}),", RegexOptions.Compiled);


            var rules = GetAuthorizationRules(targetDn, out string ownerSID);
            if (rules == null) { return null; }

            //Adapted from https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L3746
            Regex rights = new Regex(@"(GenericAll)|(.*Write.*)|(.*Create.*)|(.*Delete.*)", RegexOptions.Compiled);
            //Regex replica = new Regex(@"(.*Replication.*)", RegexOptions.Compiled);

            //string[] dcsync = { "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set" };

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                var sid = rule.IdentityReference.ToString();
                
                if (sidList.Contains(sid) || sidList.Contains(ownerSID))
                {
                    string IR = Helper.SIDNameSID(sid);
                    string objType = rule.ObjectType.ToString();
                    string adRights = rule.ActiveDirectoryRights.ToString();

                    logger.Debug($"{targetDn}:{IR}: ADRights:  {adRights} ObjectType: {objType}");

                    //Ignore the following extended rights
                    //edacfd8f-ffb3-11d1-b41d-00a0c968f939 Apply-Group-Policy
                    //ab721a55-1e2f-11d0-9819-00aa0040529b Send-To
                    if ((rights.IsMatch(adRights) || adRights == "ExtendedRight") && 
                        rule.AccessControlType.ToString() == "Allow" && 
                        objType.ToLower() != "edacfd8f-ffb3-11d1-b41d-00a0c968f939" &&
                        objType.ToLower() != "ab721a55-1e2f-11d0-9819-00aa0040529b")
                    {
                        string userRights = null;

                        if ((adRights == "ExtendedRight") && rule.AccessControlType.ToString() == "Allow")
                        {
                            //The ObjectType GUID maps to an extended right registered in the current forest schema, then that specific extended right is granted
                            //Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf
                            userRights = Rights.ResolveRightsGuid(objType, true);
                        }
                        else
                        {
                            string schemaName = Rights.ResolveRightsGuid(objType, false);
                            userRights = schemaName + $" ({adRights})";
                        }

                        if (interestingACEs.ContainsKey(IR)) { interestingACEs[IR].Add(userRights); }
                        else { interestingACEs.Add(IR, new List<string> { userRights }); }
                    }
                }
            }
            //check owner
            string owner = Helper.SIDNameSID(ownerSID);
            if (interestingACEs.ContainsKey(owner)) { interestingACEs[owner].Add("Owner"); }

            string key;
            Match matchGPO = gpoRx.Match(targetDn);
            if (matchGPO.Success)
            {
                string gpoID = matchGPO.Groups[1].ToString().ToUpper();
                string gpoName = GPO.GroupPolicies[gpoID];
                key = gpoID + " " + gpoName;
            }
            else
            {
                key = targetDn;
            }
            if (interestingACEs == null || interestingACEs.Count == 0) { return null; }
            return new DACL { ObjectName = key, ACEs = interestingACEs };
        }




        //Get DACL for certificate authories, certificate templates
        public static DACL GetCSACL(string target, ActiveDirectorySecurity sec, out bool hasControlRights, bool getTemplateACL = false)
        {
            hasControlRights = false;

            var rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier));
            if (rules == null) { return null; }
            var ownerSID = sec.GetOwner(typeof(SecurityIdentifier)).ToString();
            var ACEs = new Dictionary<string, List<string>>();

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                string objType = rule.ObjectType.ToString();
                string sid = rule.IdentityReference.ToString();
                string IR = Helper.SIDNameSID(sid);
                string adRights = rule.ActiveDirectoryRights.ToString();

                if (rule.ActiveDirectoryRights.ToString().Contains("ExtendedRight"))
                {
                    //The ObjectType GUID maps to an extended right registered in the current forest schema, then that specific extended right is granted
                    //Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf

                    adRights = adRights.Replace("ExtendedRight" , $" [{Rights.ResolveRightsGuid(objType, true)} {rule.AccessControlType}]");
                }

                logger.Debug($"{target}:{IR}: ADRights: {adRights} ObjectType: {objType} AccessControlType: {rule.AccessControlType}");

                if (getTemplateACL)//Get ACL for certificate template
                {
                    if (rule.AccessControlType.ToString() == "Allow" && Helper.IsLowPrivSid(sid))
                    {
                        //If a low priv user has certain control over the template
                        if (((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                             || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                             || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                             //|| rule.ObjectType.ToString() == "0e10c968-78fb-11d2-90d4-00c04f79dc55" //Certificate-Enrollment
                             || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && objType == "00000000-0000-0000-0000-000000000000"))
                        {
                            hasControlRights = true;
                            if ( ACEs.ContainsKey(IR)){ACEs[IR].Add(adRights); }
                            else{ ACEs.Add(IR, new List<string> { adRights }); }
                        }
                        //If a low priv user can enroll
                        else if ((rule.ActiveDirectoryRights.ToString().Contains("ExtendedRight")) && (objType.ToLower() == "0e10c968-78fb-11d2-90d4-00c04f79dc55" || objType == "00000000-0000-0000-0000-000000000000"))
                        {
                            if (ACEs.ContainsKey(IR)) { ACEs[IR].Add(adRights); }
                            else { ACEs.Add(IR, new List<string> { adRights }); }
                        }
                    }
                }
                else//Get ACL for certificate authority
                {
                    string csRights = ((CertificationAuthorityRights)rule.ActiveDirectoryRights).ToString();
                    if (ACEs.ContainsKey(IR)) { ACEs[IR].Add(csRights); }
                    else { ACEs.Add(IR, new List<string> { csRights }); }
                }
            }

            if (ACEs.Count == 0) { return null; }

            string owner = Helper.SIDNameSID(ownerSID);
            if (ACEs.ContainsKey(owner)) { ACEs[owner].Add("Owner"); }
            else { ACEs.Add(owner, new List<string> { "Owner" }); }

            return new DACL {ObjectName = $"DACL on {target}", ACEs = ACEs };
        }




        public static List<DACL> ACLScan(string user, List<string> groupSIDs)
        {
            if (user == null) { return null; }

            var ACLList = new List<DACL>();

            //1. Locate the user
            var targetEntry = Searcher.GetResultEntry(new LDAPSearchString
            {
                DN = Searcher.LdapInfo.TargetSearchBase,
                Filter = $"(sAMAccountName={user})",
                Scope = SearchScope.Subtree
            });
            if (targetEntry == null) {return null; }

            var targetSid = new SecurityIdentifier((byte[])targetEntry.Attributes["objectsid"][0], 0).ToString();

            //2. Get user nested group sid
            
            groupSIDs.Add(targetSid);

            
            //Iterate all objects
            var partitions = new string[] { Searcher.LdapInfo.RootDN, Searcher.LdapInfo.ConfigDN, Searcher.LdapInfo.SchemaDN };

            if (Searcher.LdapInfo.TargetSearchBase != Searcher.LdapInfo.RootDN)
            {
                var allObjects = Searcher.GetResultEntries(new LDAPSearchString
                {
                    DN = Searcher.LdapInfo.TargetSearchBase,
                    Filter = "(ObjectCategory=*)",
                    Scope = SearchScope.Subtree
                });

                foreach (var obj in allObjects)
                {
                    var acl = GetMyInterestingACLOnObject(obj.DistinguishedName, groupSIDs);
                    if (acl != null)
                    {
                        ACLList.Add(acl);
                    }
                }
            }
            else
            {
                foreach (var partition in partitions)
                {
                    var allObjects = Searcher.GetResultEntries(new LDAPSearchString 
                    {
                        DN = partition,
                        Filter = "(ObjectCategory=*)",
                        Scope = SearchScope.Subtree
                    });

                    foreach (var obj in allObjects)
                    {
                        var acl = GetMyInterestingACLOnObject(obj.DistinguishedName, groupSIDs);
                        if (acl != null)
                        {
                            ACLList.Add(acl);
                        }
                    }
                }
            }

            return ACLList;
        }
    }
}
