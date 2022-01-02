using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ADCollector3
{
    public class GPO
    {
        private static Logger _logger { get; set; } = LogManager.GetCurrentClassLogger();
        public static Dictionary<string, string> WMIPolicies = new Dictionary<string, string>();
        public static Dictionary<string, string> GroupPolicies = new Dictionary<string, string>();
        public string OU { get; set; }
        public string Name { get; set; }
        public string GUID { get; set; }
        public bool IsEnforced { get; set; }

        public GPO()
        {
            
        }

        public static void GetAllGPOs()
        {
            GetWMIPolicies();

            _logger.Debug("Collecting GPOs");
            Regex filterRx = new Regex(@";(\{.+?\});", RegexOptions.Compiled);

            string gpoRootDN = "CN=Policies,CN=System," + Searcher.LdapInfo.RootDN;//"CN=System," + rootDn;
            string gpoForestDN = "CN=Policies,CN=System," + Searcher.LdapInfo.ForestDN;
            string[] gpoDNs = (Searcher.LdapInfo.RootDN != Searcher.LdapInfo.ForestDN) ?  new string[] { gpoRootDN, gpoForestDN } : new string[] { gpoRootDN };

            string gpoFilter = @"(objectCategory=groupPolicyContainer)";
            string[] gpoAttrs = { "displayName", "cn", "gPCWQLFilter", "nTSecurityDescriptor" };
            //string extrightsDn = "CN=Extended-Rights,CN=Configuration," + forestDn;

            try
            {
                foreach (string gpodn in gpoDNs)
                {
                    _logger.Debug($"Enumerateing GPOs in {gpodn}");

                    var gpoEntries = Searcher.GetResultEntries(new LDAPSearchString {DN = gpodn, Filter = gpoFilter, ReturnAttributes = gpoAttrs, Scope = SearchScope.Subtree }).ToList();

                    foreach (var entry in gpoEntries)
                    {
                        string dn = entry.Attributes["cn"][0].ToString().ToUpper();
                        string displayname = entry.Attributes["displayName"][0].ToString().ToUpper();

                        //WMI Filtering
                        if (entry.Attributes.Contains("gPCWQLFilter"))
                        {
                            string filterAttr = entry.Attributes["gPCWQLFilter"][0].ToString();
                            //Could be empty " "
                            if (filterAttr.Length > 2)
                            {
                                Match filterM = filterRx.Match(filterAttr);
                                string filter = filterM.Groups[1].ToString();
                                string wmiName = WMIPolicies[filter];
                                displayname += "   [EvaluateWMIPolicy: " + wmiName + " - " + filter + "]";
                            }
                        }
                        if (!GroupPolicies.ContainsKey(dn)) { GroupPolicies.Add(dn, displayname); }
                    }
                }
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
            }
        }



        public static void GetWMIPolicies()
        {
            _logger.Debug("Collecting WMI Policies");

            string wmiRootDn = "CN=SOM,CN=WMIPolicy,CN=System," + Searcher.LdapInfo.RootDN;
            string wmiForestDn = "CN=SOM,CN=WMIPolicy,CN=System," + Searcher.LdapInfo.ForestDN;
            string[] wmiDNs = (Searcher.LdapInfo.RootDN != Searcher.LdapInfo.ForestDN) ? new string[] { wmiRootDn, wmiForestDn } : new string[] { wmiRootDn };

            string wmiFilter = @"(objectClass=msWMI-Som)";
            string[] wmiAttrs = { "msWMI-Name", "msWMI-ID"};

            foreach(var wmiDn in wmiDNs)
            {
                var resultEntries = Searcher.GetResultEntries(new LDAPSearchString { DN = wmiDn, Filter = wmiFilter, ReturnAttributes = wmiAttrs, Scope = SearchScope.Subtree }).ToList();
                
                foreach (var entry in resultEntries)
                {
                    WMIPolicies.Add(entry.Attributes["msWMI-ID"][0].ToString().ToUpper(), entry.Attributes["msWMI-Name"][0].ToString());
                }
            }
        }


        public static List<string> GetAllGPODNList()
        {
            return GroupPolicies.Keys.Select(gpo => $"CN={gpo},CN=Policies,CN=System,{Searcher.LdapInfo.RootDN}").ToList();
        }

    }
}
