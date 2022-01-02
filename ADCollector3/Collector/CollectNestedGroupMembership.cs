using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    class CollectNestedGroupMembership : ICollector
    {
        Logger _logger { get; set; }
        //Dictionary<sAMAccountName, Dictionary<groupSID, groupName>>
        public static Dictionary<string, Dictionary<string, string>> UserSIDNameDictionary { get; set; } 

        public CollectNestedGroupMembership()
        {
            _logger = LogManager.GetCurrentClassLogger();
            UserSIDNameDictionary = new Dictionary<string, Dictionary<string, string>>();
        }


        public IResult Collect(SearchString searchstring)
        {
            NestedGMSearchString searchString = (NestedGMSearchString)searchstring;

            _logger.Debug($"Collecting Nested Group Membership for {searchString.SAMAccountName}");
            List<string> groupList = new List<string>();
            Dictionary<string, string> groupMap = new Dictionary<string, string>();

            string nameFilter = $"(sAMAccountName={searchString.SAMAccountName})";

            var ldapSearchString = new LDAPSearchString { DN = Searcher.LdapInfo.RootDN, Filter = nameFilter, Scope = SearchScope.Subtree };
            var resultEntry = Searcher.GetResultEntry(ldapSearchString);
            if (resultEntry == null) { return null; }

            using (var userEntry = (Searcher.GetDirectoryEntry(resultEntry.DistinguishedName)))
            {
                //https://www.morgantechspace.com/2015/08/active-directory-tokengroups-vs-memberof.html
                //Use RefreshCach to get the constructed attribute tokenGroups.
                userEntry.RefreshCache(new string[] { "tokenGroups" });

                foreach (byte[] sid in userEntry.Properties["tokenGroups"])
                {
                    string groupSID = new SecurityIdentifier(sid, 0).ToString();
                    string groupName = Helper.SIDNameSID(groupSID);
                    groupList.Add(groupName);
                    groupMap.Add(groupSID, groupName);
                }
            }
            
            //Somehow these groups are missing
            groupMap.Add("S-1-5-11", @"NT AUTHORITY\Authenticated Users");
            groupMap.Add("S-1-5-15", @"NT AUTHORITY\This Organization");
            UserSIDNameDictionary.Add(searchString.SAMAccountName.ToUpper(), groupMap);

            return new ListResult { Title = searchString.Title, Result = groupList};
        }

        //public static Dictionary<string, Dictionary<string, string>> GetUserSIDNameDictionary()
        //{
        //    return UserSIDNameDictionary;
        //}

    }
}
