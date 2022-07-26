using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    public class SchemaUtil
    {
        public static Logger logger { get; set; } = LogManager.GetCurrentClassLogger();
        public static List<string> GetSchemaAttributes()
        {
            List<string> attributes = new List<string>();

            var ldapInfo = Searcher.LdapInfo;
            var schemaEntries = Searcher.GetResultEntries(new LDAPSearchString
            {
                DN = ldapInfo.SchemaDN,
                Filter = "(ldapdisplayname=*)",
                Scope = SearchScope.Subtree,
                ReturnAttributes = new string[] { "ldapdisplayname" }
            }).ToList();

            foreach (SearchResultEntry entry in schemaEntries)
            {
                attributes.Add(entry.Attributes["ldapdisplayname"][0].ToString());
            }

            return attributes;
        }

        //Get rid of some common attributes that are applied on most of the AD objects
        //Also some attributes that are not applied to the matching rule
        public static List<string> GetUncommonSchemaAttributes(List<string> attributes)
        {
            List<string> uncommonAttributes = new List<string>();
            string[] commonAttrs = new string[] { "msds-supportedencryptiontypes", "operatingsystem", "operatingsystemversion", "lastlogontimestamp", "o", "primarygroupid", "pwdlastset", "accountexpires", "objectsid", "ntsecuritydescriptor", "distinguishedname", "objectclass", "objectcategory", "objectguid", "badpasswordtime", "badpwdcount", "mail", "codepage", "name", "replpropertymetadata", "showinadvancedviewonly", "countrycode", "mobile", "displayname", "serviceprincipalname", "dnshostname", "sn", "samaccountname", "givenname", "cn", "samaccounttype", "createtimestamp", "iscriticalsystemobject", "grouptype", "userprincipalname", "lastlogoff", "useraccountcontrol", "dscorepropagationdata", "lastlogon", "memberof", "localpolicyflags", "l", "lockouttime", "division", "department", "employeeid", "instancetype", "company", "usncreated", "usnchanged", "member", "msds-authenticatedatdc", "whenchanged", "whencreated", "modifytimestamp", "msds-parentdistname", "usercertificate",
            "msds-isrodc","msds-keyversionnumber","msds-resultantpso","entryttl","msds-sitename","msds-topquotausage","msds-principalname","msds-quotaeffective","msds-quotaused","msds-ncreplcursors","msds-ncreplinboundneighbors","msds-ncreploutboundneighbors","msds-replvaluemetadata","msds-replattributemetadata","msds-tokengroupnames","msds-userpasswordexpirytimecomputed","msds-tokengroupnamesglobalanduniversal","msds-user-account-control-computed","msds-tokengroupnamesnogcacceptable","msds-revealedlist","msds-isusercachableatrodc","msds-revealedlistbl","objectclasses","parentguid","possibleinferiors","primarygrouptoken","allowedattributes","allowedchildclasses","allowedattributeseffective","allowedchildclasseseffective","tokengroups","tokengroupsglobalanduniversal","tokengroupsnogcacceptable","attributetypes","canonicalname","sdrightseffective","ditcontentrules","structuralobjectclass","msds-managedpassword","extendedattributeinfo","subschemasubentry","extendedclassinfo","fromentry","msds-memberoftransitive","msds-membertransitive","msds-replvaluemetadataext","msds-auxiliary-classes","msds-approx-immed-subordinates","msds-localeffectiverecycletime","msds-localeffectivedeletiontime","msds-isgc"};
            foreach (var attribute in attributes)
            {
                string attr = attribute.ToLower();
                if (!commonAttrs.Contains(attr))
                {
                    uncommonAttributes.Add(attr);
                }
            }
            return uncommonAttributes;
        }


        //Only search in the default naming context
        public static string GetAttributeCount(string attr)
        {
            logger.Debug($"Counting attribute {attr}");
            var ldapInfo = Searcher.LdapInfo;

            var schemaEntries = Searcher.GetResultEntries(new LDAPSearchString
            {
                DN = ldapInfo.RootDN,
                Filter = $"({attr}=*)",
                Scope = SearchScope.Subtree,
                ReturnAttributes = new string[] { "cn" },
                PageSize = 1000
            });//.ToList();

            var attrCount = schemaEntries.Count();

            logger.Debug($"{attr}:{attrCount}");
            return attrCount > 0 ? $"{attr}:{attrCount}" : null;
        }
    }
}
