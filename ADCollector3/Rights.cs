using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    public static class Rights
    {
        public static Dictionary<string, string> ExtendedRightsList { get; set; } = new Dictionary<string, string>();
        public static Dictionary<string, string> SchemaList { get; set; } = new Dictionary<string, string>();

        static Logger _logger { get; set; } = LogManager.GetCurrentClassLogger();

        public static void BuildExtendedRightsDict()
        {
            _logger.Debug("Building an Extended Rights List");
            string extendedRightsDn = "CN=Extended-Rights," + Searcher.LdapInfo.ConfigDN;

            var rightsResult = Searcher.GetResultEntries(new LDAPSearchString
            {
                DN = extendedRightsDn,
                Filter = "(rightsGuid=*)",
                ReturnAttributes = new string[] { "rightsGuid", "cn" },
                Scope = SearchScope.Subtree,
                //UseGlobalCatalog = true
            }).ToList();

            foreach (var rights in rightsResult)
            {
                //Ignore duplicated rightsGuid DNS-Host-Name-Attributes & Validated-DNS-Host-Name: "72e39547-7b18-11d1-adef-00c04fd8d5cd"
                string rightsGuid = rights.Attributes["rightsGuid"][0].ToString().ToLower();

                if (rightsGuid == "72e39547-7b18-11d1-adef-00c04fd8d5cd") { continue; }

                ExtendedRightsList.Add(rightsGuid, rights.Attributes["cn"][0].ToString());

            }
            ExtendedRightsList.Add("72e39547-7b18-11d1-adef-00c04fd8d5cd", "DNS-Host-Name-Attributes & Validated-DNS-Host-Name");
            ExtendedRightsList.Add("aa4e1a6d-550d-4e05-8c35-4afcb917a9fe", "ms-TPM-OwnerInformation");
            ExtendedRightsList.Add("00000000-0000-0000-0000-000000000000", "All");
        }



        public static void BuildSchemaDict()
        {
            _logger.Debug("Building an Schema List");

            var rightsResult = Searcher.GetResultEntries(new LDAPSearchString
            {
                DN = Searcher.LdapInfo.SchemaDN,
                Filter = "(schemaIDGUID=*)",
                ReturnAttributes = new string[] { "schemaIDGUID", "cn" },
                Scope = SearchScope.OneLevel,
                //UseGlobalCatalog = true
            }).ToList();

            foreach (var rights in rightsResult)
            {
                string schemaGUID = Helper.GetStringFromByte((byte[])rights.Attributes["schemaIDGUID"][0]).ToLower();

                SchemaList.Add(schemaGUID, rights.Attributes["cn"][0].ToString());
            }
            SchemaList.Add("00000000-0000-0000-0000-000000000000", "All properties");
            // Active Directory includes predefined property sets:
            // https://docs.microsoft.com/en-us/windows/desktop/adschema/property-sets
            var predefinedProp = new Dictionary<string, string>();
            predefinedProp.Add("72e39547-7b18-11d1-adef-00c04fd8d5cd", "DNS Host Name Attributes");
            predefinedProp.Add("b8119fd0-04f6-4762-ab7a-4986c76b3f9a", "Other Domain Parameters");
            predefinedProp.Add("c7407360-20bf-11d0-a768-00aa006e0529", "Domain Password and Lockout Policies");
            predefinedProp.Add("e45795b2-9455-11d1-aebd-0000f80367c1", "Phone and Mail Options");
            predefinedProp.Add("59ba2f42-79a2-11d0-9020-00c04fc2d3cf", "General Information");
            predefinedProp.Add("bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "Group Membership");
            predefinedProp.Add("ffa6f046-ca4b-4feb-b40d-04dfee722543", "MS-TS-GatewayAccess");
            predefinedProp.Add("77b5b886-944a-11d1-aebd-0000f80367c1", "Personal Information");
            predefinedProp.Add("91e647de-d96f-4b70-9557-d63ff4f3ccd8", "Private Information");
            predefinedProp.Add("e48d0154-bcf8-11d1-8702-00c04fb96050", "Public Information");
            predefinedProp.Add("5805bc62-bdc9-4428-a5e2-856a0f4c185e", "Terminal Server License Server");
            predefinedProp.Add("4c164200-20c0-11d0-a768-00aa006e0529", "Account Restrictions");
            predefinedProp.Add("5f202010-79a5-11d0-9020-00c04fc2d4cf", "Logon Information");
            predefinedProp.Add("e45795b3-9455-11d1-aebd-0000f80367c1", "Web Information");
            predefinedProp.Add("9b026da6-0d3c-465c-8bee-5199d7165cba", "DS-Validated-Write-Computer");
            predefinedProp.Add("037088f8-0ae1-11d2-b422-00a0c968f939", "RAS-Information");
            foreach(var prop in predefinedProp)
            {
                if (!SchemaList.ContainsKey(prop.Key))
                {
                    SchemaList.Add(prop.Key, prop.Value);
                }
            }
            
        }

        //It does not work well with Task
        public static string ResolveRightsGuid(string rightsGuid, bool isExtendedRights = true)
        {
            if (isExtendedRights)
            {
                if (ExtendedRightsList.ContainsKey(rightsGuid.ToLower()))
                {
                    return ExtendedRightsList[rightsGuid.ToLower()];
                }
                //ms-TPM-OwnerInformation:aa4e1a6d-550d-4e05-8c35-4afcb917a9fe (this is a schema attribute...)
                else 
                {
                    _logger.Warn($"{rightsGuid} is extended rights but cannot be resolved");
                    return rightsGuid; 
                }
            }
            else
            {
                if (SchemaList.ContainsKey(rightsGuid.ToLower()))
                {
                    return SchemaList[rightsGuid.ToLower()];
                }
                else
                {
                    _logger.Warn($"{rightsGuid} is a schema attribute but cannot be resolved");
                    return rightsGuid;
                }
            }

            //string partition = isExtendedRights ? "CN=Extended-Rights,CN=Configuration," : "CN=Schema,CN=Configuration,";
            //string partition = "CN=Schema,CN=Configuration,";

            //No SPACE near "="
            //From The .Net Developer Guide to Directory Services Programming Searching for Binary Data

            //resolve schema attributes / extended rights
            //string searchFilter = isExtendedRights ? @"(rightsGuid=" + rightsGuid + @")" :
            //    @"(schemaIDGUID=" + BuildFilterOctetString(new Guid(rightsGuid).ToByteArray()) + @")";

        }



    }
}
