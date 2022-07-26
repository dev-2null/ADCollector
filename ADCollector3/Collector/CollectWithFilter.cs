using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Numerics;
using System.Security.Principal;
using static ADCollector3.Helper;

namespace ADCollector3
{
    public class CollectWithFilter : ICollector
    {
        public LDAPResult CollectResult { get; set; }
        Logger _logger;
        public CollectWithFilter()
        {
            _logger = LogManager.GetCurrentClassLogger();
        }
        public IResult Collect(SearchString searchstring)
        {
            _logger.Debug($"Collecting");
            LDAPSearchString searchString = (LDAPSearchString)searchstring;
            List<ILDAPObject> ldapObjects = new List<ILDAPObject>();

            var results = Searcher.GetResultEntries(searchString).ToList();
            
            foreach (var result in results)
            {
                //If we need User
                if (searchString.ReturnAttributes.Contains("sAMAccountName"))
                {
                    var user = User.GetUserObject(result);
                    ldapObjects.Add(user);
                }
                else
                {
                    ldapObjects.Add(new LDAPBaseObject { Attributes = ProcessAttributes(result.Attributes), DistinguishedName = result.DistinguishedName });
                }
            }

            CollectResult = new LDAPResult { LDAPObjects = ldapObjects, Title = searchstring.Title };

            _logger.Debug("LDAP Objects Collected");
            return CollectResult;
        }


        //Convert special type attributes to user friendly string
        public static Dictionary<string, List<string>> ProcessAttributes(SearchResultAttributeCollection collection)
        {
            Dictionary<string, List<string>> attributes = new Dictionary<string, List<string>>();


            foreach (string attrName in collection.AttributeNames)
            {
                List<string> attributeValue = new List<string>();
                if (attrName.ToLower() == "whencreated" || attrName.ToLower() == "whenchanged")
                {
                    attributeValue.Add(ConvertWhenCreated(collection[attrName][0].ToString()).ToString());
                }
                else if (attrName.ToLower() == "maxpwdage")
                {
                    attributeValue.Add(ConvertLargeInteger(collection[attrName][0].ToString(), true));
                }
                else if (attrName.ToLower() == "lockoutduration")
                {
                    attributeValue.Add(ConvertLargeInteger(collection[attrName][0].ToString(), false));
                }
                else if (attrName.ToLower() == "objectsid" || attrName.ToLower() == "securityidentifier")
                {
                    attributeValue.Add(ConvertByteArrayToSID((byte[])collection[attrName][0]));
                }
                else if (attrName.ToLower() == "userpassword" || attrName.ToLower() == "unixuserpassword" 
                    || attrName.ToLower() == "unicodepwd" || attrName.ToLower() == "mssfu30password" 
                    || attrName.ToLower() == "os400-password")
                {
                    attributeValue.Add(ConvertAscii(collection[attrName]));
                }
                else
                {
                    for (int i = 0; i < collection[attrName].Count; i++)
                    {
                        attributeValue.Add(collection[attrName][i].ToString());
                    }
                }
                attributes.Add(attrName, attributeValue);
            }

            return attributes;
        }


    }
}
