using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    public class User : LDAPBaseObject
    {
        public Dictionary<string, List<string>> Properities { get; set; }

        public static User GetUserObject(SearchResultEntry resultEntry)
        {
            User user = new User { DistinguishedName = resultEntry.DistinguishedName, Properities = new Dictionary<string, List<string>>() };

            foreach (string attrName in resultEntry.Attributes.AttributeNames)
            {
                DirectoryAttribute attr = resultEntry.Attributes[attrName];
                List<string> attrList = new List<string>();

                if (attr[0] is string)
                {
                    for (int i = 0; i < attr.Count; i++)
                    {
                        attrList.Add(attr[i].ToString());
                    }
                }
                else if (attr[0] is byte[])
                {
                    if (IsSecurityDescriptorAttribute(attrName))
                    {
                        attrList = Helper.ConvertSecurityDescriptor(attr);
                    }
                    else
                    {
                        attrList = Helper.ConvertByteArrayToSID(attr);
                    }
                }
                user.Properities.Add(attrName, attrList);
            }
            return user;
        }

        public static bool IsSecurityDescriptorAttribute(string attribute)
        {
            string[] attributes = new string[] { "msds-allowedtoactonbehalfofotheridentity" };

            return attributes.Contains(attribute.ToLower());
        }
    }
}
