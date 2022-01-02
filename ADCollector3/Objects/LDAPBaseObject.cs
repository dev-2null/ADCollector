using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    public class LDAPBaseObject : ILDAPObject
    {
        public string DistinguishedName { get; set; }
        public Dictionary<string, List<string>> Attributes { get; set; }
    }
}
