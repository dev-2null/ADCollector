using System.Collections.Generic;

namespace ADCollector3
{
    public class LDAPResult : IResult
    {
        public string Title { get; set; }
        public List<ILDAPObject> LDAPObjects { get; set; }
    }
}
