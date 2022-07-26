using System.DirectoryServices.Protocols;

namespace ADCollector3
{
    public class LDAPSearchString : SearchString
    {
        public string Title { get; set; }
        public string DN { get; set; }
        public string Filter { get; set; }
        public string[] ReturnAttributes { get; set; }
        public SearchScope Scope { get; set; }
        public bool UseGlobalCatalog { get; set; }
        public int PageSize = 500;

    }
}
