using System.DirectoryServices.Protocols;

namespace ADCollector3
{
    public interface ILDAPObject
    {
        string DistinguishedName { get; set; }
    }
}
