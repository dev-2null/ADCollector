using CommandLine;

namespace ADCollector3
{
    public class Options
    {
        public static Options Instance { get; set; }

        [Option("Domain", Default = null, HelpText = "Domain to enumerate")]
        public string Domain { get; set; }

        [Option("LDAPS", Default = false, HelpText = "LDAP over SSL/TLS")]
        public bool Ldaps { get; set; }

        [Option("DisableSigning", Default = false, HelpText = "Disable Kerberos Encryption (with -LDAPS flag)")]
        public bool DisableSigning { get; set; }

        [Option("UserName", Default = null, HelpText = "Alternative UserName")]
        public string Username { get; set; }

        [Option("Password", Default = null, HelpText = "Alternative Credential")]
        public string Password { get; set; }

        [Option("DC", Default = null, HelpText = "Alternative Domain Controller (Hostname/IP) to connect to")]
        public string DC { get; set; }

        [Option("OU", Default = null, HelpText = "Perform the Search under a specific Organizational Unit")]
        public string OU { get; set; }

        [Option("LDAPONLY", Default = false, HelpText = "Only Enumerate LDAP")]
        public bool LDAPONLY { get; set; }

        [Option("ACLScan", Default = null, HelpText = "Perform ACL scan for an Identity")]
        public string ACLScan { get; set; }

        [Option("ADCS", Default = false, HelpText = "Only Perform AD Certificate Service Check")]
        public bool ADCS { get; set; }

        [Option("TEMPLATES", Default = false, HelpText = "Only Enumerate All AD Certificate Templates")]
        public bool TEMPLATES { get; set; }

        [Option("ADIDNS", Default = false, HelpText = "Only Collect ADIDNS Records")]
        public bool ADIDNS { get; set; }

        [Option("NGAGP", Default = null, HelpText = "Only enumerate Nested Group Membership and Applied Group Policies on the target object")]
        public string NGAGP { get; set; }

        [Option("SCHEMA", Default = false, HelpText = "Count all attributes in the Schema")]
        public bool SCHEMA { get; set; }

        [Option("DACL", Default = null, HelpText = "Enumerate DACL on the target object (with DistinguishedName)")]
        public string DACL { get; set; }

        [Option("SessionEnum", Default = false, HelpText = "Enumerate session information on the target host")]
        public bool SessionEnum { get; set; }

        [Option("UserEnum", Default = false, HelpText = "Enumerate user information on the target host")]
        public bool UserEnum { get; set; }

        [Option("LocalGMEnum", Default = false, HelpText = "Enumerate local group members on the target host")]
        public bool LocalGMEnum { get; set; }

        [Option("Host", Default = "Localhost", HelpText = "Hostname for Session/User/Groupmember Enumeration")]
        public string Host { get; set; }

        [Option("Group", Default = "Administrators", HelpText = "Local Group Name for Local GroupMember Enumeration")]
        public string Group { get; set; }

        [Option("Debug", Default = false, HelpText = "Debug Mode")]
        public bool Debug { get; set; }

        public static void GetHelp()
        {
            var help = @"
  --Domain            Domain to enumerate
  --LDAPS             (Default: false) LDAP over SSL/TLS
  --DisableSigning    (Default: false) Disable Kerberos Encryption (with -LDAPS flag)
  --UserName          Alternative UserName
  --Password          Alternative Credential
  --DC                Alternative Domain Controller (Hostname/IP) to connect to
  --OU                Perform the Search under a specific Organizational Unit
  --LDAPONLY          Only Enumearte Objects in LDAP
  --ACLScan           Perform ACL scan for an Identity
  --ADCS              (Default: false) Only Perform AD Certificate Service Check
  --TEMPLATES         (Default: false) Only Enumerate All Certificate Templates with their DACL
  --SCHEMA            (Default: false) Count Schema Attributes in the default naming context
  --ADIDNS            (Default: false) Only Collect ADIDNS Records
  --NGAGP             Only enumerate Nested Group Membership and Applied Group Policies on the target object
  --DACL              Enumerate DACL on the target object (with DistinguishedName)
  --SessionEnum       (Default: false) Enumerate session information on the target host
  --UserEnum          (Default: false) Enumerate user information on the target host
  --LocalGMEnum       (Default: false) Enumerate local group members on the target host
  --Host              (Default: Localhost) Hostname for Session/User/Groupmember Enumeration
  --Group             (Default: Administrators) Local Group Name for Local GroupMember Enumeration
  --Debug             (Default: false) Debug Mode
  --help              Display this help screen.

Example: .\ADCollector.exe
         .\ADCollector.exe --LDAPs --DisableSigning
         .\ADCollector.exe --OU IT
         .\ADCollector.exe --OU OU=IT,DC=domain,DC=local
         .\ADCollector.exe --ADCS
         .\ADCollector.exe --TEMPLATES
         .\ADCollector.exe --LDAPOnly
         .\ADCollector.exe --SCHEMA
         .\ADCollector.exe --ADIDNS
         .\ADCollector.exe --NGAGP samaccountname
         .\ADCollector.exe --DACL DC=domain,DC=net
         .\ADCollector.exe --ACLScan user --OU OU=IT,DC=domain,DC=local
         .\ADCollector.exe --SessionEnum --Host targetHost
         .\ADCollector.exe --UserEnum --Host targetHost
         .\ADCollector.exe --LocalGMEnum --Host targetHost --Group 'Remote Desktop Users'
         .\ADCollector.exe --Domain domain.local --Username user --Password pass
         .\ADCollector.exe --Domain domain.local --DC 10.10.10.1
";
            System.Console.WriteLine(help);
        }
    }
}
