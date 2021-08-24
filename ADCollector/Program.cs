using System;
using CommandLine;

namespace ADCollector
{
    public class MainClass
    {

        public static void Main(string[] args)
        {
            Printer.PrintBanner();

            Options options = new Options();
            
            if (!Parser.Default.ParseArguments(args, options)) { return; }

            Collector adc = new Collector(options);

            if (options.Choice != 0)
            {
                adc.InteraciveMenu(options.Choice, options.Param);
                Environment.Exit(0);
            }

            if (options.Interactive)
            {
                adc.InteraciveMenu();
            }
            else
            {
                
                adc.Run();
            }

            Console.WriteLine();
        }
    }




    public class Options
    {
        [Option("Domain", DefaultValue = null, HelpText = "Domain to enumerate", MutuallyExclusiveSet = "DomainOption")]
        public string Domain { get; set; }

        [Option("LDAPS", DefaultValue = false, HelpText = "LDAP over SSL/TLS")]
        public bool Ldaps { get; set; }

        [Option("DisableSigning", DefaultValue = false, HelpText = "Disable Kerberos Encryption (with -LDAPS flag)")]
        public bool DisableSigning { get; set; }

        [Option("UserName", DefaultValue = null, HelpText = "Alternative UserName")]
        public string Username { get; set; }

        [Option("Password", DefaultValue = null, HelpText = "Alternative Credential")]
        public string Password { get; set; }

        [Option("DC", DefaultValue = null, HelpText = "Alternative Domain Controller (Hostname/IP) to connect to")]
        public string DC { get; set; }

        [Option("OU", DefaultValue = null, HelpText = "Perform the Search under a specific Organizational Unit")]
        public string OU { get; set; }

        [Option("ACLScan", DefaultValue = false, HelpText = "Perform ACL scan for an Identity")]
        public bool ACLScan { get; set; }

        [Option("ADCS", DefaultValue = false, HelpText = "Perform AD Certificate Service Check")]
        public bool ADCS { get; set; }

        [Option("Identity", DefaultValue = null, HelpText = "The Identity for ACL scan")]
        public string Identity { get; set; }

        [Option("Interactive", DefaultValue = null, HelpText = "Enter Interactive Menu")]
        public bool Interactive { get; set; }

        [Option("Choice", DefaultValue = 0, HelpText = "Select an Interactive Choice Directly")]
        public int Choice { get; set; }

        [Option("Param", DefaultValue = null, HelpText = "Parameter for Interactive Options")]
        public string Param { get; set; }

        [HelpOption]
        public string GetHelp()
        {
            var help = @"
Usage: ADCollector.exe -h
    
    --Domain (Default: current domain)
            Enumerate the specified domain
    --Ldaps (Default: LDAP)
            Use LDAP over SSL/TLS
    --DiableSigning (Default: Enabled)
            With --Ldaps
    --DC (IP Address of the Domain Controller)
    --OU (Search under an Organizational Unit)
    --ADCS (Enumerate certificate services)
    --ACLScan (Perform ACL scan against all objects in Domain/Configuration/Schema partitions if no OU is provided)
    --Identity (The Identity used for ACL Scan)
    --UserName (Alternative UserName to Connect LDAP)
    --Password (Alternative LDAP Credential)
    --Interactive (Enter Interactive Menu)
    --Choice (Command Line Option For Interactive Menu)    
    --Param (Parameter Value For Options in Interactive Menu)
Example: .\ADCollector.exe
         .\ADCollector.exe --LDAPs --DisableSigning
         .\ADCollector.exe --OU IT
         .\ADCollector.exe --OU OU=IT,DC=domain,DC=local
         .\ADCollector.exe --ADCS
         .\ADCollector.exe --ACLScan --Identity user --OU OU=IT,DC=domain,DC=local
         .\ADCollector.exe --Domain domain.local --Username user --Password pass
         .\ADCollector.exe --Domain domain.local --DC 10.10.10.1
         .\ADCollector.exe --Domain domain.local --Choice 1
         .\ADCollector.exe --Domain domain.local --Choice 3 --Param mssql*

Interactive Menu:
    ===================================
                Interative Menu          
    0.  - EXIT
    1.  - Collect LDAP DNS Records
    2.  - Find Single LDAP DNS Record
    3.  - SPN Scan
    4.  - Find Nested Group Membership
    5.  - Search Interesting Term on User Description Fields
    6.  - Enumerate Interesting ACLs on an Object
    7.  - NetSessionEnum
    8.  - NetLocalGroupGetMembers
    9.  - NetWkstaUserEnum
    ===================================
";
            return help;
        }

    }
}
