using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
//using Microsoft.GroupPolicy;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
//using System.DirectoryServices.ActiveDirectory.ActiveDirectoryPartition;


namespace ADCollector
{
    class Program
    {
        static void Main(string[] args)
        {
            //PrintBanner();
            Console.WriteLine();




            Domain currentDomain = Domain.GetCurrentDomain();

            Forest currentForest = Forest.GetCurrentForest();

            DirectoryEntry rootEntry = new DirectoryEntry("LDAP://rootDSE");

            string rootDn = (string)rootEntry.Properties["defaultNamingContext"].Value;





            ////Basic Info

            Console.WriteLine("[-]Current Domain:        {0}\n", currentDomain.Name);
            //int domainL = currentDomain.Name.Length;
            //int forestL = currentForest.Name.Length;
            //Console.WriteLine(domainL+ " -- " + forestL);

            Console.WriteLine("[-]Current Forest:        {0}\n", currentForest.Name);
            Console.WriteLine("___________________________________________________________________________\n");


            //Domains
            Console.WriteLine("[-]Domains in the current forest:\n");

            foreach (Domain d in currentForest.Domains)
            {
                Console.WriteLine(" * {0}\n", d.Name);
            }
            Console.WriteLine("___________________________________________________________________________\n");





            //DCs
            Console.WriteLine("[-]Domain Controllers in the current domain:\n");

            foreach (DomainController dc in currentDomain.FindAllDiscoverableDomainControllers())
            {
                try
                {
                    Console.WriteLine(" * {0}", dc.Name);
                    //if ((Int32)dc.GetDirectoryEntry().Properties["primaryGroupID"].Value == 516)
                    //{
                    //    Console.WriteLine(" * {0}  [Read-Only DC]", dc.Name);
                    //}
                    //else
                    //{
                    //    Console.WriteLine(" * {0}", dc.Name);
                    //}

                }
                catch (Exception e) { Console.WriteLine("Exception: "+e.Message); }
            }
            Console.WriteLine("___________________________________________________________________________\n");




            GetDomainTrust(currentDomain);
            GetForestTrust(currentForest);
            //GetUnconstrained(rootDn);
            //GetMSSQL(currentForest);
            //GetGPOs(currentDomain, rootDn);

            GetConfiAttri(rootEntry);




            Console.WriteLine();
        }



        //userAccountControl attribute ([MS-ADTS] section 2.2.16) TD flag 

        //[Flags]
        //public enum UACFlags
        //{
        //    SCRIPT = 0x1,
        //    ACCOUNT_DISABLE = 0x2,
        //    HOMEDIR_REQUIRED = 0x8,
        //    LOCKOUT = 0x10,
        //    PASSWD_NOTREQD = 0x20,
        //    PASSWD_CANT_CHANGE = 0x40,
        //    ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80,
        //    NORMAL_ACCOUNT = 0x200,
        //    INTERDOMAIN_TRUST_ACCOUNT = 0x800,
        //    WORKSTATION_TRUST_ACCOUNT = 0x1000,
        //    SERVER_TRUST_ACCOUNT = 0x2000,
        //    DONT_EXPIRE_PASSWD = 0x10000,
        //    SMARTCART_REQUIRED = 0x40000,
        //    TRUSTED_FOR_DELEGATION = 0x80000,
        //    NOT_DELEGATED = 0x100000,
        //    USE_DES_KEY_ONLY = 0x200000,
        //    DONT_REQUIRE_PREAUTH = 0x400000,
        //    PASSWORD_EXPIRED = 0x800000,
        //    TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000,
        //    NO_AUTH_DATA_REQUIRED = 0x2000000,
        //    PARTIAL_SECRETS_ACCOUNT = 0x4000000
        //}









        public static void PrintBanner()
        {
            Console.WriteLine(@"    _    ____   ____      _ _           _             ");
            Console.WriteLine(@"   / \  |  _ \ / ___|___ | | | ___  ___| |_ ___  _ __ ");
            Console.WriteLine(@"  / _ \ | | | | |   / _ \| | |/ _ \/ __| __/ _ \| '__|");
            Console.WriteLine(@" / ___ \| |_| | |__| (_) | | |  __/ (__| || (_) | |   ");
            Console.WriteLine(@"/_/   \_\____/ \____\___/|_|_|\___|\___|\__\___/|_|   ");
            Console.WriteLine();
        }



 
        //Domain trusts

        public static void GetDomainTrust(Domain currentDomain)
        {
            Console.WriteLine("[-]Trust Relationship in the current domain:\n");

            Console.WriteLine("{0,-30}{1,-30}{2,-15}{3,-20}\n", "Source", "Target", "TrustType", "TrustDirection");

            foreach (TrustRelationshipInformation trustInfo in currentDomain.GetAllTrustRelationships())
            {

                Console.Write("{0,-30}{1,-30}{2,-15}{3,-20}", trustInfo.SourceName, trustInfo.TargetName, trustInfo.TrustType, trustInfo.TrustDirection);

                if (currentDomain.GetSidFilteringStatus(trustInfo.TargetName))
                {
                    Console.WriteLine("[SID Filtering is enabled]\n");
                }
                else
                {
                    Console.WriteLine("[Not Filtering SIDs]\n");
                }
            }
            Console.WriteLine("___________________________________________________________________________\n");

        }



        //Forest trusts

        public static void GetForestTrust(Forest currentForest)
        {
            Console.WriteLine("[-]Trust Relationship in the current forest:\n");

            Console.WriteLine("{0,-30}{1,-30}{2,-15}{3,-20}\n", "Source", "Target", "TrustType", "TrustDirection");

            foreach (TrustRelationshipInformation trustInfo in currentForest.GetAllTrustRelationships())
            {
                Console.Write("{0,-30}{1,-30}{2,-15}{3,-20}", trustInfo.SourceName, trustInfo.TargetName, trustInfo.TrustType, trustInfo.TrustDirection);
                try
                {
                    if (currentForest.GetSidFilteringStatus(trustInfo.TargetName))
                    {
                        Console.WriteLine("[SID Filtering is enabled]\n");
                    }
                    else
                    {
                        Console.WriteLine("[Not Filtering SIDs]\n");
                    }
                }
                catch (Exception e) //Forest trust relationship does not exist???
                {
                    Console.WriteLine("Something wrong with SID filtering");
                    Console.WriteLine("Error: {0}\n",e.Message);
                }

            }
            Console.WriteLine("___________________________________________________________________________\n");
        }



        //Unconstrained Delegation

        public static void GetUnconstrained(string rootDn)
        {
            Console.WriteLine("[-]Unconstrained Delegation Accounts:");
            Console.WriteLine();

            DirectoryEntry entry = new DirectoryEntry("LDAP://" + rootDn);

            using (entry)
            {
                //Search accounts with TRUSTED_FOR_DELEGATION flag set
                string queryUncon = @"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))";//excluding DCs

                DirectorySearcher unconSearch = new DirectorySearcher(entry, queryUncon);

                unconSearch.PropertiesToLoad.Add("sAMAccountName");

                foreach (SearchResult sr in unconSearch.FindAll())
                {
                    Console.WriteLine(" * {0}\n\n   LDAP Path:    {1}\n", sr.Properties["sAMAccountName"][0], sr.Path.Replace("LDAP://", ""));
                }
            }

            //
            //string searchUser = @"(|(objectCategory=Computer)(&(objectCategory=person)(sAMAccountName=*)))";
            //DirectorySearcher ds = new DirectorySearcher(entry,searchUser);
            //foreach(SearchResult sr in ds.FindAll())
            //{
            //    try
            //    {
            //        UACFlags uac = (UACFlags)sr.GetDirectoryEntry().Properties["userAccountControl"].Value;
            //        if (uac.HasFlag(UACFlags.TRUSTED_FOR_DELEGATION))
            //        {
            //            Console.WriteLine(" * {0}",sr.Path.Replace("LDAP://",""));
            //        }
            //    }
            //    catch (Exception){}
            //}
        }




        //SPN Scanning to discover MSSQL in the forest

        public static void GetMSSQL(Forest currentForest)
        {

            string gcDn = "DC=" + currentForest.Name.Replace(".", ",DC=");

            DirectoryEntry gcEntry = new DirectoryEntry("GC://" + gcDn);

            string queryMSSQL = @"(servicePrincipalName=MSSQL*)";

            using (gcEntry)
            {
                DirectorySearcher mssqlSearch = new DirectorySearcher(gcEntry, queryMSSQL);
                //mssqlSearch.PropertiesToLoad

                foreach (SearchResult sr in mssqlSearch.FindAll())
                {
                    var SPNs = sr.Properties["servicePrincipalName"];

                    Console.WriteLine("_________________\nSAM Account Name: {0}", sr.Properties["sAMAccountName"][0]);

                    if (SPNs.Count > 1)
                    {
                        foreach (string spn in SPNs)
                        {
                            if (spn.Contains("MSSQL"))
                            {
                                Console.WriteLine(spn);
                                break;
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine(SPNs[0]);
                    }

                    Console.WriteLine();
                }
            }

        }



        //GPOs
        public static void GetGPOs(Domain currentDomain, string rootDn)
        {
            Console.WriteLine("[-] Group Policies in the current domain:\n");

            DirectoryEntry gpoEntry = new DirectoryEntry("LDAP://CN=Policies,CN=System," + rootDn);

            using (gpoEntry)
            {
                DirectoryEntries gpos = gpoEntry.Children;

                foreach (DirectoryEntry gpo in gpos)
                {
                    string gpoPath = "\\\\" + currentDomain.Name + "\\SYSVOL\\" + currentDomain.Name + "\\Policies\\" + gpo.Name.Replace("CN=", "");

                    Console.WriteLine(gpoPath);

                    foreach (FileSystemAccessRule fsar in File.GetAccessControl(gpoPath).GetAccessRules(true, true, typeof(NTAccount)))
                    {

                        string username = fsar.IdentityReference.Value;
                        string userRights = fsar.FileSystemRights.ToString();
                        //if (userRights.Contains())
                        string userAccessType = fsar.AccessControlType.ToString();
                        string ruleSource = fsar.IsInherited ? "Inherited" : "Explicit";
                        string rulePropagation = fsar.PropagationFlags.ToString();
                        string ruleInheritance = fsar.InheritanceFlags.ToString();
                        Console.WriteLine(username + "\n" + userRights + "\n" + userAccessType + "\n" + ruleSource + "\n" + rulePropagation + "\n" + ruleInheritance);
                        Console.WriteLine();
                    }

                    Console.WriteLine(" * GPO Name: {0}\n   {1}\n", gpo.Properties["displayName"][0].ToString(), gpo.Name);
                }
            }
            Console.WriteLine("___________________________________________________________________________\n");

        }


        //Hidden attributes from [MS-ADTS] Section 3.1.1.2.3
        //Search Flags  CF (fCONFIDENTIAL,0x00000080)
        public static void GetConfiAttri(DirectoryEntry rootEntry)
        {

            Console.WriteLine("[-] Confidential Attributes:\n");

            string schemaDn = (string)rootEntry.Properties["schemaNamingContext"].Value;

            DirectoryEntry schemaEntry = new DirectoryEntry("LDAP://" + schemaDn);

            using (schemaEntry)
            {
                //string category1Attribute = @"(&(objectCategory=attributeSchema)(systemFlags:1.2.840.113556.1.4.803:=16))";

                string confidential = @"(searchFlags:1.2.840.113556.1.4.803:=128)";

                DirectorySearcher confiSearch = new DirectorySearcher(schemaEntry, confidential);

                foreach (SearchResult sr in confiSearch.FindAll())
                {
                    Console.WriteLine(" * {0}",sr.Properties["Name"][0]);
                }
            }

            Console.WriteLine("___________________________________________________________________________\n");
        }




    }
}