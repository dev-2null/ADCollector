using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
//using Microsoft.GroupPolicy;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
//using System.DirectoryServices.ActiveDirectory.ActiveDirectoryPartition;
using ConsoleTables;

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
            //Domain Entry
            DirectoryEntry entry = new DirectoryEntry("LDAP://" + rootDn);


            string forestDn = "DC=" + currentForest.Name.Replace(".", ",DC=");
            //Forest Entry
            DirectoryEntry forestEntry = new DirectoryEntry("LDAP://" + forestDn);



            ////Basic Info

            Console.WriteLine("[-] Current Domain:        {0}\n", currentDomain.Name);
            //int domainL = currentDomain.Name.Length;
            //int forestL = currentForest.Name.Length;
            //Console.WriteLine(domainL+ " -- " + forestL);

            Console.WriteLine("[-] Current Forest:        {0}\n", currentForest.Name);
            Console.WriteLine("___________________________________________________________________________\n");


            //Domains
            Console.WriteLine("[-] Domains in the current forest:\n");

            foreach (Domain d in currentForest.Domains)
            {
                Console.WriteLine(" * {0}", d.Name);

                //Console.WriteLine("DomainMode: {0}\n",d.DomainMode);
                DirectoryEntry dEntry = d.GetDirectoryEntry();

                using (dEntry)
                {
                    var objectSid = (byte[])dEntry.Properties["objectSid"][0];

                    var domainSID = new SecurityIdentifier(objectSid,0);

                    Console.WriteLine("   Domain SID:   "+ domainSID.ToString());

                    Console.WriteLine();
                    //var domainSID = new SecurityIdentifier(dEntry.Properties["objectSid"].Value);//.ObjectSecurity.);
                }
            }
            Console.WriteLine("___________________________________________________________________________\n");

            //$ADDomainSid = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0],0)
            //$ADDomainSid.Value






            GetDomainTrust(currentDomain);
            GetForestTrust(currentForest);
            GetUnconstrained(entry);
            GetMSSQL(currentForest);
            GetGPOs(currentDomain, rootDn);
            GetConfiAttri(rootEntry);
            GetDCs(currentDomain);
            GetPrivUsers(entry, forestEntry);



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

 

        /// <summary>
        /// Gets the DC.
        /// </summary>
        /// <param name="currentDomain">Current domain.</param>
        public static void GetDCs(Domain currentDomain)
        {
            //DCs
            Console.WriteLine("[-] Domain Controllers in the current domain:\n");

            //foreach (DomainController dc in currentDomain.FindAllDomainControllers())
            foreach (DomainController dc in currentDomain.FindAllDiscoverableDomainControllers())
            {
                try
                {
                    string DCType = "";

                    if (dc.IsGlobalCatalog())
                    {
                        DCType += "[Global Catalog] ";
                    }

                    using (DirectoryEntry dcServerEntry = dc.GetDirectoryEntry())
                    {
                        //Console.WriteLine(dcEntry.Properties["primaryGroupID"].Value);
                        //Exception: Object reference not set to an instance of an object

                        //https://stackoverflow.com/questions/34925136/why-property-primarygroupid-missing-for-domain-controller
                        //dc.GetDirectoryEntry() returns a server object, not the computer object of DC
                        //primaryGroupID does not exist on server object

                        using (DirectoryEntry dcEntry = new DirectoryEntry("LDAP://" + dcServerEntry.Properties["serverReference"].Value))
                        {
                            //Check if the primaryGroupID attribute has a value of 521 (Read-Only Domain Controller)
                            if ((int)dcEntry.Properties["primaryGroupID"].Value == 521)
                            {
                                DCType += "[Read-Only Domain Controller]";
                            }
                        }
                    }

                    Console.WriteLine(" * {0}  {1}", dc.Name, DCType);
                    Console.WriteLine("   IPAddress\t\t\t:  {0}", dc.IPAddress);
                    Console.WriteLine("   OS\t\t\t\t:  {0}", dc.OSVersion);
                    Console.WriteLine("   Site\t\t\t\t:  {0}", dc.SiteName);

                    //string partitions = "";
                    //foreach (var partition in dc.Partitions)
                    //{
                    //    partitions += partition +"   ";
                    //}
                    //Console.WriteLine("   Partitions\t\t\t:  {0}",partitions);

                    string roles = "";

                    foreach (var role in dc.Roles)
                    {
                        roles += role + "   ";
                    }
                    Console.WriteLine("   Roles\t\t\t:  {0}", roles);

                    Console.WriteLine();

                }
                catch (Exception)
                {
                    Console.WriteLine(" * {0}:  RPC server is unavailable.", dc.Name);
                    //Console.WriteLine("Exception: "+e.Message); 
                }
            }
            Console.WriteLine("___________________________________________________________________________\n");

        }




        //Domain trusts
        /// <summary>
        /// Gets the domain trust.
        /// </summary>
        /// <param name="currentDomain">Current domain.</param>
        public static void GetDomainTrust(Domain currentDomain)
        {
            Console.WriteLine("[-] Trust Relationship in the current domain:\n");

            //https://github.com/khalidabuhakmeh/ConsoleTables/blob/master/src/ConsoleTables/ConsoleTable.cs

            var domtable = new ConsoleTable("Source", "Target", "TrustType", "TrustDirection","SID Filtering");

            var sidStatus = "";

            //Console.WriteLine("{0,-30}{1,-30}{2,-15}{3,-20}\n", "Source", "Target", "TrustType", "TrustDirection");

            foreach (TrustRelationshipInformation trustInfo in currentDomain.GetAllTrustRelationships())
            {
                if (currentDomain.GetSidFilteringStatus(trustInfo.TargetName))
                {
                    sidStatus = "[SID Filtering is enabled]\n";
                }
                else
                {
                    sidStatus = "[Not Filtering SIDs]\n";
                }

                domtable.AddRow(trustInfo.SourceName, trustInfo.TargetName, trustInfo.TrustType, trustInfo.TrustDirection,sidStatus);

                //Console.Write("{0,-30}{1,-30}{2,-15}{3,-20}", trustInfo.SourceName, trustInfo.TargetName, trustInfo.TrustType, trustInfo.TrustDirection);

                //if (currentDomain.GetSidFilteringStatus(trustInfo.TargetName))
                //{
                //    Console.WriteLine("[SID Filtering is enabled]\n");
                //}
                //else
                //{
                //    Console.WriteLine("[Not Filtering SIDs]\n");
                //}
            }

            Console.WriteLine(domtable);
            Console.WriteLine("___________________________________________________________________________\n");

        }



        //Forest trusts
        /// <summary>
        /// Gets the forest trust.
        /// </summary>
        /// <param name="currentForest">Current forest.</param>
        public static void GetForestTrust(Forest currentForest)
        {
            Console.WriteLine("[-] Trust Relationship in the current forest:\n");

            var foresttable = new ConsoleTable("Source", "Target", "TrustType", "TrustDirection", "SID Filtering");

            var sidStatus = "";

            foreach (TrustRelationshipInformation trustInfo in currentForest.GetAllTrustRelationships())
            {
                try
                {
                    if (currentForest.GetSidFilteringStatus(trustInfo.TargetName))
                    {
                        sidStatus = "[SID Filtering is enabled]\n";
                    }
                    else
                    {
                        sidStatus = "[Not Filtering SIDs]\n";
                    }
                }
                catch (Exception e)
                {
                    sidStatus = "";
                    Console.WriteLine("Something wrong with SID filtering");

                    Console.WriteLine("Error: {0}\n", e.Message);
                }


                foresttable.AddRow(trustInfo.SourceName, trustInfo.TargetName, trustInfo.TrustType, trustInfo.TrustDirection, sidStatus);

                //Console.Write("{0,-30}{1,-30}{2,-15}{3,-20}", trustInfo.SourceName, trustInfo.TargetName, trustInfo.TrustType, trustInfo.TrustDirection);
                //try
                //{
                //    if (currentForest.GetSidFilteringStatus(trustInfo.TargetName))
                //    {
                //        Console.WriteLine("[SID Filtering is enabled]\n");
                //    }
                //    else
                //    {
                //        Console.WriteLine("[Not Filtering SIDs]\n");
                //    }
                //}
                //catch (Exception e) //Forest trust relationship does not exist???
                //{
                //    Console.WriteLine("Something wrong with SID filtering");
                //    Console.WriteLine("Error: {0}\n",e.Message);
                //}

            }
            Console.WriteLine(foresttable);
            Console.WriteLine("___________________________________________________________________________\n");
        }



        ///// <summary>
        /// Gets the priv users.
        /// </summary>
        /// <param name="entry">Entry.</param>
        /// <param name="forestEntry">Forest entry.</param>
        //DAs EAs
        public static void GetPrivUsers(DirectoryEntry entry, DirectoryEntry forestEntry)
        {
            Console.WriteLine("[-] Privileged Users/Groups:");
            Console.WriteLine();

            ////Admin groups
            //Console.WriteLine(" * Admin Groups:");
            //string queryAdminGroup = @"(&(objectClass=group)(name=*admin*))";
            //DirectorySearcher searchAdminGroup = new DirectorySearcher(entry, queryAdminGroup);

            //using (SearchResultCollection adminGroups = searchAdminGroup.FindAll())
            //{
            //    foreach (SearchResult adminGroup in adminGroups)
            //    {
            //        Console.WriteLine("   {0}",adminGroup.Properties["name"][0]);
            //    }
            //}
            //Console.WriteLine();


           
            //Domain Admins
            Console.WriteLine(" * Domain Admins:");
            string queryDAGroup = @"(&(objectClass=group)(name=Domain Admins))";
            DirectorySearcher searchDAGroup = new DirectorySearcher(entry);
            searchDAGroup.Filter = queryDAGroup;
            var DAgroup = searchDAGroup.FindOne();


            //string queryDAusers = @"(&(memberof:1.2.840.113556.1.4.1941:="+ DAgroup.Path.Replace("LDAP://","")+ @")(objectCategory=user))";
            //Console.WriteLine(queryDAusers);
            //searchDAGroup.Filter = queryDAusers;
            //searchDAGroup.PropertiesToLoad.Add("sAMAccountName");
            //SearchResultCollection DAs = searchDAGroup.FindAll();
            //foreach (SearchResult DA in DAs)
            //{
            //    Console.WriteLine(DA.Path); //Properties["sAMAccountName"][0]);
            //}


            foreach (var da in DAgroup.Properties["member"])
            {
                Console.WriteLine("   {0}",da);
            }
            Console.WriteLine();



            //Enterprise Admins
            Console.WriteLine(" * Enterprise Admins:");
            string queryEAGroup = @"(&(objectClass=group)(name=Enterprise Admins))";
            DirectorySearcher searchEAGroup = new DirectorySearcher(forestEntry);//, queryEAGroup);
            searchEAGroup.Filter = queryEAGroup;
            var EAgroup = searchEAGroup.FindOne();

            //string queryEAusers = @"(&(memberof:1.2.840.113556.1.4.1941:=" + EAgroup.Path.Replace("LDAP://", "") + @")(objectCategory=user))";
            //Console.WriteLine(queryEAusers);
            //searchEAGroup.Filter = queryEAusers;
            //searchEAGroup.PropertiesToLoad.Add("sAMAccountName");
            //SearchResultCollection EAs = searchEAGroup.FindAll();
            //foreach (SearchResult EA in EAs)
            //{
            //    Console.WriteLine(EA.Path); //Properties["sAMAccountName"][0]);
            //}

            foreach (var ea in EAgroup.Properties["member"])
            {
                Console.WriteLine("   {0}",ea);
            }
            Console.WriteLine();


            ////
            //Console.WriteLine(" * Domain Admins:");
            //string queryDAGroup = @"(&(objectClass=group)(name=Domain Admins))";
            //DirectorySearcher searchDAGroup = new DirectorySearcher(entry, queryDAGroup);
            //var DAs = searchDAGroup.FindOne();

            //foreach (var da in DAs.Properties["member"])
            //{
            //    Console.WriteLine("   {0}", da);
            //}
            //Console.WriteLine();



        }



        //Unconstrained Delegation
        /// <summary>
        /// Gets the unconstrained.
        /// </summary>
        /// <param name="entry">Entry.</param>
        public static void GetUnconstrained(DirectoryEntry entry)
        {
            Console.WriteLine("[-] Unconstrained Delegation Accounts:");
            Console.WriteLine();

            //DirectoryEntry entry = new DirectoryEntry("LDAP://" + rootDn);

            //using (entry)
            //{
            //Search accounts with TRUSTED_FOR_DELEGATION flag set

            string queryUncon = @"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))";//excluding DCs

            DirectorySearcher unconSearch = new DirectorySearcher(entry, queryUncon);

            unconSearch.PropertiesToLoad.Add("sAMAccountName");

            foreach (SearchResult sr in unconSearch.FindAll())
            {
                Console.WriteLine(" * {0}\n\n   LDAP Path:    {1}\n", sr.Properties["sAMAccountName"][0], sr.Path.Replace("LDAP://", ""));
            }
            //}

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
        /// <summary>
        /// Gets the mssql.
        /// </summary>
        /// <param name="currentForest">Current forest.</param>
        public static void GetMSSQL(Forest currentForest)
        {
            Console.WriteLine("[-] MSSQL Accounts:");
            Console.WriteLine();

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
        /// <summary>
        /// Gets the GPO.
        /// </summary>
        /// <param name="currentDomain">Current domain.</param>
        /// <param name="rootDn">Root dn.</param>
        /// Show certain set of GPO on the current machine [gpresult /R]
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

                    //gpo.Name : CN={*******-****-****-****-***********}
                    Console.WriteLine(" * GPO Name: {0}\n   {1}\n", gpo.Properties["displayName"][0], gpo.Name);

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


                }
            }
            Console.WriteLine("___________________________________________________________________________\n");

        }




        //Hidden attributes from [MS-ADTS] Section 3.1.1.2.3
        //Search Flags  CF (fCONFIDENTIAL,0x00000080)
        /// <summary>
        /// Gets the confi attri.
        /// </summary>
        /// <param name="rootEntry">Root entry.</param>
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