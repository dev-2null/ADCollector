using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ADCollector3
{
    public static class AsyncCollection
    {
        public static async Task<List<DACL>> GetInterestingACLAsync(List<string> targetDnList)
        {
            var tasks = new List<Task<DACL>>();

            foreach (string targetDn in targetDnList)
            {
                tasks.Add(Task.Run(() => DACL.GetInterestingACLOnObject(targetDn)));
            }

            var aclList = (await Task.WhenAll(tasks)).ToList();

            return aclList;
        }


        public static async Task<List<DACL>> GetACLAsync(List<string> targetDnList)
        {
            var tasks = new List<Task<DACL>>();

            foreach (string targetDn in targetDnList)
            {
                tasks.Add(Task.Run(() => DACL.GetACLOnObject(targetDn)));
            }

            var aclList = (await Task.WhenAll(tasks)).ToList();

            return aclList;
        }


        public static async Task<List<FileResult>> GetSYSVOLAsync(SearchString searchstring)
        {
            SMBSearchString searchString = (SMBSearchString)searchstring;

            var tasks = new List<Task<FileResult>>();

            foreach(var filePath in searchString.FilePathList)
            {
                var ss = new SMBSearchString { Title = searchString.Title, FilePath = filePath, FileAttributes = searchString.FileAttributes };
                tasks.Add(Task.Run(() => CollectSYSVOL.Collect(ss)));
            }

            var aclList = (await Task.WhenAll(tasks)).ToList();
            return aclList;
        }


        public static async Task<List<string>> TestEnrollmentEndpointsAsync(string caName, string caHostname)
        {
            List<Task<string>> tasks = new List<Task<string>>();

            //Adjusted from PKIAudit
            foreach (var protocol in new string[] { "http://", "https://" })
            {
                foreach (var suffix in new string[] { "/certsrv/",
                            $"/{caName}_CES_Kerberos/service.svc",
                            $"/{caName}_CES_Kerberos/service.svc/CES",
                            "/ADPolicyProvider_CEP_Kerberos/service.svc",
                            "/certsrv/mscep/" })
                {
                    var url = protocol + caHostname + suffix;

                    tasks.Add(Task.Run(() => Helper.TestWebConnection(url)));
                }
            }
            var enrollmentEndpoints = (await Task.WhenAll(tasks)).ToList();

            return enrollmentEndpoints;
        }



        public static async Task<List<ADCS>> GetADCSAsync()
        {
            string csFilter = @"(objectCategory=pKIEnrollmentService)";

            string csDn = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + Searcher.LdapInfo.ConfigDN;

            List<Task<ADCS>> tasks = new List<Task<ADCS>>();

            var csEntries = Searcher.GetResultEntries(new LDAPSearchString {DN = csDn,
                Filter =  csFilter,
                Scope = SearchScope.Subtree
            }).ToList();

            foreach (SearchResultEntry csEntry in csEntries)
            {
                tasks.Add(Task.Run(() => ADCS.GetADCS(csEntry)));
            }

            var caList = (await Task.WhenAll(tasks)).ToList();

            return caList;
        }



        public static async Task<List<CertificateTemplate>> GetInterestingCertTemplatesAsync()
        {
            var certTemplateList = Searcher.GetResultEntries(new LDAPSearchString
            {
                DN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,"+Searcher.LdapInfo.ConfigDN,
                Filter = @"(objectCategory=pKICertificateTemplate)",
                Scope = SearchScope.Subtree }).ToList();

            List<Task<CertificateTemplate>> tasks = new List<Task<CertificateTemplate>>();

            foreach (var certTemplate in certTemplateList)
            {
                tasks.Add(Task.Run(() => CertificateTemplate.GetInterestingCertTemplates(certTemplate)));
            }
            var CTTasks = (await Task.WhenAll(tasks)).ToList();
            return CTTasks;
        }





        public static async Task<List<string>> GetGPPXML()
        {
            List<string> gpoPathList = GPO.GroupPolicies.Keys.Select(k => $"\\\\{Searcher.LdapInfo.DomainController}\\SYSVOL\\{Searcher.LdapInfo.DomainName}\\Policies\\{k}").ToList();

            var xmlList = new List<string> { "Groups.xml", "Services.xml", "Scheduledtasks.xml", "Datasources.xml", "Printers.xml", "Drives.xml" };

            List<Task<List<string>>> tasks = new List<Task<List<string>>>();

            try
            {
                foreach(var path in gpoPathList)
                {
                    tasks.Add(Task.Run(() => GetXMLFileFromPath(path)));
                }
            }
            catch { }

            var fileList = (await Task.WhenAll(tasks)).ToList();
            var files = new List<string>();
            foreach(var file in fileList)
            {
                foreach(string name in file)
                {
                    if (name != null && name == string.Empty) { files.Add(name); }
                }
            }
            return files;
        }


        public static async Task<List<string>> GetXMLFileFromPath(string path)
        {
            List<Task<string>> tasks = new List<Task<string>>();

            var xmlList = new List<string> { "Groups.xml", "Services.xml", "ScheduledTasks.xml", "Datasources.xml", "Printers.xml", "Drives.xml" };

            foreach (string file in Directory.GetFiles(path, "*.*", System.IO.SearchOption.AllDirectories))
            {
                tasks.Add(Task.Run(() => Helper.CheckFile(xmlList, file)));
            }

            var files = (await Task.WhenAll(tasks)).ToList();
            return files;
        }



        public static List<CertificateTemplate> GetAllCertTemplatesAsync()
        {
            List<CertificateTemplate> CTS = new List<CertificateTemplate>();
            var certTemplateList = Searcher.GetResultEntries(new LDAPSearchString
            {
                DN = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + Searcher.LdapInfo.ConfigDN,
                Filter = @"(objectCategory=pKICertificateTemplate)",
                Scope = SearchScope.Subtree
            }).ToList();

            foreach (var certTemplate in certTemplateList)
            {
                CTS.Add(CertificateTemplate.GetAllCertTemplates(certTemplate));
            }

            return CTS;
        }


        public static List<string> GetAttributeCountAsync(List<string> attributes)
        {
            var attrCount = new List<string>();
            int maxConcurrency = 20;

            using (SemaphoreSlim concurrencySemaphore = new SemaphoreSlim(maxConcurrency))
            {
                List<Task> tasks = new List<Task>();
                foreach (var attr in attributes)
                {
                    concurrencySemaphore.Wait();
                    var t = Task.Factory.StartNew(() =>
                    {
                        try
                        {
                            var temp = SchemaUtil.GetAttributeCount(attr);

                            if (temp != null){ attrCount.Add(temp); }
                        }
                        finally
                        {
                            concurrencySemaphore.Release();
                        }
                    });
                    tasks.Add(t);
                }

                Task.WaitAll(tasks.ToArray());
            }

            //foreach (var attr in attributes)
            //{
            //    tasks.Add(Task.Run(() => SchemaUtil.GetAttributeCount(attr)));
            //}
            //var c = (await Task.WhenAll(tasks)).ToList();

            return attrCount;
        }

    }
}
