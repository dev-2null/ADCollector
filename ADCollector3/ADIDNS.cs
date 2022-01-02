using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    class ADIDNS
    {
        //Retrieve IP from LDAP dnsRecord only
        public static Dictionary<string, Dictionary<string, string>> GetDNS(bool searchForest = false)
        {
            Dictionary<string, Dictionary<string, string>> dnsDict = new Dictionary<string, Dictionary<string, string>>();

            string dDnsDn = "DC=DomainDnsZones," + Searcher.LdapInfo.RootDN;//not searching from "CN=MicrosoftDNS,DC=DomainDnsZones,";
            string fDnsDn = "DC=ForestDnsZones," + Searcher.LdapInfo.ForestDN;
            string queryZones = @"(&(objectClass=dnsZone)(!(DC=*arpa))(!(DC=RootDNSServers)))";
            string[] dnsZoneAttrs = { "name" };

            var dnsZoneSearchResult = searchForest ?
                Searcher.GetResultEntries(new LDAPSearchString
                {
                    DN = fDnsDn,
                    Filter = queryZones,
                    ReturnAttributes = dnsZoneAttrs,
                    Scope = SearchScope.Subtree
                }).ToList()
                :
                Searcher.GetResultEntries(new LDAPSearchString
                {
                    DN = dDnsDn,
                    Filter = queryZones,
                    ReturnAttributes = dnsZoneAttrs,
                    Scope = SearchScope.Subtree
                }).ToList();

            //excluding objects that have been removed
            string queryRecord = @"(&(objectClass=*)(!(DC=@))(!(DC=*DnsZones))(!(DC=*arpa))(!(DC=_*))(!dNSTombstoned=TRUE))";
            string[] dnsAttrs = { "dnsRecord" };

            byte[] dnsByte = null;
            string ip = null;
            string hostname = null;

            foreach (var dnsZone in dnsZoneSearchResult)
            {
                Dictionary<string, string> dnsRecordDict = new Dictionary<string, string>();

                var dnsResponse = Searcher.GetResultEntries(new LDAPSearchString
                {
                    DN = dnsZone.DistinguishedName,
                    Filter = queryRecord,
                    Scope = SearchScope.OneLevel,
                    ReturnAttributes = dnsAttrs
                }).ToList();

                foreach (var dnsResult in dnsResponse)
                {
                    //If have permission to view the record
                    if (dnsResult.Attributes.Contains("dnsRecord"))
                    {
                        dnsByte = ((byte[])dnsResult.Attributes["dnsRecord"][0]);
                        
                        ip = ResolveDNSRecord(dnsByte);
                        if (ip == string.Empty || ip == null)
                        {
                            continue;
                        }
                        hostname = dnsResult.DistinguishedName;

                        if (!dnsRecordDict.ContainsKey(hostname.ToUpper()))
                        {
                            dnsRecordDict.Add(hostname.ToUpper(), ip);
                        }
                    }
                }
                if (!dnsDict.ContainsKey(dnsZone.DistinguishedName.ToUpper()))
                {
                    dnsDict.Add(dnsZone.DistinguishedName.ToUpper(), dnsRecordDict);
                }
            }
            return dnsDict;
        }






        ////Retrieve Single dnsRecord with a hostname
        //public static string GetSingleDNSRecord(string hostname, bool searchForest = true)
        //{
        //    string dDnsDn = "DC=DomainDnsZones," + Searcher.LdapInfo.RootDN;//not searching from "CN=MicrosoftDNS,DC=DomainDnsZones,";
        //    string fDnsDn = "DC=ForestDnsZones," + Searcher.LdapInfo.ForestDN;
        //    string queryZones = @"(&(objectClass=dnsZone)(!(DC=*arpa))(!(DC=RootDNSServers)))";
        //    string[] dnsZoneAttrs = { "name" };

        //    var dnsZoneSearchResult = searchForest ?
        //        Searcher.GetResultEntries(new LDAPSearchString
        //        {
        //            DN = fDnsDn,
        //            Filter = queryZones,
        //            ReturnAttributes = dnsZoneAttrs,
        //            Scope = SearchScope.Subtree
        //        }).ToList()
        //        :
        //        Searcher.GetResultEntries(new LDAPSearchString
        //        {
        //            DN = dDnsDn,
        //            Filter = queryZones,
        //            ReturnAttributes = dnsZoneAttrs,
        //            Scope = SearchScope.Subtree
        //        }).ToList();


        //    string queryRecord = @"(&(objectClass=*)(!(DC=@))(!(DC=*DnsZones))(!(DC=*arpa))(!(DC=_*))(name=" + hostname + "))";

        //    string[] dnsAttrs = { "dnsRecord", "name" };

        //    foreach (var dnsZone in dnsZoneSearchResult)
        //    {
        //        var hostResult = Searcher.GetResultEntry(new LDAPSearchString
        //        {
        //            DN = dnsZone.DistinguishedName,
        //            Filter = queryRecord,
        //            Scope = SearchScope.OneLevel,
        //            ReturnAttributes = dnsAttrs
        //        });

        //        if (hostResult == null) { continue; }

        //        if (hostResult.Attributes.Contains("dnsRecord"))
        //        {
        //            string ip = ResolveDNSRecord(((byte[])hostResult.Attributes["dnsRecord"][0]));

        //            return ip;
        //        }

        //    }
        //    return null;
        //}


        public static string ResolveDNSRecord(byte[] dnsByte)
        {
            var rdatatype = dnsByte[2];

            string ip = null;

            if (rdatatype == 1)
            {
                ip = dnsByte[24] + "." + dnsByte[25] + "." + dnsByte[26] + "." + dnsByte[27];
            }
            return ip;
        }


    }
}
