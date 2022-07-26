using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SecurityMasks = System.DirectoryServices.Protocols.SecurityMasks;
using ADCollector3;
using NLog;
using System.Linq;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using static ADCollector3.Enums;

namespace ADCollector3
{
    public class Searcher
    {
        public static string DomainName;
        public static string DomainSID;
        public static string RootDN;
        public static string TargetSearchBase;
        public static int Port;
        internal static string DomainController;
        public static Dictionary<string, List<string>> BasicLDAPInfo { get; set; } = new Dictionary<string, List<string>>();
        public static LDAPInfo LdapInfo;

        private static readonly ConcurrentBag<LdapConnection> _connectionPool = new ConcurrentBag<LdapConnection>();

        static Logger _logger;

        public Searcher()
        {
            _logger = LogManager.GetCurrentClassLogger();

            PrepareSearcher();
        }


        public void PrepareSearcher()
        {
            _logger.Debug("Preparing Searcher");

            DomainName = Options.Instance.Domain ?? Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            DomainController = Options.Instance.DC ?? DomainName;
            Port = Options.Instance.Ldaps ? 636 : 389;
            RootDN = "DC="+DomainName.Replace(".", ",DC=");

            if (Options.Instance.OU != null)
            {
                _logger.Debug("Checking User Supplied OU");
                if (!Options.Instance.OU.Contains("DC="))
                {
                    var findOU = GetResultEntries(new LDAPSearchString { DN = RootDN, Filter = ("(&(objectClass=organizationalUnit)(name=" + Options.Instance.OU + "))"), Scope = SearchScope.Subtree }).ToList();
                    if (findOU.Count == 0) { _logger.Error("The specified OU does not exist"); Environment.Exit(1); }
                    else { TargetSearchBase = findOU[0].DistinguishedName; }
                }
            }
            else { TargetSearchBase = RootDN; }
        }



        public void Init()
        {
            _logger.Debug($"Connecting to {DomainController}");
            
            var RootDSE = GetDirectoryEntry("rootDSE");
            //Test Connection
            try
            {
                RootDSE.RefreshCache();
            }
            catch (Exception e)
            {
                _logger.Error($"Unable to connect to LDAP://{DomainController}:{Port}/rootDSE");
                _logger.Trace(e.Message);
                Environment.Exit(1);
            }
            
            _logger.Debug("Connected. Enumerating root DSE");
            
            string RootDN = RootDSE.Properties["defaultNamingContext"].Value.ToString();
            string ForestDN = RootDSE.Properties["rootDomainNamingContext"].Value.ToString();
            DomainName = RootDN.Replace("DC=", "").Replace(",", ".");
            string ForestName = ForestDN.Replace("DC=", "").Replace(",", ".");
            string domainFunc = (Enum.Parse(typeof(Functionality), RootDSE.Properties["domainFunctionality"].Value.ToString())).ToString();
            string forestFunc = (Enum.Parse(typeof(Functionality), RootDSE.Properties["forestFunctionality"].Value.ToString())).ToString();
            string dcFunc = (Enum.Parse(typeof(Functionality), RootDSE.Properties["domainControllerFunctionality"].Value.ToString())).ToString();

            //BasicLDAPInfo.Add("RootDN", new List<string> { RootDN });
            //BasicLDAPInfo.Add("ForestDN", new List<string> { ForestDN });
            BasicLDAPInfo.Add("DomainName", new List<string> { DomainName.ToUpper() });
            BasicLDAPInfo.Add("ForestName", new List<string> { ForestName.ToUpper() });
            BasicLDAPInfo.Add("DomainFunctionality", new List<string> { domainFunc });
            BasicLDAPInfo.Add("ForestFunctionality", new List<string> { forestFunc });
            BasicLDAPInfo.Add("DomainControllerFunctionality", new List<string> { dcFunc });

            var domainEntry = GetResultEntry(new LDAPSearchString { DN  = RootDN, Filter = "name=*", Scope = SearchScope.Base});
            DomainSID = Helper.ConvertByteArrayToSID((byte[])domainEntry.Attributes["objectsid"][0]);

            LdapInfo = new LDAPInfo
            {
                RootDN = RootDN,
                ForestDN = ForestDN,
                ConfigDN = RootDSE.Properties["configurationNamingContext"].Value.ToString(),
                SchemaDN = RootDSE.Properties["schemaNamingContext"].Value.ToString(),
                DomainName = DomainName,
                ForestName = ForestName,
                TargetSearchBase = TargetSearchBase,
                DomainController = DomainController,
                DomainSID = DomainSID
            };


            string[] attributeNames = new string[] { "serverName", "isSynchronized", "isGlobalCatalogReady", "dnsHostName",
                "ldapServiceName", "supportedLDAPVersion", "supportedSASLMechanisms", "namingContexts", "dsServiceName"};

            foreach (string name in attributeNames)
            {
                List<string> valueCollection = new List<string>();
                foreach (string value in RootDSE.Properties[name])
                {
                    valueCollection.Add(value);
                }
                BasicLDAPInfo.Add(name, valueCollection);
            }
            _logger.Debug("Enumerated");
            RootDSE.Dispose();
        }



        private static LdapConnection ConnectDirectory(bool useGlobalCatalog = false)
        {
            string target = useGlobalCatalog ? "GlobalCatalog" : "LDAP";
            _logger.Debug($"Connecting to {target}");

            LdapConnection Connection;
            //Only try to retrieve the existing connetion if not using GC as GC connection will always be disposed after being used
            //otherwise it will make the connection unusable for non GC search
            if (!useGlobalCatalog)
            {
                if (_connectionPool.TryTake(out Connection))
                {
                    _logger.Debug("Taking connection from the pool");
                    return Connection;
                }
            }

            int port = useGlobalCatalog ? 3268 : Port;
            try
            {
                var identifier = new LdapDirectoryIdentifier(DomainController, port, false, false);
                _logger.Debug($"Connecting to {DomainController} on port {port}");

                Connection = (Options.Instance.Username != null) ?
                    new LdapConnection(identifier, new NetworkCredential(Options.Instance.Username, Options.Instance.Password)) :
                    new LdapConnection(identifier);

                Connection.SessionOptions.SecureSocketLayer = !useGlobalCatalog && Options.Instance.Ldaps;

                if (!Options.Instance.DisableSigning)
                {
                    Connection.SessionOptions.Signing = true;
                    Connection.SessionOptions.Sealing = true;
                }

                Connection.SessionOptions.ProtocolVersion = 3;
                Connection.SessionOptions.SendTimeout = new TimeSpan(0, 0, 10, 0);
                Connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                Connection.SessionOptions.VerifyServerCertificate += delegate { return true; };
                Connection.AuthType = AuthType.Negotiate;
                Connection.Timeout = new TimeSpan(0, 0, 10, 0);

                return Connection;
            }
            catch
            {
                _logger.Error($"Something is wrong, add --DisableSigning if you are using --LDAPs");
                return null;
            }
            
        }


        private static SearchRequest GetRequest(string dn, string filter, string[] returnAttrs, SearchScope scope = SearchScope.Subtree)
        {
            var request = new SearchRequest(dn, filter, scope, returnAttrs);

            // turn off referral chasing so that data 
            // from other partitions is not returned

            var searchControl = new SearchOptionsControl(SearchOption.DomainScope);

            //To retrieve nTSecurityDescriptor attribute https://github.com/BloodHoundAD/SharpHound3/blob/master/SharpHound3/DirectorySearch.cs#L157
            var securityDescriptorFlagControl = new SecurityDescriptorFlagControl
            {
                SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
            };
            request.Controls.Add(securityDescriptorFlagControl);
            request.Controls.Add(searchControl);

            return request;
        }



        //Find all matching LDAP objects from LDAP
        //[adsisearcher]::new([adsi]"LDAP://DC","(filter)").FindAll()
        public static IEnumerable<SearchResultEntry> GetResultEntries(LDAPSearchString searchString)
        {
            var connection = ConnectDirectory(searchString.UseGlobalCatalog);

            _logger.Debug($"Collecting {searchString.Filter} from ({searchString.DN}) with SearchScope.{searchString.Scope}");

            try
            {
                var request = GetRequest(searchString.DN, searchString.Filter, searchString.ReturnAttributes, searchString.Scope);
                var pageReqControl = new PageResultRequestControl(searchString.PageSize);
                request.Controls.Add(pageReqControl);
                
                while (true)
                {
                    SearchResponse response;
                    try
                    {
                        //_logger.Debug("Sending Request...");
                        response = (SearchResponse)connection.SendRequest(request);
                        _logger.Debug($"{response.Entries.Count} Entries Received");
                    }
                    catch (Exception e)
                    {
                        _logger.Warn(e.Message + "[DN:" + searchString.DN + " Filter:" + searchString.Filter + "]");
                        yield break;
                    }
                    if (response.Controls.Length != 1 || !(response.Controls[0] is PageResultResponseControl))
                    {
                        _logger.Error("The server does not support this advanced search operation");
                        yield break;
                    }

                    var pageResControl = (PageResultResponseControl)response.Controls[0];

                    //Console.WriteLine("\n[*] This page contains {0} response entries:\n", response.Entries.Count);
                    if (response.Entries.Count != 0)
                    {
                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            yield return entry;
                        }
                    }

                    if (pageResControl.Cookie.Length == 0) { break; }

                    pageReqControl.Cookie = pageResControl.Cookie;
                }
            }
            finally
            {
                if (!searchString.UseGlobalCatalog) { _connectionPool.Add(connection); }
                else { connection.Dispose(); }   
            }

        }



        //Find one matching LDAP object from the global catalog
        //[adsisearcher]::new([adsi]"GC://DC","(filter)").FindOne()
        internal static SearchResultEntry GetResultEntry(LDAPSearchString searchString)
        {
            var connection = ConnectDirectory(true);

            var request = GetRequest(searchString.DN, searchString.Filter, searchString.ReturnAttributes, searchString.Scope);
            
            try
            {
                //_logger.Debug("Sending Request...");
                _logger.Debug($"Collecting {searchString.Filter} from ({searchString.DN}) with SearchScope.{searchString.Scope}");

                var response = (SearchResponse)connection.SendRequest(request);

                _logger.Debug($"{response.Entries.Count} Entries Received");

                if (response.Entries.Count == 0) { return null; }
                return response.Entries[0];
            }
            catch (Exception e)
            {
                _logger.Warn(e.Message + $"[DN:({searchString.DN}) Filter:({searchString.Filter})]");
                return null;
            }
            finally
            {
                connection.Dispose();
            }
        }


        //Get the attribute value of a specific LDAP object from the global catalog
        //[adsisearcher]::new([adsi]"GC://DC","(filter)").FindOne().Properities[attribute]
        public static object GetSingleAttributeValue(string dn, string filter, string attribute)
        {
            _logger.Debug($"Trying to retrieve attribute {attribute}");
            //We are searching from the global catalog, the target search base has to set to the forestDN
            var searchstring = new LDAPSearchString { DN = dn, Filter = filter, ReturnAttributes = new string[] { attribute }, Scope = SearchScope.Subtree, UseGlobalCatalog = true };

            var result = GetResultEntry(searchstring);
            if (result == null) 
            {
                _logger.Warn($"Cannot find object with {filter}");
                return null; 
            };

            var value = result.Attributes[attribute][0];

            return value;

        }


        //Get a DirectoryEntry object
        public static DirectoryEntry GetDirectoryEntry(string dn, bool useGlobalCatalog = false)
        {
            int port = useGlobalCatalog ? 3268 : Port;

            _logger.Debug($"Connecting LDAP://{DomainController}:{port}/{dn}");

            try
            {
                return new DirectoryEntry($"LDAP://{DomainController}:{port}/{dn}", Options.Instance.Username, Options.Instance.Password);
            }
            catch
            {
                _logger.Warn($"Cannot connect to {dn}");
                return null;
            }

        }

    }
}
