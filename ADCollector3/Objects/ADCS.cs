using Microsoft.Win32;
using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using static ADCollector3.Enums;

namespace ADCollector3
{
    public class ADCS
    {
        public string CAName;
        public string whenCreated;
        public string dnsHostName;
        public string enrollServers;
        public PkiCertificateAuthorityFlags flags;
        public bool allowUserSuppliedSAN;
        public List<X509Certificate2> caCertificates;
        public DACL DACL;
        public List<string> certTemplates;
        public List<string> enrollmentEndpoints;
        public static List<ADCS> CertificateServices { get; set; }
        static Logger logger { get; set; } = LogManager.GetCurrentClassLogger();

        public static ADCS GetADCS(SearchResultEntry csEntry)
        {
            logger.Debug("Collecting ADCS");

            string enrollServers = null;
            List<string> certTemplates = new List<string>();
            List<X509Certificate2> caCertificates = new List<X509Certificate2>();
            DACL acl;
            string caHostname = csEntry.Attributes["dnshostname"][0].ToString();
            string caName = csEntry.Attributes["name"][0].ToString();
            string whenCreated = Helper.ConvertWhenCreated(csEntry.Attributes["whencreated"][0].ToString()).ToString();

            var enrollmentEndpoints = AsyncCollection.TestEnrollmentEndpointsAsync(caName, caHostname).Result;

            PkiCertificateAuthorityFlags flags = (PkiCertificateAuthorityFlags)Enum.Parse(typeof(PkiCertificateAuthorityFlags), csEntry.Attributes["flags"][0].ToString());

            //The target attribute may not exist
            foreach (string attribute in csEntry.Attributes.AttributeNames)
            {
                if (attribute == "certificatetemplates")
                {
                    foreach (var certTemp in csEntry.Attributes[attribute])
                    {
                        certTemplates.Add(Encoding.UTF8.GetString((byte[])certTemp));
                    }
                }
                if (attribute == "mspki-enrollment-servers")
                {
                    enrollServers = csEntry.Attributes[attribute][0].ToString().Replace("\n", ",");
                }
                if (attribute == "cacertificate")
                {
                    caCertificates = GetCaCertificate(csEntry.Attributes[attribute]);
                }
            }


            bool allowSuppliedSAN = false;
            bool usingLDAP;

            var remoteReg = Helper.ReadRemoteReg(caHostname,
                RegistryHive.LocalMachine,
                $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy");

            //If the remote registry cannot be accessed, using LDAP to retrieve security descriptor instead
            usingLDAP = remoteReg == null ? true : false;

            if (usingLDAP)
            {
                acl = DACL.GetACLOnObject(csEntry.DistinguishedName);
            }
            else
            {
                int editFlags = (remoteReg == null) ? 0 : (int)(remoteReg).GetValue("EditFlags");
                allowSuppliedSAN = ((editFlags & 0x00040000) == 0x00040000);

                //Reading DACL from the remote registry, nTSecurityDescriptor from LDAP does not have the necessary information 
                var regSec = (byte[])(Helper.ReadRemoteReg(caHostname,
                RegistryHive.LocalMachine,
                $"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}")).GetValue("Security");
 
                var regSecDescriptor = new ActiveDirectorySecurity();
                regSecDescriptor.SetSecurityDescriptorBinaryForm(regSec, AccessControlSections.All);

                acl = DACL.GetCSACL($"{caHostname}:{RegistryHive.LocalMachine}:SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{caName}", regSecDescriptor, out _, false);
            }

            return new ADCS()
            {
                flags = flags,
                caCertificates = caCertificates,
                allowUserSuppliedSAN = allowSuppliedSAN,
                CAName = caName,
                whenCreated = whenCreated,
                dnsHostName = caHostname,
                enrollServers = enrollServers,
                DACL = acl,
                certTemplates = certTemplates,
                enrollmentEndpoints = enrollmentEndpoints
            };

        }


        public static List<X509Certificate2> GetCaCertificate(DirectoryAttribute caCert)
        {
            var certs = new List<X509Certificate2>();
            foreach (var certBytes in caCert)
            {
                var cert = new X509Certificate2((byte[])certBytes);
                certs.Add(cert);
            }
            return certs;
        }
    }
}
