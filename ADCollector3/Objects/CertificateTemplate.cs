using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static ADCollector3.Enums;
using static ADCollector3.Natives;

namespace ADCollector3
{
    public class CertificateTemplate
    {
        public string TemplateCN;
        public string TemplateDisplayName;
        public List<string> ExtendedKeyUsage;
        public int RaSigature;
        public bool IsPublished;
        public string PublishedBy;
        public msPKICertificateNameFlag CertNameFlag;
        public msPKIEnrollmentFlag EnrollFlag;
        public DACL DACL;
        static Logger logger { get; set; } = LogManager.GetCurrentClassLogger();

        public static CertificateTemplate GetAllCertTemplates(SearchResultEntry certTemplateResultEntry)
        {
            var enrollFlag = (msPKIEnrollmentFlag)Enum.Parse(typeof(msPKIEnrollmentFlag), certTemplateResultEntry.Attributes["mspki-enrollment-flag"][0].ToString());
            var raSig = int.Parse(certTemplateResultEntry.Attributes["mspki-ra-signature"][0].ToString());
            var certNameFlag = (msPKICertificateNameFlag)Enum.Parse(typeof(msPKICertificateNameFlag), (unchecked((uint)(Convert.ToInt32(certTemplateResultEntry.Attributes["mspki-certificate-name-flag"][0].ToString())))).ToString());
            List<string> ekus = new List<string>();
            List<string> ekuNames = new List<string>();

            if (certTemplateResultEntry.Attributes.Contains("pkiextendedkeyusage"))
            {
                foreach (byte[] eku in certTemplateResultEntry.Attributes["pkiextendedkeyusage"])
                {
                    string ekuStr = Encoding.UTF8.GetString(eku);
                    ekus.Add(ekuStr);
                    ekuNames.Add(new Oid(ekuStr).FriendlyName);
                }
            }

            return new CertificateTemplate
            {
                IsPublished = true,
                //PublishedBy = "CA",//publishedBy,
                CertNameFlag = certNameFlag,
                RaSigature = raSig,
                EnrollFlag = enrollFlag,
                TemplateCN = certTemplateResultEntry.Attributes["cn"][0].ToString(),
                TemplateDisplayName = certTemplateResultEntry.Attributes["displayName"][0].ToString(),
                ExtendedKeyUsage = ekuNames,
                DACL = DACL.GetACLOnObject(certTemplateResultEntry.DistinguishedName)//retrieve the complete DACL instead of interesting ACEs
            };

        }
        public static CertificateTemplate GetInterestingCertTemplates(SearchResultEntry certTemplateResultEntry)
        {
            bool isPublished = false;
            string publishedBy = null;
            ActiveDirectorySecurity adRights = new ActiveDirectorySecurity();

            byte[] ldapSecBytes = (byte[])certTemplateResultEntry.Attributes["ntsecuritydescriptor"][0];
            
            adRights.SetSecurityDescriptorBinaryForm(ldapSecBytes, AccessControlSections.All);
            var acl = DACL.GetCSACL(certTemplateResultEntry.DistinguishedName,
                adRights, 
                out bool hasControlRights, true);

            var enrollFlag = (msPKIEnrollmentFlag)Enum.Parse(typeof(msPKIEnrollmentFlag), certTemplateResultEntry.Attributes["mspki-enrollment-flag"][0].ToString());
            var raSig = int.Parse(certTemplateResultEntry.Attributes["mspki-ra-signature"][0].ToString());
            var certNameFlag = (msPKICertificateNameFlag)Enum.Parse(typeof(msPKICertificateNameFlag), (unchecked((uint)(Convert.ToInt32(certTemplateResultEntry.Attributes["mspki-certificate-name-flag"][0].ToString())))).ToString());
            List<string> ekus = new List<string>();
            List<string> ekuNames = new List<string>();

            if (certTemplateResultEntry.Attributes.Contains("pkiextendedkeyusage"))
            {
                foreach (byte[] eku in certTemplateResultEntry.Attributes["pkiextendedkeyusage"])
                {
                    string ekuStr = Encoding.UTF8.GetString(eku);
                    ekus.Add(ekuStr);
                    ekuNames.Add(new Oid(ekuStr).FriendlyName);
                }
            }

            //If a low priv user has control rights over the templates
            if (hasControlRights)
            {
                foreach (var ca in ADCS.CertificateServices)
                {
                    var certInCa = ca.certTemplates.FirstOrDefault(caCerts => caCerts.Contains(certTemplateResultEntry.Attributes["name"][0].ToString()));
                    if (certInCa != null)
                    {
                        isPublished = true;
                        publishedBy = ca.CAName;
                    }
                }
                return new CertificateTemplate
                {
                    IsPublished = isPublished,
                    PublishedBy = publishedBy,
                    CertNameFlag = certNameFlag,
                    RaSigature = raSig,
                    EnrollFlag = enrollFlag,
                    TemplateCN = certTemplateResultEntry.Attributes["cn"][0].ToString(),
                    TemplateDisplayName = certTemplateResultEntry.Attributes["displayName"][0].ToString(),
                    ExtendedKeyUsage = ekuNames,
                    DACL = DACL.GetACLOnObject(certTemplateResultEntry.DistinguishedName)//retrieve the complete DACL instead of interesting ACEs
                };
            }
            //If a low priv user can enroll
            else if (acl != null)
            {
                logger.Debug("Checking manager approval...");
                //Check if manager approval is enabled
                if (!enrollFlag.HasFlag(msPKIEnrollmentFlag.PEND_ALL_REQUESTS))
                {
                    logger.Debug(certTemplateResultEntry.DistinguishedName);
                    logger.Debug("Checking authorized signatures...");
                    //Check if authorized signatures are required
                    if (raSig <= 0)
                    {
                        logger.Debug(certTemplateResultEntry.DistinguishedName);
                        logger.Debug("Checking EKUs & ENROLLEE_SUPPLIES_SUBJECT ...");
                        //Check if ENROLLEE_SUPPLIES_SUBJECT is enabled and a low priv user can request a cert for authentication 
                        //Check if the template has dangerous EKUs
                        logger.Debug(certTemplateResultEntry.DistinguishedName);
                        if ((certNameFlag.HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT) && HasAuthenticationEKU(ekus)) || HasDanagerousEKU(ekus))
                        {
                            logger.Debug(certTemplateResultEntry.DistinguishedName);
                            foreach (var ca in ADCS.CertificateServices)
                            {
                                var certInCa = ca.certTemplates.FirstOrDefault(caCerts => caCerts.Contains(certTemplateResultEntry.Attributes["name"][0].ToString()));

                                if (certInCa != null)
                                {
                                    isPublished = true;
                                    publishedBy = ca.CAName;
                                }
                            }
                            if (acl.ACEs.Count != 0)
                            {
                                return new CertificateTemplate
                                {
                                    IsPublished = isPublished,
                                    PublishedBy = publishedBy,
                                    CertNameFlag = certNameFlag,
                                    RaSigature = raSig,
                                    EnrollFlag = enrollFlag,
                                    TemplateCN = certTemplateResultEntry.Attributes["cn"][0].ToString(),
                                    TemplateDisplayName = certTemplateResultEntry.Attributes["displayName"][0].ToString(),
                                    ExtendedKeyUsage = ekuNames,
                                    DACL = DACL.GetACLOnObject(certTemplateResultEntry.DistinguishedName)//retrieve the complete DACL instead of interesting ACEs
                                };
                            }
                        }
                    }
                }
            }
            return null;
        }

        public static bool HasAuthenticationEKU(List<string> oids)
        {
            if (!oids.Any())
            {
                return false;
            }
            foreach (var oid in oids)
            {
                //          SmartcardLogon          ||    ClientAuthentication    || PKINITClientAuthentication
                if (oid == "1.3.6.1.4.1.311.20.2.2" || oid == "1.3.6.1.5.5.7.3.2" || oid == "1.3.6.1.5.2.3.4") { return true; }
            }
            return false;
        }

        public static bool HasDanagerousEKU(List<string> oids)
        {
            //Empty == AnyPurpose
            if (!oids.Any())
            {
                return true;
            }
            foreach (var oid in oids)
            {
                //          AnyPurpose   ||    CertificateRequestAgent
                if (oid == "2.5.29.37.0" || oid == "1.3.6.1.4.1.311.20.2.1"){ return true; }
            }
            return false;
        }


    }
}
