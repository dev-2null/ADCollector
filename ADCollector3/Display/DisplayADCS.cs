using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    public class DisplayADCS : IDisplay
    {
        public static IDisplay daclDisplayer { get; set; } = new DisplayDACL();
        public void DisplayResult(List<ADCS> certsrvs)
        {
            if (certsrvs == null || certsrvs.Count == 0) { return; }
            foreach (var certsrv in certsrvs)
            {
                Console.WriteLine("    * CA Name:                 {0}", certsrv.CAName);
                Console.WriteLine("      DNSHostName:             {0}", certsrv.dnsHostName);
                Console.WriteLine("      WhenCreated:             {0}", certsrv.whenCreated);
                Console.WriteLine("      Flags:                   {0}", certsrv.flags);
                Console.WriteLine("      Enrollment Servers:      {0}", certsrv.enrollServers);
                Console.WriteLine("      Certificate Templates:   {0}", string.Join(",", certsrv.certTemplates));
                Console.WriteLine("      Enrollment Endpoints:    {0}", string.Join(",", certsrv.enrollmentEndpoints.Where(x => x != null).ToList()));
                Console.WriteLine("      Supplied SAN Enabled:    {0}", certsrv.allowUserSuppliedSAN.ToString().ToUpper());
                
                foreach (var cert in certsrv.caCertificates)
                {
                    Console.WriteLine("      Cert SubjectName:        {0}", cert.SubjectName.Name);
                    Console.WriteLine("      Cert Thumbprint:         {0}", cert.Thumbprint);
                    Console.WriteLine("      Cert Start Date:         {0}", cert.NotBefore);
                    Console.WriteLine("      Cert End Date:           {0}", cert.NotAfter);
                }

                daclDisplayer.DisplayResult(new DACLResult { Result = new List<DACL> { certsrv.DACL } });
                Console.WriteLine();
            }
        }


        public void DisplayResult(List<CertificateTemplate> certTemplates)
        {
            if (certTemplates == null || certTemplates.Count == 0) { return; }

            foreach (var template in certTemplates.Where(v => v != null).ToList())
            {
                if (template.IsPublished)
                {
                    Console.WriteLine("    * CertTemplate:            {0}", template.TemplateDisplayName);
                    Console.WriteLine("      CA Name:                 {0}", template.PublishedBy);
                    Console.WriteLine("      CN:                      {0}", template.TemplateCN);
                    Console.WriteLine("      Enrollment Flag:         {0}", template.EnrollFlag);
                    Console.WriteLine("      Cert Name Flag:          {0}", template.CertNameFlag);
                    Console.WriteLine("      Extended Key Usage:      {0}", string.Join(",", template.ExtendedKeyUsage));
                    Console.WriteLine("      RA Signatures:           {0}", template.RaSigature);
                    Console.WriteLine("      DACL:");
                    daclDisplayer.DisplayResult(new DACLResult { Result = new List<DACL> { template.DACL } });
                    Console.WriteLine();
                }
            }
            foreach (var template in certTemplates.Where(v => v != null).ToList())
            {
                if (!template.IsPublished)
                {
                    Console.WriteLine("    * The Certificate Template [{0}] is vulnerable but it is not published by any CA ", template.TemplateDisplayName);
                    Console.WriteLine("      DACL:");
                    daclDisplayer.DisplayResult(new DACLResult { Result = new List<DACL> { template.DACL } });
                    Console.WriteLine();
                }

            }
        }
        public override void DisplayResult(IResult collectResult)
        {
            throw new NotImplementedException();
        }
    }
}
