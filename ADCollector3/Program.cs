using System;
using System.Collections.Generic;
using CommandLine;

namespace ADCollector3
{
    class Program
    {
        static void Main(string[] args)
        {
            DisplayUtil.PrintBanner();

            var parser = new Parser(with =>
            {
                with.CaseInsensitiveEnumValues = true;
                with.CaseSensitive = false;
                with.HelpWriter = null;
            });

            parser.ParseArguments<Options>(args).WithParsed(o => {Options.Instance = o; }).WithNotParsed(error => { });
            parser.Dispose();

            var options = Options.Instance;
            if (options == null) { Options.GetHelp(); return; }

            Logging.LoadLoggingConfig(options.Debug);

            if (options.Username != null)
            {
                Impersonation.RunAs(options.Domain, options.Username, options.Password, () =>
                {
                    ChooseOption(options);
                });
            }
            else{ ChooseOption(options); }


            DisplayUtil.Done();
        }

        public static void ChooseOption(Options options)
        {
            if (options.SessionEnum)
            {
                ADCollector.GetHostSession(options.Host);
            }
            else if (options.UserEnum)
            {
                ADCollector.GetHostUser(options.Host);
            }
            else if (options.LocalGMEnum)
            {
                ADCollector.GetHostGroupMember(options.Host, options.Group);
            }
            else
            {
                var adcollector = new ADCollector();
                if (options.LDAPONLY)
                {
                    adcollector.GetLDAPOnly();
                }
                else if (options.SCHEMA)
                {
                    adcollector.GetSchemaCount();
                }
                else if (options.TEMPLATES)
                {
                    adcollector.GetTemplates();
                }
                else if (options.ADCS)
                {
                    adcollector.GetADCS();
                }
                else if (options.ADIDNS)
                {
                    adcollector.GetADIDNS();
                }
                else if (options.NGAGP != null)
                {
                    adcollector.GetNGAGP(new List<string> { options.NGAGP });
                }
                else if (options.DACL != null)
                {
                    adcollector.GetACL(options.DACL);
                }
                else if (options.ACLScan != null)
                {
                    adcollector.InvokeACLScan(options.ACLScan);
                }
                else
                {
                    adcollector.Run();
                }
            }
        }
    }

}
