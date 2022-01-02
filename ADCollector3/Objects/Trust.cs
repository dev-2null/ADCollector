using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using static ADCollector3.Enums;
using static ADCollector3.Natives;

namespace ADCollector3
{
    class Trust
    {
        public string SourceDomainName;
        public string TargetDomainName;
        public string NetBIOSName;
        public bool IsTransitive;
        public bool FilteringSID;
        public TrustDirection TrustDirection;
        public TrustType TrustType;
        private List<Trust> Trusts { get; set; } = new List<Trust>();
        private static Logger _logger;
        public Trust()
        {
            _logger = LogManager.GetCurrentClassLogger();
            SourceDomainName = Searcher.LdapInfo.DomainName;
        }


        public List<Trust> AnalyzeTrust(DS_DOMAIN_TRUSTS[] trustResults)
        {
            if (trustResults == null) { return null; }

            DS_DOMAIN_TRUSTS currentDomain = new DS_DOMAIN_TRUSTS();

            foreach (var domain in trustResults)
            {
                if (domain.DnsDomainName.ToUpper() == SourceDomainName.ToUpper())
                {
                    currentDomain = domain;
                    break;
                }
            }

            foreach (var trust in trustResults)
            {
                var dnsDomainName = trust.DnsDomainName;

                if (dnsDomainName.ToUpper() == SourceDomainName.ToUpper()) { continue; }

                var trustAttributes = (TrustAttributes)trust.TrustAttributes;
                var trustFlags = (TrustFlags)trust.Flags;
                var netbiosName = trust.NetbiosDomainName;
                //var domainSid = (new SecurityIdentifier(trust.DomainSid)).ToString();
                bool sidFiltering = trustAttributes.HasFlag(TrustAttributes.FilterSids) ? true : false;
                bool isTransitive = trustAttributes.HasFlag(TrustAttributes.NonTransitive) ? false : true;

                TrustDirection trustDirection;

                if (trustFlags.HasFlag(TrustFlags.DirectInBound) && trustFlags.HasFlag(TrustFlags.DirectOutBound))
                {
                    trustDirection = TrustDirection.BiDirectional;

                }
                else if (trustFlags.HasFlag(TrustFlags.DirectInBound))
                {
                    trustDirection = TrustDirection.InBound;
                }
                else if (trustFlags.HasFlag(TrustFlags.DirectOutBound))
                {
                    trustDirection = TrustDirection.OutBound;
                }
                else
                {
                    trustDirection = TrustDirection.Disable;
                }

                TrustType trustType;

                //If the target domain is the current tree root or if target domain is a child domain of the current domain
                if ((trustFlags.HasFlag(TrustFlags.TreeRoot) &&
                    trustFlags.HasFlag(TrustFlags.InForest) &&
                    (currentDomain.DnsDomainName.ToUpper().Contains(dnsDomainName.ToUpper()))) ||
                    (trustResults[trust.ParentIndex].DnsDomainName.ToUpper() == SourceDomainName.ToUpper()))
                {
                    trustType = TrustType.ParentChild;
                }
                else if (trustFlags.HasFlag(TrustFlags.TreeRoot) && trustFlags.HasFlag(TrustFlags.InForest))
                {
                    trustType = TrustType.TreeRoot;
                }
                else if (trustFlags.HasFlag(TrustFlags.InForest))
                {
                    trustType = TrustType.ShortCut;
                }
                else if (trustAttributes.HasFlag(TrustAttributes.ForestTransitive))
                {
                    trustType = TrustType.Forest;
                }
                else
                {
                    trustType = TrustType.External;
                }


                Trusts.Add(new Trust()
                {
                    SourceDomainName = SourceDomainName,
                    NetBIOSName = netbiosName,
                    TargetDomainName = dnsDomainName,
                    //DomainSid = domainSid,
                    IsTransitive = isTransitive,
                    TrustDirection = trustDirection,
                    TrustType = trustType,
                    FilteringSID = sidFiltering
                });
            }

            return Trusts;
        }
    }
}
