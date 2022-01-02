using System;
using System.Collections.Generic;

namespace ADCollector3
{
    public class DisplayADIDNS : IDisplay
    {
        public void DisplayResult(Dictionary<string, Dictionary<string, string>> dnsDict)
        {
            foreach (var zone in dnsDict)
            {
                Console.WriteLine("    * Zone: {0}", zone.Key);
                foreach (var dns in zone.Value)
                {
                    Console.WriteLine("      - {0,-20}  {1,-25}", dns.Value, dns.Key);
                }
            }
        }

        public override void DisplayResult(IResult collectResult)
        {
            throw new NotImplementedException();
        }
    }
}
