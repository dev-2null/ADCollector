using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using static ADCollector3.Enums;

namespace ADCollector3
{
    class DisplayType
    {
        public static void DisplayTrust(List<Trust> domainTrusts)
        {
            if (domainTrusts == null || domainTrusts.FirstOrDefault() == null) { return; }
            foreach (var trust in domainTrusts)
            {
                foreach (var f in typeof(Trust).GetFields(BindingFlags.Public | BindingFlags.Instance))
                {
                    Console.WriteLine("    {0, -25}  {1,-3}", f.Name, f.GetValue(trust));
                }
                Console.WriteLine();
            }
        }

    }
}
