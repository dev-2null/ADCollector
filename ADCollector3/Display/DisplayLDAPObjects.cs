using System;
using static ADCollector3.Enums;

namespace ADCollector3
{
    public class DisplayLDAPObjects : IDisplay
    {
        public override void DisplayResult(IResult collectResult)
        {
            if (collectResult == null) { return; }
            LDAPResult collectResults = (LDAPResult)collectResult;
            if (collectResults.LDAPObjects.Count == 0) { return; }

            foreach (var ldapObject in collectResults.LDAPObjects)
            {
                Console.WriteLine("    * {0}", ldapObject.DistinguishedName.ToUpper());

                if (ldapObject is User u)
                {
                    foreach (var attr in u.Properities)
                    {
                        foreach (var value in attr.Value)
                        {
                            Console.WriteLine("      - {0, -30}  {1}", attr.Key + ":", value);
                        }
                    }
                }
                else if (ldapObject is LDAPBaseObject b)
                {
                    foreach (var dict in b.Attributes)
                    {
                        foreach (var attr in dict.Value)
                        {
                            Console.WriteLine("      {0, -30}    {1}", dict.Key, attr);
                        }
                        //Console.WriteLine();
                    }
                }
                //Console.WriteLine();
            } 
        }

    }
}
