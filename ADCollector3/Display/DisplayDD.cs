using System;

namespace ADCollector3
{
    public class DisplayDD : IDisplay
    {
        public override void DisplayResult(IResult collectResult)
        {
            if (collectResult == null) { return; }
            DDResult collectResults = (DDResult)collectResult;
            if (collectResults.Result == null) { return; }

            foreach (var dict1 in collectResults.Result)
            {
                Console.WriteLine("    - {0}", dict1.Key);
                foreach(var dict2 in dict1.Value)
                {
                    Console.WriteLine("      {0, -36}      {1}", dict2.Key, dict2.Value);
                }
                Console.WriteLine();
            }
        }
    }
}
