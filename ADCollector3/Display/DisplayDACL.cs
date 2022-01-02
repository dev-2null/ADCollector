using System;
using System.Linq;

namespace ADCollector3
{
    public class DisplayDACL : IDisplay
    {
        public override void DisplayResult(IResult collectResult)
        {
            if (collectResult == null) { return; }
            DACLResult collectResults = (DACLResult)collectResult;
            if (collectResults.Result == null) { return; }

            foreach (var dacl in collectResults.Result)
            {
                if (dacl == null) { continue; }
                Console.WriteLine("      - {0}", dacl.ObjectName);

                foreach (var ace in dacl.ACEs)
                {
                    int c = 0;
                    foreach (var attr in ace.Value)
                    {
                        if (c == 0)
                        {
                            Console.WriteLine("        {0, -36}      {1}", ace.Key, attr);
                        }
                        else
                        {
                            Console.WriteLine("        {0, -36}      {1}", string.Empty, attr);
                        }
                        c = 1;
                    }
                }
                Console.WriteLine();
            }
        }
    }
}
