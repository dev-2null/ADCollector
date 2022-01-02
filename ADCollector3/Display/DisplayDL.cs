using System;

namespace ADCollector3
{
    public class DisplayDL : IDisplay
    {
        public override void DisplayResult(IResult collectResult)
        {
            if (collectResult == null) { return; }
            DLResult collectResults = (DLResult)collectResult;
            if (collectResults.Result == null) { return; }
            foreach(var result in collectResults.Result)
            {
                if (result == null) { return; }
                foreach (var dict in result)
                {
                    string key = dict.Key;
                    int c = 0;
                    foreach (var attr in dict.Value)
                    {
                        if (c == 0)
                        {
                            Console.WriteLine("      {0, -36}      {1}", key, attr);
                        }
                        else
                        {
                            Console.WriteLine("      {0, -36}      {1}", string.Empty, attr);
                        }
                        c = 1;
                    }
                }
                Console.WriteLine();
            }
            


            
        }
    }
}
