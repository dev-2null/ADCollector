using System;

namespace ADCollector3
{
    public class DisplayList : IDisplay
    {
        public override void DisplayResult(IResult collectResult)
        {
            if (collectResult == null) { return; }
            ListResult collectResults = (ListResult)collectResult;
            
            foreach (string obj in collectResults.Result)
            {
                Console.WriteLine("      {0, -25}", obj);
                //Console.WriteLine();
            }
        }
    }
}
