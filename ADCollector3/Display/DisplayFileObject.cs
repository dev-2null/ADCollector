using System;
using System.IO;
using System.Collections.Generic;
using static ADCollector3.Enums;

namespace ADCollector3
{
    public class DisplayFileObjects : IDisplay
    {
        public override void DisplayResult(IResult collectResult)
        {
            if (collectResult == null) { return; }
            FileResult collectResults = (FileResult)collectResult;
            if (collectResults.FileObject == null) { return; }
            if (collectResults.FileObject.Properties.Count == 0) { return; }
            Console.WriteLine("    * {0}", collectResults.FileObject.GPO);
            foreach (var sections in collectResults.FileObject.Properties)
            {
                foreach(var section in sections.Value)
                {
                    Console.WriteLine("    - {0}", sections.Key);
                    foreach (var attr in section)
                    {
                        Console.WriteLine("      {0, -36}      {1}", attr.Key + " :", attr.Value);
                    }
                    Console.WriteLine();
                }
            }
            

        }

    }
}
