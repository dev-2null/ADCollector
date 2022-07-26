using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static ADCollector3.Enums;

namespace ADCollector3
{
    public abstract class IDisplay
    {
        public static void DisplayTitle(string Title)
        {
            DisplayUtil.Print(string.Format("\n[-] {0}:\n", Title), PrintColor.GREEN);
        }
        public abstract void DisplayResult(IResult collectResult);
    }

    public class Display : IDisplay
    {
        public override void DisplayResult(IResult collectResult)
        {
            throw new NotImplementedException();
        }
    }
}
