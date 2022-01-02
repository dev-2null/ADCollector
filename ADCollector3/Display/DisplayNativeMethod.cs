using System;

namespace ADCollector3
{
    public class DisplayNativeMethod : IDisplay
    {

        public void DisplayNetSession(SESSION_INFO_10[] Results)
        {
            if (Results == null) { return; }
            else
            {
                foreach (var info in Results)
                {
                    Console.WriteLine("    ------------------------------");
                    foreach (var t in info.GetType().GetFields())
                    {
                        Console.WriteLine("    {0, -25}  {1,-3}", t.Name.ToUpper() + " : ", t.GetValue(info));
                    }
                }
            }
        }




        public void DisplayNetWkstaUserEnum(WKSTA_USER_INFO_1[] Results)
        {
            if (Results == null) { return; }
            else
            {
                foreach (var info in Results)
                {
                    Console.WriteLine("    ------------------------------");
                    foreach (var t in info.GetType().GetFields())
                    {
                        Console.WriteLine("    {0, -25}  {1,-3}", t.Name.ToUpper() + " : ", t.GetValue(info));
                    }
                }
            }
        }




        public void DisplayNetLocalGroupGetMembers(LOCALGROUP_MEMBERS_INFO_2[] Results)
        {
            if (Results == null) { return; }
            else
            {
                foreach (var info in Results)
                {
                    Console.WriteLine("    ------------------------------");
                    foreach (var t in info.GetType().GetFields())
                    {
                        Console.WriteLine("    {0, -25}  {1,-3}", t.Name.ToUpper() + " : ", t.GetValue(info));
                    }
                }
            }
        }

        public override void DisplayResult(IResult collectResult)
        {
            throw new NotImplementedException();
        }


    }
}
