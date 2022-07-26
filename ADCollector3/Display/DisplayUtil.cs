using System;
using System.Linq;
using System.Collections.Generic;
using static ADCollector3.Enums;

namespace ADCollector3
{
    public static class DisplayUtil
    {
        public static void PrintBanner()
        {
            Console.WriteLine();
            Console.WriteLine(@"      _    ____   ____      _ _             _             ");
            Console.WriteLine(@"     / \  |  _ \ / ___|___ | | | ___  ___ _| |_ ___  _ __ ");
            Console.WriteLine(@"    / _ \ | | | | |   / _ \| | |/ _ \/ __|_  __/ _ \| '__|");
            Console.WriteLine(@"   / ___ \| |_| | |__| (_) | | |  __/ (__  | || (_) | |   ");
            Console.WriteLine(@"  /_/   \_\____/ \____\___/|_|_|\___|\___| |__/\___/|_|   ");
            Console.WriteLine();
            Console.WriteLine("  v3.0.1  by dev2null\r\n");
        }


        public static void Print(string output, PrintColor color)
        {
            switch (color)
            {
                case PrintColor.YELLOW:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(output);
                    Console.ResetColor();
                    break;
                case PrintColor.GREEN:
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(output);
                    Console.ResetColor();
                    break;
                case PrintColor.RED:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(output);
                    Console.ResetColor();
                    break;
            }
        }


        public static void Done()
        {
            Print("\n[*] Done!\n", PrintColor.GREEN);
        }



    }
}
