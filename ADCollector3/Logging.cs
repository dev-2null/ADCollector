using NLog;
using NLog.Config;
using NLog.Targets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    public class Logging
    {
        public static void LoadNormalConfig(LoggingConfiguration config)
        {
            ColoredConsoleTarget consoleTarget = new ColoredConsoleTarget
            {
                Name = "console",
                Layout = "[x] ${message}"
            };
            
            config.AddRule(LogLevel.Error, LogLevel.Fatal, consoleTarget, "*");
            SetConsoleColor(consoleTarget);
            LogManager.Configuration = config;
        }

        public static void LoadDebugConfig(LoggingConfiguration config)
        {
            ColoredConsoleTarget consoleTarget = new ColoredConsoleTarget
            {
                Name = "console",
                Layout = "[!] ${level:uppercase=true} (${callsite}): ${message}"
            };
            config.AddRule(LogLevel.Debug, LogLevel.Fatal, consoleTarget, "*");
            SetConsoleColor(consoleTarget);
            LogManager.Configuration = config;
        }

        public static void SetConsoleColor(ColoredConsoleTarget consoleTarget)
        {
            consoleTarget.RowHighlightingRules.Add(new ConsoleRowHighlightingRule { Condition = "level == LogLevel.Info", ForegroundColor = ConsoleOutputColor.Green });
            consoleTarget.RowHighlightingRules.Add(new ConsoleRowHighlightingRule { Condition = "level == LogLevel.Debug", ForegroundColor = ConsoleOutputColor.Yellow });
            consoleTarget.RowHighlightingRules.Add(new ConsoleRowHighlightingRule { Condition = "level == LogLevel.Trace", ForegroundColor = ConsoleOutputColor.DarkGreen });
            consoleTarget.RowHighlightingRules.Add(new ConsoleRowHighlightingRule { Condition = "level == LogLevel.Warn", ForegroundColor = ConsoleOutputColor.Red });
            consoleTarget.RowHighlightingRules.Add(new ConsoleRowHighlightingRule { Condition = "level == LogLevel.Error", ForegroundColor = ConsoleOutputColor.DarkRed });
        }

        public static void LoadLoggingConfig(bool debug)
        {
            LoggingConfiguration config = new LoggingConfiguration(); 
            if (debug)
            {
                LoadDebugConfig(config);
            }
            else
            {
                LoadNormalConfig(config);
            }
        }
    }
}
