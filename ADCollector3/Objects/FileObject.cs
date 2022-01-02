using NLog;
using System;
using System.Collections.Generic;

namespace ADCollector3
{
    public abstract class FileObject
    {
        public Logger logger;
        public string FilePath { get; set; }
        public string GPO { get; set; }
        public string Content { get; set; }
        public Dictionary<string, List<Dictionary<string, string>>> Properties { get; set; } = new Dictionary<string, List<Dictionary<string, string>>>();

        public FileObject(string filePath)
        {
            logger = LogManager.GetCurrentClassLogger();
            FilePath = filePath;
            string gpoID = FilePath.Split('{')[1].Split('}')[0].ToUpper();
            try
            {

                GPO = ADCollector3.GPO.GroupPolicies["{"+ gpoID+"}"] + " {"+ gpoID + "}";
            }
            catch { logger.Warn($"GPO GUID {gpoID} Does not Exist"); }

            //ParseFile();
            //if (HasCondition()) { ParseFile(); }
        }

        public abstract void ParseFile();
        //public virtual bool HasCondition() { return true; }

    }
}
