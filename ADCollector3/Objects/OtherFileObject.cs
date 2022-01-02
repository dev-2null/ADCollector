using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ADCollector3
{
    public class OtherFileObject : FileObject
    {
        public OtherFileObject(string filePath) : base(filePath) { }

        public override void ParseFile()
        {
            try
            {
                logger.Debug($"Reading {FilePath}...");
                Content = File.ReadAllText(FilePath);
            }
            catch
            {
                logger.Warn($"Unable to parse {FilePath}...");
                return;
            }
        }
    }
}
