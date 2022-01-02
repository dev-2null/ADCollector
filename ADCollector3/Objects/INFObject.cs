using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ADCollector3
{
    public class INFObject : FileObject
    {
        public INFObject(string filePath) : base(filePath) { }
        public static Dictionary<string, INFObject> EnumeratedINFObjects { get; set; } = new Dictionary<string, INFObject>();

        public override void ParseFile()
        {
            try
            {
                //logger.Debug($"Reading {FilePath}...");
                Content = File.ReadAllText(FilePath);
            }
            catch
            {
                logger.Warn($"Unable to parse {FilePath}...");
                return;
            }

            string content = Regex.Replace(Content, @"^\s*;.*$", "", RegexOptions.Multiline);

            //^\[(.+?)\](\r\n.*)+
            //char[] removeSquare = new char[] { '[', ']' };

            foreach (var section in Regex.Split(content, @"\r\n\["))
            {

                var tempSection = section + "\r\n";

                Dictionary<string, string> lines = new Dictionary<string, string>();

                var sectionName = (Regex.Match(tempSection, @"(.*?)\]\r\n", RegexOptions.Singleline)).Value.Trim('\r', '\n', '[', ']');

                foreach (Match m in Regex.Matches(tempSection, @"^\s*(.*?)\s*=(\s(.*?)\s)|(\r\n)$", RegexOptions.Multiline))
                {
                    string key = m.Groups[1].Value.Trim(' ', '\r', '\n');
                    string value = m.Groups[2].Value.Trim(' ', '\r', '\n');
  
                    if (!lines.ContainsKey(key) && (!string.IsNullOrEmpty(key))) { lines[key] = value; }
                }

                if (!Properties.ContainsKey(sectionName)) { Properties[sectionName] = new List<Dictionary<string, string>> { lines }; }
            }

            EnumeratedINFObjects.Add(FilePath, new INFObject(FilePath) { Properties = Properties});
        }
    }
}
