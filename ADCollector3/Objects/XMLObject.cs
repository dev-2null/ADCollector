using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace ADCollector3
{
    public class XMLObject : FileObject
    {
        public XMLObject(string filePath) : base(filePath) { }
        public XmlDocument Doc { get; set; } = new XmlDocument();


        public override void ParseFile()
        {
            logger.Debug($"Parsing {FilePath}...");

            try
            {
                Doc.Load(FilePath);
                Content = Doc.InnerXml;
            }
            catch
            {
                logger.Warn($"Unable to access {FilePath}");
            }

            string xmlNode = GetXMLNode(FilePath.Split('\\').Last());

            if (xmlNode == null) { return; }
            XmlNodeList nodes = Doc.DocumentElement.SelectNodes(xmlNode);
            List<Dictionary<string, string>> attrsList = new List<Dictionary<string, string>>();
            try
            {
                foreach (XmlNode node in nodes)
                {
                    Dictionary<string, string> attrs = new Dictionary<string, string>();
                    foreach (XmlAttribute attr in node.Attributes)
                    {
                        attrs.Add(attr.Name, attr.Value);
                    }
                    attrsList.Add(attrs);
                }
            }catch(Exception e)
            {
                Console.WriteLine(e.Message + FilePath);
            }
            //foreach (XmlNode node in nodes)
            //{
            //    foreach (XmlAttribute attr in node.Attributes)
            //    {
            //        attrs.Add(attr.Name, attr.Value);
            //    }
            //}

            Properties.Add(FilePath.Split('\\').Last(), attrsList);
        }



        //https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
        //Search for groups.xml, scheduledtasks.xml, services.xml, datasources.xml, printers.xml and drives.xml
        //findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
        public static string GetXMLNode(string file)
        {
            var gppDict = new Dictionary<string, string>();
            gppDict.Add("Groups.xml", "/Groups/User/Properties");
            gppDict.Add("Services.xml", "/NTServices/NTService/Properties");
            gppDict.Add("Scheduledtasks.xml", "/ScheduledTasks/Task/Properties");
            gppDict.Add("Datasources.xml", "/DataSources/DataSource/Properties");
            gppDict.Add("Printers.xml", "/Printers/SharedPrinter/Properties");
            gppDict.Add("Drives.xml", "/Drives/Drive/Properties");

            if (gppDict.ContainsKey(file))
            {
                return gppDict[file];
            }
            return null;
        }

    }
}
