using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using System.Linq;
using static ADCollector3.Helper;
using System.Text.RegularExpressions;

namespace ADCollector3
{
    public class CollectSYSVOL
    {
        private static Logger _logger { get; set; } = LogManager.GetCurrentClassLogger();
        public static Regex groupMemRX { get; set; } = new Regex("__");

        public static FileResult Collect(SearchString searchstring)
        {
            SMBSearchString searchString = (SMBSearchString)searchstring;
            if (searchString.FilePath == null | searchString.FilePath == string.Empty) { return null; }
            string filePath = searchString.FilePath;

            if (!File.Exists(filePath)){ return null; }

            try
            {
                switch (Path.GetExtension(filePath).ToLower())
                {
                    case ".inf":
                        if (INFObject.EnumeratedINFObjects.ContainsKey(filePath))
                        {
                            return new FileResult { FileObject = CollectFileObject(INFObject.EnumeratedINFObjects[filePath], searchString) };
                        }
                        else
                        {
                            var infFile = new INFObject(filePath);
                            infFile.ParseFile();
                            return new FileResult { FileObject = CollectFileObject(infFile, searchString) };
                        }
                        
                    case ".xml":
                        var xmlFile = new XMLObject(filePath);
                        xmlFile.ParseFile();
                        return new FileResult { FileObject = CollectFileObject(xmlFile, searchString) };
                    default:
                        var otherFile = new OtherFileObject(filePath);
                        otherFile.ParseFile();
                        return new FileResult { FileObject = CollectFileObject(otherFile, searchString) }; 
                }
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
                return null;
            }
            

        }


        public static FileObject CollectFileObject(FileObject fileObject, SearchString searchstring)
        {
            
            SMBSearchString searchString = (SMBSearchString)searchstring;
            Dictionary<string, List<Dictionary<string, string>>> Properties = new Dictionary<string, List<Dictionary<string, string>>>();
            try
            {
                if (fileObject is INFObject)
                {
                    foreach (var property in fileObject.Properties)
                    {
                        if (searchString.FileAttributes.Contains(property.Key))
                        {
                            Dictionary<string, string> attributes = new Dictionary<string, string>();

                            foreach (var attr in property.Value.First())
                            {
                                attributes.Add(CheckGroupName(attr.Key), CheckGroupName(attr.Value));
                            }
                            Properties.Add(property.Key, new List<Dictionary<string, string>> { attributes });
                        }
                    }
                }
                else if (fileObject is XMLObject)
                {
                    foreach (var property in fileObject.Properties)
                    {
                        var attrsList = new List<Dictionary<string, string>>();

                        foreach (var attrDict in property.Value)
                        {
                            var attrs = new Dictionary<string, string>();
                            foreach (var attr in attrDict)
                            {
                                if (searchString.FileAttributes.Contains(attr.Key))
                                {
                                    attrs.Add(attr.Key, attr.Value);
                                }
                            }
                            if (attrs.Count != 0) { attrsList.Add(attrs); }

                        }
                        if (attrsList.Count != 0) { Properties.Add(property.Key, attrsList); }
                    }
                }
            }catch(Exception e)
            {
                logger.Error($"{fileObject.FilePath}: {e.Message}");
            }
            
            if (Properties.Count == 0) { return null; }

            fileObject.Properties = Properties;
            return fileObject;
        }


        public static string CheckGroupName(string name)
        {
            if (name == string.Empty) { return name; }

            //*S-1-5-21-2964291000-3697813071-3260305335-2606__Memberof = *S-1-5-32-555,*S-1-5-32-544
            string value = "";
            try
            {
                if (name.Contains("__"))
                {
                    string groupName = groupMemRX.Split(name)[0];
                    string relation = groupMemRX.Split(name)[1];
                    if (groupName.Contains("*"))
                    {
                        groupName = ConvertSIDToName(groupName.Replace("*", null));
                    }
                    value = string.Format($"{groupName} ({relation})");
                }
                else
                {
                    foreach (var v in name.Split(','))
                    {
                        string sid = v.Replace(",", null);
                        value += sid.Contains("*") ? (ConvertSIDToName(sid.Replace("*", null)) + ",") : (sid + ",");
                    }
                    value = value.Trim(',');
                }
            }
            catch(Exception e)
            {
                logger.Error($"{name}:{e.Message}");
            }
            
            return value;
        }

        public static bool CanConnectSYSVOL()
        {
            string sysvolPath = $"\\\\{Searcher.LdapInfo.DomainController}\\SYSVOL\\{Searcher.LdapInfo.DomainName}\\";

            try
            {
                var accessControlList = Directory.GetAccessControl(sysvolPath);
                if (accessControlList == null)
                {
                    logger.Error("Unable to access SYSVOL");
                    return false;
                }
            }
            catch
            {
                logger.Error("Unable to access SYSVOL");
                return false;
            }
            
            return true;
        }

    }
}
