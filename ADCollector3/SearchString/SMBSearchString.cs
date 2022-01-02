using System.Collections.Generic;

namespace ADCollector3
{
    public class SMBSearchString : SearchString
    {
        public string Title { get; set; }
        public string FilePath { get; set; }
        public List<string> FilePathList { get; set; }
        
        //filePath: sections/properties
        public List<string> FileAttributes { get; set; }

    }
}
