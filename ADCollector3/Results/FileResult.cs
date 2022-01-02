using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    public class FileResult: IResult
    {
        public string Title { get; set ; }
        public FileObject FileObject { get; set; }
    }
}
