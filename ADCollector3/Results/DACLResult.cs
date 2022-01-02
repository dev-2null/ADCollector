using System.Collections.Generic;

namespace ADCollector3
{
    public class DACLResult : IResult
    {
        public string Title { get; set; }
        public List<DACL> Result { get; set; }
    }
}
