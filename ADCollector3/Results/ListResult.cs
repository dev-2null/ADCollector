using System.Collections.Generic;

namespace ADCollector3
{
    public class ListResult : IResult
    {
        public string Title { get; set; }
        public List<string> Result { get; set; }
    }
}
