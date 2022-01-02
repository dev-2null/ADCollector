using System.Collections.Generic;

namespace ADCollector3
{
    public class DLResult : IResult
    {
        public string Title { get; set; }
        public List<Dictionary<string, List<string>>> Result { get; set; }
    }
}
