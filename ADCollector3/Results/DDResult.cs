using System.Collections.Generic;

namespace ADCollector3
{
    public class DDResult : IResult
    {
        public string Title { get; set; }
        public Dictionary<string, Dictionary<string, string>> Result { get; set; }
    }
}
