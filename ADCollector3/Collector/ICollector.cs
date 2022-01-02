using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADCollector3
{
    public interface ICollector
    {
        IResult Collect(SearchString searchstring);
    }
}
