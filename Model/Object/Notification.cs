using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Vulnerator.Model.Object
{
    public class Notification
    {
        public string Accent { get; set; }
        public string Background { get; set; }
        public string Badge { get; set; }
        public string Foreground { get; set; }
        public string Header { get; set; }
        public string Message { get; set; }

        public Notification()
        { }
    }
}
