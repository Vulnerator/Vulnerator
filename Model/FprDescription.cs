using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Vulnerator.Model
{
    public class FprDescription
    {
        public string ClassId = string.Empty;
        public string VulnTitle = string.Empty;
        public string RiskStatement = string.Empty;
        public string Description = string.Empty;
        public string FixText = string.Empty;
        public Dictionary<string, string> References = new Dictionary<string, string>();
        public string InstanceId = string.Empty;
    }
}
