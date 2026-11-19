using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Vulnerator.Model.Object
{
    /// <summary>
    /// Holds the Group ID and Hardware ID to be associated / disassociated
    /// </summary>
    public class GroupHardwareMappingDoWorkArguments
    {
        public string GroupName { get; set; }

        public string DiscoveredHostName { get; set; }
    }
}
