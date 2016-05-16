using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Vulnerator.Model
{
    public class DiscrepancyItem
    {
        public string VulnId { get; set; }
        public string VulnTitle { get; set; }
        public string RuleId { get; set; }
        public string Status { get; set; }
        public string AssetId { get; set; }
        public string FileName { get; set; }
        public string Source { get; set; }
        public string Comments { get; set; }
        public string FindingDetails { get; set; }
        public string Group { get; set; }

        public DiscrepancyItem()
        { }
    }
}
