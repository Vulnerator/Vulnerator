using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Vulnerator.Model.Object
{
    public class Report
    {
        [Key]
        public int ReportId { get; set; }
        [Required]
        public string Name { get; set; }
        [Required]
        public string BoundProperty { get; set; }
        [Required]
        public string Type { get; set; }
        [Required]
        public string Category { get; set; }

        public Report(string name, string boundProperty, string type, string category)
        {

        }
    }
}
