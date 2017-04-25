using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Collections.Generic;

namespace Vulnerator.Model.Object
{
    [Table("Groups")]
    public class Group
    {
        [Key]
        public int? GroupIndex { get; set; }
        [Required]
        public string ProjectName { get; set; }
        public string AccreditationName { get; set;}
        List<Mitigation> LongRunningMitigations { get; set; }
    }
}
