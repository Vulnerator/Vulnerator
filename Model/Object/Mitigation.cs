using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Object
{
    [Table("LongRunningMitigations")]
    public class Mitigation
    {
        [Key]
        public int? MitigationIndex { get; set; }
        [Required]
        public string VulnId { get; set; }
        [Required]
        public string Text { get; set; }
        [Required]
        public string DateEntered { get; set; }
        [Required]
        public string DateExpires { get; set; }
        [Required]
        public int? StatusIndex { get; set; }
        public int? AssetIndex { get; set; }
        public int? GroupIndex { get; set; }
        public Group Group { get; set; }
        public Asset Asset { get; set; }
        public FindingStatus FindingStatus { get; set; }
        [NotMapped]
        public bool IsChecked { get; set; }
    }
}
