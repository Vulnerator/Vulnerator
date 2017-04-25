using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Object
{
    [Table("FindingStatuses")]
    public class FindingStatus
    {
        [Key]
        public int StatusIndex { get; set; }
        public string Status { get; set; }
    }
}
