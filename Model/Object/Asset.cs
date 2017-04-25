using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Object
{
    [Table("Assets")]
    public class Asset
    {
        [Key]
        public int? AssetIndex { get; set; }
        [Required]
        public string AssetIdToReport { get; set; }
        public string HostName { get; set; }
        public string IpAddress { get; set; }
        public string OperatingSystem { get; set; }
        public string IsCredentialed { get; set; }
        public string Found21745 { get; set; }
        public string Found26917 { get; set; }
        [Required]
        public int? GroupIndex { get; set; }
        public Group Group { get; set; }
    }
}
