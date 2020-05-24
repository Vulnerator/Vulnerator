namespace Vulnerator.Model.Entity
{
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    [Table("Accessibility")]
    public partial class Accessibility
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Accessibility_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string LogicalAccess { get; set; }

        [Required]
        [StringLength(25)]
        public string PhysicalAccess { get; set; }

        [Required]
        [StringLength(25)]
        public string AV_Scan { get; set; }

        [Required]
        [StringLength(25)]
        public string DODIN_ConnectionPeriodicity { get; set; }
    }
}
