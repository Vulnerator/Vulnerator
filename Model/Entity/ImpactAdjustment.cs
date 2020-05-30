namespace Vulnerator.Model.Entity
{
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class ImpactAdjustment
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ImpactAdjustment_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string AdjustedConfidentiality { get; set; }

        [Required]
        [StringLength(25)]
        public string AdjustedIntegrity { get; set; }

        [Required]
        [StringLength(25)]
        public string AdjustedAvailability { get; set; }
        
        public virtual SystemCategorization SystemCategorization { get; set; }
    }
}
