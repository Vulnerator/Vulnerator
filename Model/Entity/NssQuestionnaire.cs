namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("NssQuestionnaire")]
    public partial class NssQuestionnaire
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public NssQuestionnaire()
        {
            SystemCategorizations = new HashSet<SystemCategorization>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NssQuestionnaire_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string InvolvesIntelligenceActivities { get; set; }

        [Required]
        [StringLength(5)]
        public string InvolvesCryptoActivities { get; set; }

        [Required]
        [StringLength(5)]
        public string InvolvesCommandAndControl { get; set; }

        [Required]
        [StringLength(5)]
        public string IsMilitaryCritical { get; set; }

        [Required]
        [StringLength(5)]
        public string IsBusinessInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string HasExecutiveOrderProtections { get; set; }

        [Required]
        [StringLength(5)]
        public string IsNss { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SystemCategorization> SystemCategorizations { get; set; }
    }
}
