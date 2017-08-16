namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("ControlSelection")]
    public partial class ControlSelection
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ControlSelection()
        {
            Accreditations = new HashSet<Accreditation>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ControlSelection_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string TierOneApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string TierOneJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string TierTwoApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string TierTwoJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string TierThreeApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string TierThreeJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string CNSS_1253_Applied { get; set; }

        [Required]
        [StringLength(50)]
        public string CNSS_1253_Justification { get; set; }

        [Required]
        [StringLength(5)]
        public string SpaceApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string SpaceJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string CDS_Applied { get; set; }

        [StringLength(50)]
        public string CDS_Justification { get; set; }

        [Required]
        [StringLength(5)]
        public string IntelligenceApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string IntelligenceJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string ClassifiedApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string ClassifiedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string OtherApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string OtherJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string CompensatingControlsApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string CompensatingControlsJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string NA_BaselineControls { get; set; }

        [Required]
        [StringLength(100)]
        public string NA_BaselineControlsJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string BaselineControlsModified { get; set; }

        [Required]
        [StringLength(100)]
        public string ModifiedBaselineJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string BaselineRiskModified { get; set; }

        [Required]
        [StringLength(100)]
        public string BaselineRiskModificationJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string BaselineScopeApproved { get; set; }

        [Required]
        [StringLength(100)]
        public string BaselineScopeJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string InheritableControlsDefined { get; set; }

        [Required]
        [StringLength(100)]
        public string InheritableControlsJustification { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Accreditation> Accreditations { get; set; }
    }
}
