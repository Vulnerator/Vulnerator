using System.ComponentModel;

namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    [Table("ControlSelection")]
    public partial class ControlSelection : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ControlSelection()
        { Groups = new ObservableCollection<Group>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ControlSelection_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string IsTierOneApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string TierOneAppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsTierTwoApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string TierTwoAppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsTierThreeApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string TierThreeAppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsCNSS_1253_Applied { get; set; }

        [Required]
        [StringLength(50)]
        public string CNSS_1253_AppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsSpaceApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string SpaceAppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsCDS_Applied { get; set; }

        [StringLength(50)]
        public string CDS_AppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsIntelligenceApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string IntelligenceAppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsClassifiedApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string ClassifiedAppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsOtherApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string OtherAppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string AreCompensatingControlsApplied { get; set; }

        [Required]
        [StringLength(50)]
        public string CompensatingControlsAppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string HasNA_BaselineControls { get; set; }

        [Required]
        [StringLength(100)]
        public string NA_BaselineControlsAppliedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string AreBaselineControlsModified { get; set; }

        [Required]
        [StringLength(100)]
        public string BaselineIsModifiedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsBaselineRiskModified { get; set; }

        [Required]
        [StringLength(100)]
        public string BaselineRiskIsModificationJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string IsBaselineScopeApproved { get; set; }

        [Required]
        [StringLength(100)]
        public string BaselineScopeIsApprovedJustification { get; set; }

        [Required]
        [StringLength(5)]
        public string AreInheritableControlsDefined { get; set; }

        [Required]
        [StringLength(100)]
        public string InheritableControlsAreDefinedJustification { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }
    }
}
