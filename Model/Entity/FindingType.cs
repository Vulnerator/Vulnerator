namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class FindingType
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public FindingType()
        {
            UniqueFindings = new ObservableCollection<UniqueFinding>();
            ReportFindingTypeUserSettings = new ObservableCollection<ReportFindingTypeUserSettings>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long FindingType_ID { get; set; }

        [Required]
        [StringLength(25)]
        [Column("FindingType")]
        public string Finding_Type { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UniqueFinding> UniqueFindings { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ReportFindingTypeUserSettings> ReportFindingTypeUserSettings { get; set; }
    }
}
