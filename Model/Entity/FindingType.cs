namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class FindingType
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public FindingType()
        { UniqueFindings = new ObservableCollection<UniqueFinding>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Finding_Type_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string Finding_Type { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UniqueFinding> UniqueFindings { get; set; }
    }
}
