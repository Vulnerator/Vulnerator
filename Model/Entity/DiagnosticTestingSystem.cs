namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class DiagnosticTestingSystem
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public DiagnosticTestingSystem()
        { PIT_Determination = new ObservableCollection<PIT_Determination>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long DiagnosticTesting_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string BuiltInTestingEquipment { get; set; }

        [Required]
        [StringLength(5)]
        public string PortableTestingEquipment { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<PIT_Determination> PIT_Determination { get; set; }
    }
}
