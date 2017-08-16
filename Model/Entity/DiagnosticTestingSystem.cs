namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class DiagnosticTestingSystem
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public DiagnosticTestingSystem()
        {
            PIT_Determination = new HashSet<PIT_Determination>();
        }

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
