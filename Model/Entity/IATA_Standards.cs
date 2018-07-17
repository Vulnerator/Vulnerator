namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class IATA_Standards
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public IATA_Standards()
        {
            Accreditations = new ObservableCollection<Accreditation>();
            NistControls = new ObservableCollection<NistControl>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long IATA_Standard_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string Standard_Title { get; set; }

        [Required]
        [StringLength(1000)]
        public string Standard_Description { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Accreditation> Accreditations { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControl> NistControls { get; set; }
    }
}
