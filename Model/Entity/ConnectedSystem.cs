namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class ConnectedSystem
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ConnectedSystem()
        { Accreditations = new ObservableCollection<Accreditation>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ConnectedSystem_ID { get; set; }

        [Required]
        [StringLength(100)]
        public string ConnectedSystemName { get; set; }

        [Required]
        [StringLength(5)]
        public string IsAuthorized { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Accreditation> Accreditations { get; set; }
    }
}
