using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("Boundaries")]
    public class Boundary : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Boundary()
        { HardwareSoftwarePortsProtocolsServicesBoundaries = new ObservableCollection<HardwareSoftwarePortProtocolServiceBoundary>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Boundary_ID { get; set; }
        
        [Required]
        [StringLength(50)]
        public string BoundaryName { get; set; }

        [StringLength(50)]
        public string BoundaryAlternateName { get; set; }

        [StringLength(25)]
        public string BoundaryAcronym { get; set; }

        [StringLength(50)]
        public string BoundaryType { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HardwareSoftwarePortProtocolServiceBoundary> HardwareSoftwarePortsProtocolsServicesBoundaries { get; set; }
    }
}
