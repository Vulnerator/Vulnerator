using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
   public class PortService : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public PortService()
        { Softwares = new ObservableCollection<Software>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long PortsService_ID { get; set; }

        [Required]
        [StringLength(500)]
        public string DiscoveredServiceName { get; set; }
        
        [Required]
        [StringLength(500)]
        public string DisplayedServiceName { get; set; }

        [Required]
        [StringLength(100)]
        public string ServiceAcronym { get; set; }
        
        [Required]
        public long PortProtocol_ID { get; set; }

        public virtual PortProtocol PortProtocol { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Software> Softwares { get; set; }
    }
}