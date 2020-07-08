using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("PortsProtocolsServices")]
    public class PortProtocolService : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public PortProtocolService()
        {
            HardwarePortsProtocolsServices = new ObservableCollection<HardwarePortProtocolService>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long PortProtocolService_ID { get; set; }

        [Required]
        public long Port { get; set; }

        [Required]
        [StringLength(25)]
        public string Protocol { get; set; }
        
        [Required]
        public string DiscoveredServiceName { get; set; }
        
        public string DisplayedServiceName { get; set; }
        
        public string ServiceAcronym { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HardwarePortProtocolService> HardwarePortsProtocolsServices { get; set; }
    }
}
