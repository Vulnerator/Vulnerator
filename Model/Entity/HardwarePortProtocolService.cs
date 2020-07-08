using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("HardwarePortsProtocolsServices")]
    public class HardwarePortProtocolService : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public HardwarePortProtocolService()
        {
            HardwareSoftwarePortsProtocolsServices = new ObservableCollection<HardwareSoftwarePortProtocolService>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long HardwarePortProtocolService_ID { get; set; }

        [Required]
        public long Hardware_ID { get; set; }

        public virtual Hardware Hardware { get; set; }

        [Required]
        public long PortProtocolService_ID { get; set; }

        public virtual PortProtocolService PortProtocolService { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HardwareSoftwarePortProtocolService> HardwareSoftwarePortsProtocolsServices { get; set; }

        
    }
}
