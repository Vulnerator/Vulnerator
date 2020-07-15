using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("HardwareSoftwarePortsProtocolsServices")]
    public class HardwareSoftwarePortProtocolService : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        public HardwareSoftwarePortProtocolService()
        {
            HardwareSoftwarePortsProtocolsServicesBoundaries = new ObservableCollection<HardwareSoftwarePortProtocolServiceBoundary>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long HardwareSoftwarePortProtocolService_ID { get; set; }

        [Required]
        public long HardwarePortProtocolService_ID { get; set; }

        public virtual HardwarePortProtocolService HardwarePortProtocolService { get; set; }

        [Required]
        public long Software_ID { get; set; }

        public virtual Software Software { get; set; }

        [StringLength(5)]
        public string ReportInAccreditation { get; set; }

        [StringLength(25)]
        public string Direction { get; set; }

        [StringLength(100)]
        public string BoundariesCrossed { get; set; }

        [StringLength(5)]
        public string DOD_Compliant { get; set; }

        [StringLength(100)]
        public string Classification { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HardwareSoftwarePortProtocolServiceBoundary> HardwareSoftwarePortsProtocolsServicesBoundaries { get; set; }
    }
}
