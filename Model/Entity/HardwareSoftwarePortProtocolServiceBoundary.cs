using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("HardwareSoftwarePortsProtocolsServicesBoundaries")]
    public class HardwareSoftwarePortProtocolServiceBoundary : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;


        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long HardwareSoftwarePortProtocolServiceBoundary_ID { get; set; }

        [Required]
        public long HardwareSoftwarePortProtocolService_ID { get; set; }

        public HardwareSoftwarePortProtocolService HardwareSoftwarePortProtocolService { get; set; }

        [Required]
        public long Boundary_ID { get; set; }

        public Boundary Boundary { get; set; }
        
        [StringLength(5)]
        public string CAL_Compliant { get; set; }

        [StringLength(5)]
        public string PPSM_Approved { get; set; }

        [StringLength(25)]
        public string Direction { get; set; }

        [StringLength(100)]
        public string Classification { get; set; }
    }
}
