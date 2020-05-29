using System.Collections.ObjectModel;

namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;
    
    [Table("PortsServices")]
    public class PortService
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public PortService()
        { Softwares = new ObservableCollection<Software>(); }

        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long PortsService_ID { get; set; }

        [Required]
        [StringLength(100)]
        public string PortServiceName { get; set; }

        [Required]
        [StringLength(50)]
        public string PortServiceAcronym { get; set; }
        
        [Required]
        public long PortProtocol_ID { get; set; }

        public virtual PortProtocol PortProtocol { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Software> Softwares { get; set; }
    }
}