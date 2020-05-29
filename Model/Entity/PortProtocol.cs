using System.Collections.ObjectModel;

namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("PortsProtocols")]
    public partial class PortProtocol : INotifyPropertyChanged
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public PortProtocol()
        {
            Hardwares = new ObservableCollection<Hardware>();
            PortServices = new ObservableCollection<PortService>();
        }

        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long PortProtocol_ID { get; set; }

        public long Port { get; set; }

        [Required]
        [StringLength(25)]
        public string Protocol { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<PortService> PortServices { get; set; }
    }
}
