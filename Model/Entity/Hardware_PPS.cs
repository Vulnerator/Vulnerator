namespace Vulnerator.Model.Entity
{
    using System.ComponentModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class HardwarePortsProtocols : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Hardware_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long PortsProtocols_ID { get; set; }

        [StringLength(5)]
        public string ReportInAccreditation { get; set; }

        [Key]
        [Column(Order = 2)]
        [StringLength(25)]
        public string DiscoveredService { get; set; }

        [StringLength(50)]
        public string DisplayService { get; set; }

        [StringLength(25)]
        public string Direction { get; set; }

        [StringLength(25)]
        public string BoundaryCrossed { get; set; }

        [StringLength(5)]
        public string DoD_Compliant { get; set; }

        [StringLength(25)]
        public string Classification { get; set; }

        public virtual Hardware Hardware { get; set; }

        public virtual PortsProtocols PP { get; set; }
    }
}
