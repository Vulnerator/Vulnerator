using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("Hardware")]
    public class Hardware : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Hardware()
        {
            SCAP_Scores = new ObservableCollection<SCAP_Score>();
            UniqueFindings = new ObservableCollection<UniqueFinding>();
            Contacts = new ObservableCollection<Contact>();
            EnumeratedWindowsGroups = new ObservableCollection<EnumeratedWindowsGroup>();
            Groups = new ObservableCollection<Group>();
            IP_Addresses = new ObservableCollection<IP_Address>();
            MAC_Addresses = new ObservableCollection<MAC_Address>();
            VulnerabilitySources = new ObservableCollection<VulnerabilitySource>();
            Locations = new ObservableCollection<Location>();
            PortsProtocolsServices = new ObservableCollection<PortProtocolService>();
            Softwares = new ObservableCollection<Software>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Hardware_ID { get; set; }

        [StringLength(50)]
        public string DisplayedHostName { get; set; }

        [StringLength(50)]
        public string DiscoveredHostName { get; set; }

        [StringLength(500)]
        public string FQDN { get; set; }

        [StringLength(300)]
        public string NetBIOS { get; set; }

        [StringLength(50)]
        public string ScanIP { get; set; }

        [StringLength(5)]
        public string Found21745 { get; set; }

        [StringLength(5)]
        public string Found26917 { get; set; }

        [StringLength(5)]
        public string IsVirtualServer { get; set; }

        [StringLength(25)]
        public string NIAP_Level { get; set; }

        [StringLength(25)]
        public string Manufacturer { get; set; }

        [StringLength(50)]
        public string ModelNumber { get; set; }

        [StringLength(5)]
        public string IsIA_Enabled { get; set; }

        [StringLength(50)]
        public string SerialNumber { get; set; }

        [StringLength(25)]
        public string Role { get; set; }

        public long? LifecycleStatus_ID { get; set; }

        public virtual LifecycleStatus LifecycleStatus { get; set; }

        [StringLength(100)]
        public string OperatingSystem { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SCAP_Score> SCAP_Scores { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UniqueFinding> UniqueFindings { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Contact> Contacts { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EnumeratedWindowsGroup> EnumeratedWindowsGroups { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IP_Address> IP_Addresses { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MAC_Address> MAC_Addresses { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<VulnerabilitySource> VulnerabilitySources { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Location> Locations { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<PortProtocolService> PortsProtocolsServices { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Software> Softwares { get; set; }
    }
}
