using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;

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
            Locations = new ObservableCollection<Location>();
            HardwarePortsProtocolsServices = new ObservableCollection<HardwarePortProtocolService>();
            SoftwareHardwares = new ObservableCollection<SoftwareHardware>();
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

        /// <summary>Newest ACAS / Nessus result for this host (filled by the Hardware tab, not stored).</summary>
        [NotMapped]
        public System.DateTime? LastAcasScan { get; set; }

        /// <summary>Newest STIG checklist or SCAP (XCCDF) result for this host (filled by the Hardware tab, not stored).</summary>
        [NotMapped]
        public System.DateTime? LastChecklistScan { get; set; }

        /// <summary>The newest of <see cref="LastAcasScan"/> and <see cref="LastChecklistScan"/>.</summary>
        [NotMapped]
        public System.DateTime? LastScan =>
            !LastAcasScan.HasValue ? LastChecklistScan : !LastChecklistScan.HasValue ? LastAcasScan :
            (LastAcasScan.Value > LastChecklistScan.Value ? LastAcasScan : LastChecklistScan);

        /// <summary>"ACAS", "STIG", "ACAS, STIG" or empty: where this host has results.</summary>
        [NotMapped]
        public string ScanSources =>
            string.Join(", ", new[] { LastAcasScan.HasValue ? "ACAS" : null, LastChecklistScan.HasValue ? "STIG" : null }.Where(s => s != null));

        /// <summary>The host's groups, comma separated.</summary>
        [NotMapped]
        public string GroupNames =>
            Groups == null ? string.Empty : string.Join(", ", Groups.Where(g => g != null && g.GroupName != "All").Select(g => g.GroupName).OrderBy(g => g));

        /// <summary>The lifecycle status name.</summary>
        [NotMapped]
        public string LifecycleStatusName => LifecycleStatus?.Lifecycle_Status ?? string.Empty;

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
        public virtual ICollection<Location> Locations { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HardwarePortProtocolService> HardwarePortsProtocolsServices { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SoftwareHardware> SoftwareHardwares { get; set; }
    }
}
