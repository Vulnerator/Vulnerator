namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("Hardware")]
    public partial class Hardware
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Hardware()
        {
            Hardware_PPS = new HashSet<Hardware_PPS>();
            HardwareLocations = new HashSet<HardwareLocation>();
            ScapScores = new HashSet<ScapScore>();
            SoftwareHardwares = new HashSet<SoftwareHardware>();
            UniqueFindings = new HashSet<UniqueFinding>();
            Contacts = new HashSet<Contact>();
            EnumeratedWindowsGroups = new HashSet<EnumeratedWindowsGroup>();
            Groups = new HashSet<Group>();
            IP_Addresses = new HashSet<IP_Addresses>();
            MAC_Addresses = new HashSet<MAC_Addresses>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Hardware_ID { get; set; }

        [StringLength(50)]
        public string Displayed_Host_Name { get; set; }

        [StringLength(50)]
        public string Host_Name { get; set; }

        [StringLength(100)]
        public string FQDN { get; set; }

        [StringLength(100)]
        public string NetBIOS { get; set; }

        [StringLength(25)]
        public string Scan_IP { get; set; }

        [StringLength(5)]
        public string Found_21745 { get; set; }

        [StringLength(5)]
        public string Found_26917 { get; set; }

        [StringLength(5)]
        public string Is_Virtual_Server { get; set; }

        [StringLength(25)]
        public string NIAP_Level { get; set; }

        [StringLength(25)]
        public string Manufacturer { get; set; }

        [StringLength(50)]
        public string ModelNumber { get; set; }

        [StringLength(5)]
        public string Is_IA_Enabled { get; set; }

        [StringLength(50)]
        public string SerialNumber { get; set; }

        [StringLength(25)]
        public string Role { get; set; }

        [StringLength(100)]
        public string OS { get; set; }

        public long? LifecycleStatus_ID { get; set; }

        public virtual LifecycleStatus LifecycleStatus { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware_PPS> Hardware_PPS { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HardwareLocation> HardwareLocations { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ScapScore> ScapScores { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SoftwareHardware> SoftwareHardwares { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UniqueFinding> UniqueFindings { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Contact> Contacts { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EnumeratedWindowsGroup> EnumeratedWindowsGroups { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IP_Addresses> IP_Addresses { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MAC_Addresses> MAC_Addresses { get; set; }
    }
}
