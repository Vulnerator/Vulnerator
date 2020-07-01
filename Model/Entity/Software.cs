using System.Collections.ObjectModel;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("Software")]
    public class Software : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Software()
        {
            DADMS_Networks = new ObservableCollection<DADMS_Network>();
            Contacts = new ObservableCollection<Contact>();
            Hardwares = new ObservableCollection<Hardware>();
            UniqueFindings = new ObservableCollection<UniqueFinding>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Software_ID { get; set; }

        [Required]
        [StringLength(200)]
        public string DiscoveredSoftwareName { get; set; }

        [Required]
        [StringLength(200)]
        public string DisplayedSoftwareName { get; set; }

        [StringLength(50)]
        public string SoftwareAcronym { get; set; }

        [StringLength(25)]
        public string SoftwareVersion { get; set; }

        [StringLength(500)]
        public string Function { get; set; }

        [StringLength(25)]
        public string DADMS_ID { get; set; }

        [StringLength(25)]
        public string DADMS_Disposition { get; set; }

        public DateTime? DADMS_LastDateAuthorized { get; set; }

        [StringLength(5)]
        public string HasCustomCode { get; set; }

        [StringLength(5)]
        public string IA_OrIA_Enabled { get; set; }

        [StringLength(5)]
        public string IsOS_OrFirmware { get; set; }

        [StringLength(5)]
        public string FAM_Accepted { get; set; }

        [StringLength(5)]
        public string ExternallyAuthorized { get; set; }

        [StringLength(5)]
        public string ReportInAccreditationGlobal { get; set; }

        [StringLength(5)]
        public string ApprovedForBaselineGlobal { get; set; }

        [StringLength(50)]
        public string BaselineApproverGlobal { get; set; }

        [StringLength(25)]
        public string Instance { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<DADMS_Network> DADMS_Networks { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Contact> Contacts { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UniqueFinding> UniqueFindings { get; set; }
    }
}
