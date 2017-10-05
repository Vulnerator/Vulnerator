namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    [Table("Software")]
    public partial class Software : INotifyPropertyChanged
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Software()
        {
            SoftwareHardwares = new HashSet<SoftwareHardware>();
            DADMS_Networks = new HashSet<DADMS_Networks>();
            Contacts = new HashSet<Contact>();
        }

        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Software_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string Discovered_Software_Name { get; set; }

        [Required]
        [StringLength(100)]
        public string Displayed_Software_Name { get; set; }

        [StringLength(25)]
        public string Software_Acronym { get; set; }

        [StringLength(25)]
        public string Software_Version { get; set; }

        [StringLength(500)]
        public string Function { get; set; }

        [StringLength(25)]
        public string DADMS_ID { get; set; }

        [StringLength(25)]
        public string DADMS_Disposition { get; set; }

        public DateTime? DADMS_LDA { get; set; }

        [StringLength(5)]
        public string Has_Custom_Code { get; set; }

        [StringLength(5)]
        public string IaOrIa_Enabled { get; set; }

        [StringLength(5)]
        public string Is_OS_Or_Firmware { get; set; }

        [StringLength(5)]
        public string FAM_Accepted { get; set; }

        [StringLength(5)]
        public string Externally_Authorized { get; set; }

        [StringLength(5)]
        public string ReportInAccreditation_Global { get; set; }

        [StringLength(5)]
        public string ApprovedForBaseline_Global { get; set; }

        [StringLength(50)]
        public string BaselineApprover_Global { get; set; }

        [StringLength(25)]
        public string Instance { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SoftwareHardware> SoftwareHardwares { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<DADMS_Networks> DADMS_Networks { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Contact> Contacts { get; set; }
    }
}
