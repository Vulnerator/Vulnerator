namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class CCI
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public CCI()
        {
            NIST_ControlsCCIs = new ObservableCollection<NIST_ControlCCI>();
            Vulnerabilities = new ObservableCollection<Vulnerability>();
            GroupsCCIs = new ObservableCollection<GroupsCCIs>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long CCI_ID { get; set; }
        
        [Required]
        [StringLength(25)]
        public string CCI_Number { get; set; }

        [Required]
        [StringLength(500)]
        public string CCI_Definition { get; set; }

        [Required]
        [StringLength(25)]
        public string CCI_Type { get; set; }

        [Required]
        [StringLength(25)]
        public string CCI_Status { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NIST_ControlCCI> NIST_ControlsCCIs { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Vulnerability> Vulnerabilities { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<GroupsCCIs> GroupsCCIs { get; set; }
    }
}
