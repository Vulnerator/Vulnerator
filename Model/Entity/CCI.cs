using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class CCI : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public CCI()
        {
            Vulnerabilities = new ObservableCollection<Vulnerability>();
            Groups = new ObservableCollection<Group>();
            CustomTestCases = new ObservableCollection<CustomTestCase>();
            NIST_ControlsCCIs = new ObservableCollection<NIST_ControlCCI>();
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
        public virtual ICollection<Vulnerability> Vulnerabilities { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<CustomTestCase> CustomTestCases { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NIST_ControlCCI> NIST_ControlsCCIs { get; set; }
    }
}
