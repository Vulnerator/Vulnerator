using System.ComponentModel;

namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class ConfidentialityLevel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ConfidentialityLevel()
        {
            Groups = new ObservableCollection<Group>();
            NIST_Controls = new ObservableCollection<NIST_Control>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ConfidentialityLevel_ID { get; set; }

        [Required]
        [StringLength(25)]
        [Column("ConfidentialityLevel")]
        public string Confidentiality_Level { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NIST_Control> NIST_Controls { get; set; }
    }
}
