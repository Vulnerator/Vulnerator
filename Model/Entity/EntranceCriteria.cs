using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class EntranceCriteria : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public EntranceCriteria()
        { SecurityAssessmentProcedures = new ObservableCollection<SecurityAssessmentProcedure>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long EntranceCriteria_ID { get; set; }

        [Column("EntranceCriteria")]
        [Required]
        [StringLength(100)]
        public string Entrance_Criteria { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityAssessmentProcedure> SecurityAssessmentProcedures { get; set; }
    }
}
