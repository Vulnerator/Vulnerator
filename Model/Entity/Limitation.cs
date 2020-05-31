using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class Limitation : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Limitation()
        {
            SecurityAssessmentProcedures = new ObservableCollection<SecurityAssessmentProcedure>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Limitation_ID { get; set; }

        [Required]
        [StringLength(100)]
        public string LimitationSummary { get; set; }

        [Required]
        [StringLength(500)]
        public string LimitationBackground { get; set; }

        [Required]
        [StringLength(500)]
        public string LimitationDetails { get; set; }

        [Required]
        [StringLength(5)]
        public string IsTestException { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityAssessmentProcedure> SecurityAssessmentProcedures { get; set; }
    }
}
