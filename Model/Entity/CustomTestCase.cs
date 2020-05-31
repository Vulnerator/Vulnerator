using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class CustomTestCase : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public CustomTestCase()
        { SecurityAssessmentProcedures = new ObservableCollection<SecurityAssessmentProcedure>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long CustomTestCase_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string TestCaseName { get; set; }

        [Required]
        [StringLength(500)]
        public string TestCaseDescription { get; set; }

        [Required]
        [StringLength(500)]
        public string TestCaseBackground { get; set; }

        [Required]
        [StringLength(25)]
        public string TestCaseClassification { get; set; }

        [Required]
        [StringLength(25)]
        public string TestCaseSeverity { get; set; }

        [Required]
        [StringLength(500)]
        public string TestCaseAssessmentProcedure { get; set; }

        [Required]
        public long TestCase_CCI_ID { get; set; }
        
        public virtual CCI CCI { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityAssessmentProcedure> SecurityAssessmentProcedures { get; set; }
    }
}
