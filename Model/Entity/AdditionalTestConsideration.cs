using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;


namespace Vulnerator.Model.Entity
{
    public class AdditionalTestConsideration : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public AdditionalTestConsideration()
        { SecurityAssessmentProcedures = new ObservableCollection<SecurityAssessmentProcedure>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AdditionalTestConsideration_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string AdditionalTestConsiderationTitle { get; set; }

        [Required]
        [StringLength(1000)]
        public string AdditionalTestConsiderationDetails { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityAssessmentProcedure> SecurityAssessmentProcedures { get; set; }
    }
}
