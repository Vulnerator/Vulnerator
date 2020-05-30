using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class TestScheduleItem : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public TestScheduleItem()
        {
            SecurityAssessmentProcedures = new ObservableCollection<SecurityAssessmentProcedure>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long TestScheduleItem_ID { get; set; }

        [Required]
        [StringLength(200)]
        public string TestEvent { get; set; }
        
        [Required]
        [StringLength(25)]
        public string TestScheduleCategory { get; set; }

        public long DurationInDays { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityAssessmentProcedure> SecurityAssessmentProcedures { get; set; }
    }
}
