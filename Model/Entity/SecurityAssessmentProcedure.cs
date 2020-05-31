using System.ComponentModel;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class SecurityAssessmentProcedure : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public SecurityAssessmentProcedure()
        {
            AdditionalTestConsiderations = new ObservableCollection<AdditionalTestConsideration>();
            CustomTestCases = new ObservableCollection<CustomTestCase>();
            EntranceCriterias = new ObservableCollection<EntranceCriteria>();
            ExitCriterias = new ObservableCollection<ExitCriteria>();
            Limitations = new ObservableCollection<Limitation>();
            RelatedDocuments = new ObservableCollection<RelatedDocument>();
            RelatedTestings = new ObservableCollection<RelatedTesting>();
            TestReferences = new ObservableCollection<TestReference>();
            TestScheduleItems = new ObservableCollection<TestScheduleItem>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SecurityAssessmentProcedure_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string Scope { get; set; }

        [Required]
        [StringLength(2000)]
        public string TestConfiguration { get; set; }

        [Required]
        [StringLength(1000)]
        public string LogisticsSupport { get; set; }

        [Required]
        [StringLength(1000)]
        public string Security { get; set; }

        public virtual Group Group { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AdditionalTestConsideration> AdditionalTestConsiderations { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<CustomTestCase> CustomTestCases { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EntranceCriteria> EntranceCriterias { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ExitCriteria> ExitCriterias { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Limitation> Limitations { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<RelatedDocument> RelatedDocuments { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<RelatedTesting> RelatedTestings { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<TestReference> TestReferences { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<TestScheduleItem> TestScheduleItems { get; set; }
    }
}
