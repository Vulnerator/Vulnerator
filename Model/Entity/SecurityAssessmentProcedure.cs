using System.ComponentModel;

namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class SecurityAssessmentProcedure : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public SecurityAssessmentProcedure()
        {
            Groups = new HashSet<Group>();
            AdditionalTestConsiderations = new HashSet<AdditionalTestConsideration>();
            CustomTestCases = new HashSet<CustomTestCase>();
            EntranceCriterias = new HashSet<EntranceCriteria>();
            ExitCriterias = new HashSet<ExitCriteria>();
            Limitations1 = new HashSet<Limitation>();
            RelatedDocuments = new HashSet<RelatedDocument>();
            RelatedTestings = new HashSet<RelatedTesting>();
            TestReferences = new HashSet<TestReference>();
            TestScheduleItems = new HashSet<TestScheduleItem>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SecurityAssessmentProcedure_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string Scope { get; set; }

        [Required]
        [StringLength(500)]
        public string Limitations { get; set; }

        [Required]
        [StringLength(2000)]
        public string TestConfiguration { get; set; }

        [Required]
        [StringLength(1000)]
        public string LogisiticsSupport { get; set; }

        [Required]
        [StringLength(1000)]
        public string Security { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AdditionalTestConsideration> AdditionalTestConsiderations { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<CustomTestCase> CustomTestCases { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EntranceCriteria> EntranceCriterias { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ExitCriteria> ExitCriterias { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Limitation> Limitations1 { get; set; }

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
