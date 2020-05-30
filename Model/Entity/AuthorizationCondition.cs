namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class AuthorizationCondition
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public AuthorizationCondition()
        {
            AuthorizationInformations = new ObservableCollection<AuthorizationInformation>();
            StepOneQuestionnaires = new ObservableCollection<StepOneQuestionnaire>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AuthorizationCondition_ID { get; set; }

        [Required]
        [StringLength(500)]
        [Column("AuthorizationCondition")]
        public string Condition { get; set; }

        public DateTime AuthorizationConditionCompletionDate { get; set; }

        [Required]
        [StringLength(5)]
        public string AuthorizationConditionIsCompleted { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AuthorizationInformation> AuthorizationInformations { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
    }
}
