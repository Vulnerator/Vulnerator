namespace Vulnerator.Model.Entity
{
    using PropertyChanged;
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.ComponentModel;

    [AddINotifyPropertyChangedInterface]
    public partial class MitigationsOrCondition : INotifyPropertyChanged
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public MitigationsOrCondition()
        { Groups = new ObservableCollection<Group>(); }

        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long MitigationOrCondition_ID { get; set; }

        [Required]
        public long Vulnerability_ID { get; set; }

        public virtual Vulnerability Vulnerability { get; set; }

        [StringLength(2000)]
        public string Impact_Description { get; set; }

        [StringLength(2000)]
        public string Predisposing_Conditions { get; set; }

        [StringLength(2000)]
        public string Technical_Mitigation { get; set; }

        [StringLength(2000)]
        public string Proposed_Mitigation { get; set; }

        [StringLength(10)]
        public string Threat_Relevance { get; set; }

        [StringLength(10)]
        public string Severity_Pervasiveness { get; set; }

        [StringLength(10)]
        public string Likelihood { get; set; }

        [StringLength(10)]
        public string Impact { get; set; }

        [StringLength(10)]
        public string Risk { get; set; }

        [StringLength(10)]
        public string Residual_Risk { get; set; }

        [StringLength(10)]
        public string Residual_Risk_After_Proposed { get; set; }

        [StringLength(25)]
        public string Mitigated_Status { get; set; }

        public string Approval_Date { get; set; }

        public string Estimated_Completion_Date { get; set; }

        public string Expiration_Date { get; set; }

        [StringLength(5)]
        public string IsApproved { get; set; }

        [StringLength(50)]
        public string Approver { get; set; }

        [NotMapped]
        public bool IsChecked { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }
    }
}
