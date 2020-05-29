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
    public partial class MitigationOrCondition : INotifyPropertyChanged
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public MitigationOrCondition()
        { Groups = new ObservableCollection<Group>(); }

        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long MitigationOrCondition_ID { get; set; }

        [StringLength(2000)]
        public string ImpactDescription { get; set; }

        [StringLength(2000)]
        public string PredisposingConditions { get; set; }

        [StringLength(2000)]
        public string TechnicalMitigation { get; set; }

        [StringLength(2000)]
        public string ProposedMitigation { get; set; }

        [StringLength(10)]
        public string ThreatRelevance { get; set; }

        [StringLength(10)]
        public string SeverityPervasiveness { get; set; }

        [StringLength(10)]
        public string Likelihood { get; set; }

        [StringLength(10)]
        public string Impact { get; set; }

        [StringLength(10)]
        public string Risk { get; set; }

        [StringLength(10)]
        public string ResidualRisk { get; set; }

        [StringLength(10)]
        public string ResidualRiskAfterProposed { get; set; }

        [StringLength(25)]
        public string MitigatedStatus { get; set; }

        public string ApprovalDate { get; set; }

        public string EstimatedCompletionDate { get; set; }

        public string ExpirationDate { get; set; }

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
