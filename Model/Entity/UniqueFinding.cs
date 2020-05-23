using JetBrains.Annotations;

namespace Vulnerator.Model.Entity
{
    using System;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.ComponentModel;

    public partial class UniqueFinding : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [NotMapped]
        public bool IsChecked { get; set; }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long UniqueFinding_ID { get; set; }

        [StringLength(50)]
        public string InstanceIdentifier { get; set; }

        [StringLength(2147483647)]
        public string ToolGeneratedOutput { get; set; }

        [StringLength(2147483647)]
        public string Comments { get; set; }

        [StringLength(2147483647)]
        public string FindingDetails { get; set; }

        public string FirstDiscovered { get; set; }

        public string LastObserved { get; set; }

        [Required]
        [StringLength(5)]
        public string DeltaAnalysisRequired { get; set; }

        public long FindingType_ID { get; set; }

        public long FindingSourceFile_ID { get; set; }

        [CanBeNull]
        public long? MitigationOrCondition_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string Status { get; set; }

        public long Vulnerability_ID { get; set; }

        public long? Hardware_ID { get; set; }

        public long? Software_ID { get; set; }

        [StringLength(25)]
        public string SeverityOverride { get; set; }

        [StringLength(2000)]
        public string SeverityOverrideJustification { get; set; }

        [StringLength(100)]
        public string TechnologyArea { get; set; }

        [StringLength(500)]
        public string WebDB_Site { get; set; }

        [StringLength(100)]
        public string WebDB_Instance { get; set; }

        [StringLength(25)]
        public string Classification { get; set; }

        [StringLength(5)]
        public string CVSS_EnvironmentalScore { get; set; }

        [StringLength(25)]
        public string CVSS_EnvironmentalVector { get; set; }

        public virtual FindingType FindingType { get; set; }

        public virtual Hardware Hardware { get; set; }

        public virtual Software Software { get; set; }

        [CanBeNull]
        public virtual MitigationsOrCondition MitigationsOrCondition { get; set; }

        public virtual UniqueFindingsSourceFile UniqueFindingsSourceFile { get; set; }

        public virtual Vulnerability Vulnerability { get; set; }
    }
}
