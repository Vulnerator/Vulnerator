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
        public long Unique_Finding_ID { get; set; }

        [StringLength(50)]
        public string Instance_Identifier { get; set; }

        [StringLength(2147483647)]
        public string Tool_Generated_Output { get; set; }

        [StringLength(2147483647)]
        public string Comments { get; set; }

        [StringLength(2147483647)]
        public string Finding_Details { get; set; }

        public DateTime First_Discovered { get; set; }

        public DateTime Last_Observed { get; set; }

        [Required]
        [StringLength(5)]
        public string Delta_Analysis_Required { get; set; }

        public long Finding_Type_ID { get; set; }

        public long Finding_Source_File_ID { get; set; }

        public long MitigationOrCondition_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string Status { get; set; }

        public long Vulnerability_ID { get; set; }

        public long? Hardware_ID { get; set; }

        public long? Software_ID { get; set; }

        [StringLength(25)]
        public string Severity_Override { get; set; }

        [StringLength(2000)]
        public string Severity_Override_Justification { get; set; }

        [StringLength(100)]
        public string Technology_Area { get; set; }

        [StringLength(500)]
        public string Web_DB_Site { get; set; }

        [StringLength(100)]
        public string Web_DB_Instance { get; set; }

        [StringLength(25)]
        public string Classification { get; set; }

        [StringLength(5)]
        public string CVSS_Environmental_Score { get; set; }

        [StringLength(25)]
        public string CVSS_Environmental_Vector { get; set; }

        public virtual FindingType FindingType { get; set; }

        public virtual Hardware Hardware { get; set; }

        public virtual UniqueFindingsSourceFile UniqueFindingsSourceFile { get; set; }

        public virtual Vulnerability Vulnerability { get; set; }
    }
}
