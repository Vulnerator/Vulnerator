namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("FISMA")]
    public partial class FISMA
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long FISMA_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string SecurityReviewCompleted { get; set; }

        public DateTime? SecurityReviewDate { get; set; }

        [Required]
        [StringLength(5)]
        public string ContingencyPlanRequired { get; set; }

        [StringLength(5)]
        public string ContingencyPlanTested { get; set; }

        public DateTime? ContingencyPlanTestDate { get; set; }

        [Required]
        [StringLength(5)]
        public string PIA_Required { get; set; }

        public DateTime? PIA_Date { get; set; }

        [Required]
        [StringLength(5)]
        public string PrivacyActNoticeRequired { get; set; }

        [Required]
        [StringLength(5)]
        public string eAuthenticationRiskAssessmentRequired { get; set; }

        public DateTime? eAuthenticationRiskAssessmentDate { get; set; }

        [Required]
        [StringLength(5)]
        public string ReportableTo_FISMA { get; set; }

        [Required]
        [StringLength(5)]
        public string ReportableTo_ERS { get; set; }
    }
}
