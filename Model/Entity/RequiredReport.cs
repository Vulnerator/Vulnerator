namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class RequiredReport
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long RequiredReport_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string DisplayedReportName { get; set; }

        [Required]
        [StringLength(10)]
        public string ReportType { get; set; }

        [Required]
        public string ReportCategory { get; set; }

        [Required]
        [StringLength(5)]
        public string IsReportEnabled { get; set; }

        [Required]
        [StringLength(5)]
        public string IsReportSelected { get; set; }
    }
}
