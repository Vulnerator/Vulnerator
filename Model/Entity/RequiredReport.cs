using System.Collections.ObjectModel;

namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class RequiredReport
    {
        public RequiredReport()
        {
            ReportFindingTypeUserSettings = new ObservableCollection<ReportFindingTypeUserSettings>();
            ReportSeverityUserSettings = new ObservableCollection<ReportSeverityUserSettings>();
        }
        
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long RequiredReport_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string DisplayedReportName { get; set; }

        [Required]
        [StringLength(50)]
        public string ReportType { get; set; }

        [Required]
        public string ReportCategory { get; set; }

        [Required]
        [StringLength(5)]
        public string IsReportEnabled { get; set; }

        [Required]
        [StringLength(5)]
        public string IsReportSelected { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ReportFindingTypeUserSettings> ReportFindingTypeUserSettings { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ReportSeverityUserSettings> ReportSeverityUserSettings { get; set; }
    }
}
