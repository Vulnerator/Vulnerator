using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class RequiredReport : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        public RequiredReport()
        {
            ReportFindingTypeUserSettings = new ObservableCollection<ReportFindingTypeUserSettings>();
            ReportSeverityUserSettings = new ObservableCollection<ReportSeverityUserSettings>();
            RequiredReportUserSelections = new ObservableCollection<RequiredReportUserSelection>();
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

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ReportFindingTypeUserSettings> ReportFindingTypeUserSettings { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ReportSeverityUserSettings> ReportSeverityUserSettings { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<RequiredReportUserSelection> RequiredReportUserSelections { get; set; }
    }
}
