using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class ReportFindingTypeUserSettings : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ReportFindingTypeUserSettings()
        { }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ReportFindingTypeUserSettings_ID { get; set; }
        
        [Required]
        public long RequiredReport_ID { get; set; }
        
        [Required]
        public virtual RequiredReport RequiredReport { get; set; }
        
        [Required]
        public long FindingType_ID { get; set; }
        
        [Required]
        public virtual FindingType FindingType { get; set; }

        [Required]
        [StringLength(50)]
        public string UserName { get; set; }
    }
}