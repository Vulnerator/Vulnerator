using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("ReportUseGlobalValueUserSettings")]
    public class ReportUseGlobalValueUserSettings : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ReportUseGlobalValueUserSettings_ID { get; set; }
        
        [Required]
        public long RequiredReport_ID { get; set; }
        
        [Required]
        public virtual RequiredReport RequiredReport { get; set; }

        [Required]
        [StringLength(50)]
        public string UserName { get; set; }
        
        [Required]
        [StringLength(5)]
        public string UseGlobalFindingTypeValue { get; set; }
        
        [Required]
        [StringLength(5)]
        public string UseGlobalGroupValue { get; set; }

        [Required]
        [StringLength(5)]
        public string UseGlobalRmfOverrideValue { get; set; }

        [Required]
        [StringLength(5)]
        public string UseGlobalSeverityValue { get; set; }

        [Required]
        [StringLength(5)]
        public string UseGlobalStatusValue { get; set; }
    }
}
