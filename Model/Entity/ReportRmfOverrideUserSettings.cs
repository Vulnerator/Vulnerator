using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("ReportRmfOverrideUserSettings")]
    public class ReportRmfOverrideUserSettings : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ReportRmfOverrideUserSettings_ID { get; set; }
        
        [Required]
        public long RequiredReport_ID { get; set; }
        
        [Required]
        public virtual RequiredReport RequiredReport { get; set; }

        public long? Group_ID { get; set; }
        
        public virtual Group Group { get; set; }

        [Required]
        [StringLength(50)]
        public string UserName { get; set; }
        
        [Required]
        [StringLength(5)]
        public string IsSelected { get; set; }
    }
}
