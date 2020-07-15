using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("NIST_ControlsCCIs")]
    public class NIST_ControlCCI : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NIST_ControlCCI_ID { get; set; }
        
        [Required]
        public long NIST_Control_ID { get; set; }
        
        public virtual NIST_Control NIST_Control { get; set; }
        
        [Required]
        public long CCI_ID { get; set; }
        
        public virtual CCI CCI { get; set; }
        
        [StringLength(10)]
        public string DOD_AssessmentProcedureMapping { get; set; }
        
        [Required]
        [StringLength(25)]
        public string ControlIndicator { get; set; }
        
        [Required]
        [StringLength(1000)]
        public string ImplementationGuidance { get; set; }
        
        [Required]
        [StringLength(1000)]
        public string AssessmentProcedureText { get; set; }
    }
}