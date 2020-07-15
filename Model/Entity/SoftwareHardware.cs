using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("SoftwareHardware")]
    public class SoftwareHardware : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SoftwareHardware_ID { get; set; }

        [Required]
        public long Software_ID { get; set; }

        public virtual Software Software { get; set; }

        [Required]
        public long Hardware_ID { get; set; }

        public virtual Hardware Hardware { get; set; }

        public DateTime? InstallDate { get; set; }

        [StringLength(5)]
        public string ReportInAccreditation { get; set; }

        [StringLength(5)]
        public string ApprovedForBaseline { get; set; }

        [StringLength(50)]
        public string BaselineApprover { get; set; }
    }
}
