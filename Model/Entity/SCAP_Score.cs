using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class SCAP_Score : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SCAP_Score_ID { get; set; }

        public long Score { get; set; }

        public long Hardware_ID { get; set; }

        public virtual Hardware Hardware { get; set; }

        public long FindingSourceFile_ID { get; set; }

        public virtual UniqueFindingSourceFile UniqueFindingSourceFile { get; set; }
        
        public long VulnerabilitySource_ID { get; set; }

        public virtual VulnerabilitySource VulnerabilitySource { get; set; }
        
        public DateTime ScanDate { get; set; }
    }
}
