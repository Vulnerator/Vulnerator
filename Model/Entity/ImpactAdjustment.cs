using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class ImpactAdjustment : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ImpactAdjustment_ID { get; set; }
        
        [StringLength(25)]
        public string AdjustedConfidentiality { get; set; }
        
        [StringLength(200)]
        public string AdjustedConfidentialityJustification { get; set; }

        [StringLength(25)]
        public string AdjustedIntegrity { get; set; }
        
        [StringLength(200)]
        public string AdjustedIntegrityJustification { get; set; }

        [StringLength(25)]
        public string AdjustedAvailability { get; set; }
        
        [StringLength(200)]
        public string AdjustedAvailabilityJustification { get; set; }
    }
}
