using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class SystemCategorizationInformationTypesImpactAdjustment : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        
        public SystemCategorizationInformationTypesImpactAdjustment()
        { }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SystemCategorizationInformationTypeImpactAdjustment_ID { get; set; }

        [Required]
        public long SystemCategorization_ID { get; set; }

        public virtual SystemCategorization SystemCategorization { get; set; }

        [Required]
        public long InformationType_ID { get; set; }

        public virtual InformationType InformationType { get; set; }

        [Required]
        public long ImpactAdjustment_ID { get; set; }

        public virtual ImpactAdjustment ImpactAdjustment { get; set; }
    }
}