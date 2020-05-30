using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class InformationType : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public InformationType()
        {
            MissionAreas = new ObservableCollection<MissionArea>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long InformationType_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string InfoTypeIdentifier { get; set; }

        [Required]
        [StringLength(50)]
        public string InfoTypeName { get; set; }

        [StringLength(25)]
        public string BaselineConfidentiality { get; set; }

        [StringLength(25)]
        public string BaselineIntegrity { get; set; }

        [StringLength(25)]
        public string BaselineAvailability { get; set; }

        [StringLength(25)]
        public string EnhancedConfidentiality { get; set; }

        [StringLength(25)]
        public string EnhancedIntegrity { get; set; }

        [StringLength(25)]
        public string EnhancedAvailability { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MissionArea> MissionAreas { get; set; }
    }
}
