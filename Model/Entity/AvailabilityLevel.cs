using System.ComponentModel;

namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class AvailabilityLevel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public AvailabilityLevel()
        {
            Groups = new ObservableCollection<Group>();
            NIST_ControlsAvailabilityLevels = new ObservableCollection<NIST_ControlAvailabilityLevel>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AvailabilityLevel_ID { get; set; }

        [Required]
        [StringLength(25)]
        [Column("AvailabilityLevel")]
        public string Availability_Level { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NIST_ControlAvailabilityLevel> NIST_ControlsAvailabilityLevels { get; set; }
    }
}
