using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public  class ConnectedSystem : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ConnectedSystem()
        { Groups = new ObservableCollection<Group>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ConnectedSystem_ID { get; set; }

        [Required]
        [StringLength(100)]
        public string ConnectedSystemName { get; set; }

        [Required]
        [StringLength(5)]
        public string IsAuthorized { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }
    }
}
