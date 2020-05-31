using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class JointAuthorizationOrganization : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public JointAuthorizationOrganization()
        { SystemCategorizations = new ObservableCollection<SystemCategorization>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long JointAuthorizationOrganization_ID { get; set; }

        [Required]
        [StringLength(200)]
        public string JointAuthorizationOrganizationName { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SystemCategorization> SystemCategorizations { get; set; }
    }
}
