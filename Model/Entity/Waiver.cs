using System.Collections.ObjectModel;

namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class Waiver
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Waiver()
        {
            Groups = new ObservableCollection<Group>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Waiver_ID { get; set; }

        [Required]
        [StringLength(100)]
        public string WaiverName { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }
    }
}
