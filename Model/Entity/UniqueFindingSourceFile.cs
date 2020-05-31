using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class UniqueFindingSourceFile : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public UniqueFindingSourceFile()
        {
            UniqueFindings = new ObservableCollection<UniqueFinding>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long FindingSourceFile_ID { get; set; }

        [Required]
        [StringLength(500)]
        public string FindingSourceFileName { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UniqueFinding> UniqueFindings { get; set; }
        
        public virtual SCAP_Score SCAP_Score { get; set; }
    }
}
