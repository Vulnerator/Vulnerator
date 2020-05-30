using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class Connectivity : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Connectivity()
        { StepOneQuestionnaires = new ObservableCollection<StepOneQuestionnaire>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Connectivity_ID { get; set; }
        
        [Required]
        [StringLength(25)]
        public string ConnectivityName { get; set; }

        [Required]
        [StringLength(5)]
        public string HasOwnCircuit { get; set; }

        [Required]
        [StringLength(25)]
        public string CommandCommunicationsSecurityDesginatorNumber { get; set; }

        [Required]
        [StringLength(50)]
        public string CommandCommunicationsSecurityDesginatorLocation { get; set; }

        [Required]
        [StringLength(2000)]
        public string CommandCommunicationsSecurityDesginatorSupport { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
    }
}
