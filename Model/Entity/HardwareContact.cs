using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    [Table("HardwareContacts")]
    public class HardwareContact : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long HardwareContact_ID { get; set; }

        [Required]
        public long Hardware_ID { get; set; }

        public virtual Hardware Hardware { get; set; }

        [Required]
        public long Contact_ID { get; set; }

        public virtual Contact Contact { get; set; }
    }
}
