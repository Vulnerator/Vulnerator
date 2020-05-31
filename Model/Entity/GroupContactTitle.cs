using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class GroupContactTitle : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        public GroupContactTitle()
        { }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long GroupContactTitle_ID { get; set; }

        [Required]
        public long Group_ID { get; set; }

        public virtual Group Group { get; set; }

        [Required]
        public long Contact_ID { get; set; }

        public virtual Contact Contact { get; set; }

        [Required]
        public long Title_ID { get; set; }

        public virtual Title Title { get; set; }
    }
}