using System.ComponentModel;

namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class Connection : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Connection()
        { Groups = new ObservableCollection<Group>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Connection_ID { get; set; }

        [StringLength(5)]
        public string IsInternetConnected { get; set; }

        [StringLength(5)]
        public string IsDODIN_Connected { get; set; }

        [StringLength(5)]
        public string IsDMZ_Connected { get; set; }

        [StringLength(5)]
        public string IsVPN_Connected { get; set; }

        [StringLength(5)]
        public string IsCND_ServiceProvider { get; set; }

        [StringLength(5)]
        public string IsEnterpriseServicesProvider { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }
    }
}
