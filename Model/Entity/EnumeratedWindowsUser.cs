using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class EnumeratedWindowsUser : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public EnumeratedWindowsUser()
        {
            WindowsDomainUserSettings = new ObservableCollection<WindowsDomainUserSetting>();
            WindowsLocalUserSettings = new ObservableCollection<WindowsLocalUserSetting>();
            EnumeratedWindowsGroups = new ObservableCollection<EnumeratedWindowsGroup>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long EnumeratedWindowsUser_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string EnumeratedWindowsUserName { get; set; }

        [Required]
        [StringLength(5)]
        public string IsGuestAccount { get; set; }

        [Required]
        [StringLength(5)]
        public string IsDomainAccount { get; set; }

        [Required]
        [StringLength(5)]
        public string IsLocalAccount { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<WindowsDomainUserSetting> WindowsDomainUserSettings { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<WindowsLocalUserSetting> WindowsLocalUserSettings { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EnumeratedWindowsGroup> EnumeratedWindowsGroups { get; set; }
    }
}
