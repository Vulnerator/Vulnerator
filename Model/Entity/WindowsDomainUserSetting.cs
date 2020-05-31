using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class WindowsDomainUserSetting : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public WindowsDomainUserSetting()
        {
            EnumeratedWindowsUsers = new ObservableCollection<EnumeratedWindowsUser>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long WindowsDomainUserSettings_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsDomainUserIsDisabled { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsDomainUserIsDisabledAutomatically { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsDomainUserCantChangePW { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsDomainUserNeverChangedPW { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsDomainUserNeverLoggedOn { get; set; }

        [Required]
        [StringLength(5)]
        public string WindowsDomainUserPW_NeverExpires { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EnumeratedWindowsUser> EnumeratedWindowsUsers { get; set; }
    }
}
