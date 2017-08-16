namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class WindowsLocalUserSetting
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public WindowsLocalUserSetting()
        {
            EnumeratedWindowsUsers = new HashSet<EnumeratedWindowsUser>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Local_Settings_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string Local_Is_Disabled { get; set; }

        [Required]
        [StringLength(5)]
        public string Local_Is_Disabled_Automatically { get; set; }

        [Required]
        [StringLength(5)]
        public string Local_Cant_Change_PW { get; set; }

        [Required]
        [StringLength(5)]
        public string Local_Never_Changed_PW { get; set; }

        [Required]
        [StringLength(5)]
        public string Local_Never_Logged_On { get; set; }

        [Required]
        [StringLength(5)]
        public string Local_PW_Never_Expires { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EnumeratedWindowsUser> EnumeratedWindowsUsers { get; set; }
    }
}
