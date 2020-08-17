using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class RelatedTesting : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public RelatedTesting()
        {
            SecurityAssessmentProcedures = new ObservableCollection<SecurityAssessmentProcedure>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long RelatedTesting_ID { get; set; }

        [Required]
        [StringLength(200)]
        public string TestTitle { get; set; }

        [Required]
        public DateTime DateConducted { get; set; }

        [Required]
        [StringLength(200)]
        public string RelatedSystemTested { get; set; }

        [Required]
        [StringLength(200)]
        public string ResponsibleOrganization { get; set; }

        [Required]
        [StringLength(500)]
        public string TestingImpact { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityAssessmentProcedure> SecurityAssessmentProcedures { get; set; }
    }
}
