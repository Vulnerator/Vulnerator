namespace Vulnerator.Model.Entity
{
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class GroupsCCIs
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long GroupsCCIs_ID { get; set; }

        public long Group_ID { get; set; }

        public long CCI_ID { get; set; }

        [StringLength(5)]
        public string IsInherited { get; set; }

        [StringLength(50)]
        public string InheritedFrom { get; set; }

        [StringLength(5)]
        public string Inheritable { get; set; }

        [StringLength(25)]
        public string ImplementationStatus { get; set; }

        [StringLength(500)]
        public string ImplementationNotes { get; set; }

        public virtual Group Group { get; set; }

        public virtual CCI CCI { get; set; }
    }
}
