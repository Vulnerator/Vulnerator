namespace Vulnerator.Model.Entity
{
    using System;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class GroupsWaivers
    {
        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Group_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Waiver_ID { get; set; }

        [Key]
        [Column(Order = 2)]
        public DateTime WaiverGrantedDate { get; set; }

        [Key]
        [Column(Order = 3)]
        public DateTime WaiverExpirationDate { get; set; }

        public virtual Group Group { get; set; }

        public virtual Waiver Waiver { get; set; }
    }
}