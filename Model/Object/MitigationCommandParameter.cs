namespace Vulnerator.Model.Object
{
    public class MitigationCommandParameter
    {
        public string Index { get; set; }
        public string VulnId { get; set; }
        public string Text { get; set; }
        public string Status { get; set; }
        public string Project { get; set; }
        public string Accreditation { get; set; }
        public string HostName { get; set; }
        public string IpAddress { get; set; }
        public string DateEntered { get; set; }
        public string DateExpires { get; set; }
        public bool AllInstances { get; set; }
        public bool SingleGroup { get; set; }
        public bool SingleAsset { get; set; }
    }
}
