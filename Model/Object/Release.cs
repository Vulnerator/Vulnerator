namespace Vulnerator.Model.Object
{
    public class Release
    {
        public string Name { get; set; }
        public string Body { get; set; }
        public string TagName { get; set; }
        public string HtmlUrl { get; set; }
        public string CreatedAt { get; set; }
        public int Downloads { get; set; }
    }
}
