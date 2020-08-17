namespace Vulnerator.Model.Object
{
    public class AssetOverviewLineItem
    {
        public string AssetToReport = string.Empty;
        public string DiscoveredHostName = string.Empty;
        public string IpAddress = string.Empty;
        public string FileName = string.Empty;
        public string Credentialed = string.Empty;
        public string OperatingSystem = string.Empty;
        public string GroupName = string.Empty;
        public int CatI = 0;
        public int CatII = 0;
        public int CatIII = 0;
        public int CatIV = 0;
        public int Total = 0;
        public int ScapScore = 0;
        public bool plugin21745Found = false;
        public bool plugin26917Found = false;

        public AssetOverviewLineItem(string assetToReport)
        { AssetToReport = assetToReport; }

        public void IncreaseCatIAndTotalCounts()
        {
            CatI++;
            Total++;
        }

        public void IncreaseCatIIAndTotalCounts()
        {
            CatII++;
            Total++;
        }
        public void IncreaseCatIIIAndTotalCounts()
        {
            CatIII++;
            Total++;
        }
        public void IncreaseCatIVAndTotalCounts()
        {
            CatIV++;
            Total++;
        }
    }
}
