using GalaSoft.MvvmLight;
using log4net;
using Markdig;
using System.IO;
using System.Reflection;
using Vulnerator.Model.Object;
using System.Collections.Generic;
using System;


namespace Vulnerator.ViewModel
{
    public class UserGuideViewModel : ViewModelBase
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        private Assembly assembly = Assembly.GetExecutingAssembly();
        public MarkdownPipeline MarkdownPipeline = new MarkdownPipelineBuilder()
            .UseAdvancedExtensions()
            .UseEmphasisExtras()
            .UseAutoLinks()
            .UseEmojiAndSmiley()
            .UseTaskLists()
            .Build();

        private List<UserGuidePage> _userGuidePages = new List<UserGuidePage>();
        public List<UserGuidePage> UserGuidePages
        {
            get { return _userGuidePages; }
            set
            {
                if (_userGuidePages != value)
                {
                    _userGuidePages = value;
                    RaisePropertyChanged("UserGuidePages");
                }
            }
        }

        private string _displayedPage;
        public string DisplayedPage
        {
            get { return _displayedPage; }
            set
            {
                if (_displayedPage != value)
                {
                    _displayedPage = value;
                    RaisePropertyChanged("DisplayedPage");
                }
            }
        }

        public UserGuideViewModel()
        { 
            try
            { RenderUserGuidePages(); }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to instantiate UserGuideViewModel."));
                log.Debug("Exception details:", exception);
            }
        }

        private void RenderUserGuidePages()
        { 
            try
            {
                UserGuidePages = new List<UserGuidePage>();
                string[] delimiter = new string[] { "UserGuide." };
                string[] markdownFiles = assembly.GetManifestResourceNames();
                foreach (string resource in markdownFiles)
                {
                    if (resource.Contains("UserGuide") && resource.Contains(".md"))
                    {
                        UserGuidePage userGuidePage = new UserGuidePage();
                        userGuidePage.Title = resource.Split(delimiter, StringSplitOptions.None)[1].Split('.')[0].Replace("-", " ");
                        userGuidePage.Contents = GetPageContent(resource);
                        userGuidePage.Contents = SanitizePageContent(userGuidePage.Contents);
                        userGuidePage.PageNumber = GetPageNumber(resource);
                        UserGuidePages.Add(userGuidePage);
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to render User Guide Pages."));
                throw exception;
            }
        }

        private string GetPageContent(string resource)
        {
            try
            {
                using (Stream stream = assembly.GetManifestResourceStream(resource))
                {
                    using (StreamReader streamReader = new StreamReader(stream))
                    { return streamReader.ReadToEnd(); }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to get page content."));
                throw exception;
            }
        }

        private string SanitizePageContent(string content)
        { 
            try
            {
                content = content.Replace(@"(Images/", @"(Resources/UserGuide/Images/");
                string[] superAndSubScriptTags = new string[] { "<sup>", @"</sup>", "<sub>", @"</sub>" };
                foreach (string tag in superAndSubScriptTags)
                {
                    if (tag.Contains("p"))
                    { content = content.Replace(tag, "^"); }
                    else
                    { content = content.Replace(tag, "~"); }
                }
                return content;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to sanitize page content."));
                throw exception;
            } }

        private int GetPageNumber(string resource)
        { 
            try
            {
                switch (resource)
                {
                    case "Vulnerator.Resources.UserGuide.Home.md":
                        { return 1; }
                    case "Vulnerator.Resources.UserGuide.Getting-Started.md":
                        { return 2; }
                    case "Vulnerator.Resources.UserGuide.Using-the-Software.md":
                        { return 3; }
                    case "Vulnerator.Resources.UserGuide.Error-Reporting.md":
                        { return 4; }
                    case "Vulnerator.Resources.UserGuide.Looking-Ahead.md":
                        { return 5; }
                    case "Vulnerator.Resources.UserGuide.Change-Log.md":
                        { return 6; }
                    default:
                        { return 0; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to get page number."));
                throw exception;
            }
        }
    }
}
