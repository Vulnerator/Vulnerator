﻿using GalaSoft.MvvmLight;
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
        private Assembly assembly = Assembly.GetExecutingAssembly();

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
            RenderUserGuidePages();
        }

        private void RenderUserGuidePages()
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
                    userGuidePage.PageNumber = GetPageNumber(resource);
                    UserGuidePages.Add(userGuidePage);
                }
            }
        }

        private string GetPageContent(string resource)
        {
            MarkdownPipeline pipeline = new MarkdownPipelineBuilder()
                .UseAdvancedExtensions()
                .UseEmphasisExtras()
                .UseEmojiAndSmiley()
                .Build();
            string result = string.Empty;
            using (Stream stream = assembly.GetManifestResourceStream(resource))
            {
                using (StreamReader streamReader = new StreamReader(stream))
                {
                    string pre = "<html><head><style>p,a,h1,h2,h3,h4,h5,h6,ol,ul,li,td,th,table,tr { font-family:\"Segoe UI\", \"Lucida Sans Unicode\", \"Verdana\", sans-serif; } table,th,td { border: 1px solid black; border-collapse: collapse; }</style></head><body>[body]</body></html>";
                    return result = pre.Replace("[body]", Markdown.ToHtml(streamReader.ReadToEnd(), pipeline));
                }
            }
        }

        private int GetPageNumber(string resource)
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
    }
}