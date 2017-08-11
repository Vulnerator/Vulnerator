/*
  In App.xaml:
  <Application.Resources>
      <vm:ViewModelLocator xmlns:vm="clr-namespace:Vulnerator"
                           x:Key="Locator" />
  </Application.Resources>
  
  In the View:
  DataContext="{Binding Source={StaticResource Locator}, Path=ViewModelName}"

  You can also use Blend to do all this with the tool's support.
  See http://www.galasoft.ch/mvvm
*/

using GalaSoft.MvvmLight.Ioc;
using Microsoft.Practices.ServiceLocation;

namespace Vulnerator.ViewModel
{
    /// <summary>
    /// This class contains static references to all the view models in the
    /// application and provides an entry point for the bindings.
    /// </summary>
    public class ViewModelLocator
    {
        /// <summary>
        /// Initializes a new instance of the ViewModelLocator class.
        /// </summary>
        public ViewModelLocator()
        {
            ServiceLocator.SetLocatorProvider(() => SimpleIoc.Default);

            ////if (ViewModelBase.IsInDesignModeStatic)
            ////{
            ////    // Create design time view services and models
            ////    SimpleIoc.Default.Register<IDataService, DesignDataService>();
            ////}
            ////else
            ////{
            ////    // Create run time view services and models
            ////    SimpleIoc.Default.Register<IDataService, DataService>();
            ////}

            SimpleIoc.Default.Register<MainViewModel>();
            SimpleIoc.Default.Register<VulnerabilityViewModel>();
            SimpleIoc.Default.Register<UserGuideViewModel>();
            SimpleIoc.Default.Register<AboutViewModel>();
            SimpleIoc.Default.Register<NewsViewModel>();
            SimpleIoc.Default.Register<ThemeViewModel>();
            SimpleIoc.Default.Register<RmfViewModel>();
            SimpleIoc.Default.Register<SplashViewModel>();
            SimpleIoc.Default.Register<SettingsViewModel>();
        }

        public AboutViewModel About
        { get { return ServiceLocator.Current.GetInstance<AboutViewModel>(); } }

        public MainViewModel Main
        { get { return ServiceLocator.Current.GetInstance<MainViewModel>(); } }

        public NewsViewModel News
        { get { return ServiceLocator.Current.GetInstance<NewsViewModel>(); } }

        public RmfViewModel Rmf
        { get { return ServiceLocator.Current.GetInstance<RmfViewModel>(); } }

        public SettingsViewModel Settings
        { get { return ServiceLocator.Current.GetInstance<SettingsViewModel>(); } }

        public SplashViewModel Splash
        { get { return ServiceLocator.Current.GetInstance<SplashViewModel>(); } }

        public ThemeViewModel Theme
        { get { return ServiceLocator.Current.GetInstance<ThemeViewModel>(); } }

        public UserGuideViewModel UserGuide
        { get { return ServiceLocator.Current.GetInstance<UserGuideViewModel>(); } }

        public VulnerabilityViewModel Vulnerability
        { get { return ServiceLocator.Current.GetInstance<VulnerabilityViewModel>(); } }

        public static void Cleanup()
        { }
    }
}