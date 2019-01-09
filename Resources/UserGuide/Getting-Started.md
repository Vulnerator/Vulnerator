# Downloading the Software
Courtesy of GitHub, there are now several ways to obtain the software in its various formats - your level of proficiency and intent dictate the best method for you.  For convenience, the methods are ordered below from most popular (and easiest) to least popular (and most difficult).

## Compiled Release
By far the most popular of choices, this method results in the user having a "click to launch" version of the application.  By design, the executable is portable in nature and does not require any installation.  That being said, some steps are required to be followed in order for the application to operate as intended:  

1. Begin by downloading the latest release from the [Vulnerator Releases](https://github.com/Vulnerator/Vulnerator/releases) page; the latest release can be identified via the "Latest release" badge.  Once identified, locate and click the link ending with ".zip" - take care not to download the "Source Code" files
  * If an earlier release is desired, please navigate to the [Tags](https://github.com/Vulnerator/Vulnerator/tags) page and obtain the version required
2. Once downloaded, extract the folder contained within the *.zip file; it is important to extract the entire folder, as there are hidden files that the executable itself is dependent on to run
3. After extracting the folder, open it and double-click the file named "Vulnerator.exe" (it will have the bar chart icon next to it).
  * Be sure to launch this icon from within the folder so that it is alongside its dependencies
  * If a Desktop shortcut is desired, one can be created easily by right-clicking the "Vulnerator.exe" file, hovering over the "Send to" option, and selecting "Desktop (create shortcut)"
4. Vulnerator should launch within a few moments; if an error is encountered, please report it
  * Detailed error reporting steps can be found on the Error Reporting wiki page

For a detailed guide of all of the features, head over to the Using the Software wiki page.

## Download the Source (*.zip / *.tar.gz)
This option proves useful if you are simply interested in reviewing the source code to keep the developers honest or if you'd like to run it through a code analysis software (e.g. HP Fortify)  

1. Navigate to the [Vulnerator Releases](https://github.com/Vulnerator/Vulnerator/releases) page and locate the version desired
  * Versions may also be identified via the [Tags](https://github.com/Vulnerator/Vulnerator/tags) page
2. Once the desired version is found, download the desired format via either the "Source Code (zip)" or "Source Code (tar.gz)" links

## Fork the Repository
If you would like to contribute to the project, please feel free to sign up for a GitHub account and fork the repository to create your own version of it - alternatively, you can create your own branch of the main.  From there, create a new issue to track your contribution (if one doesn't exist), modify the code with your ideas, then create a pull request; the link to do so can be found on the [Vulnerator GitHub Page](https://github.com/Vulnerator/Vulnerator).  Once your changes have been reviewed, we will either provide additional feedback or merge the change into the master.  