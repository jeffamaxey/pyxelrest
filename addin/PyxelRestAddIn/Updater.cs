﻿using log4net;
using System.Diagnostics;
using System.IO;
using System;

namespace PyxelRestAddIn
{
    internal class Updater
    {
        private static readonly ILog Log = LogManager.GetLogger("Updater");
        
        private readonly string updateScriptPath;
        private readonly bool checkPreReleases;

        internal Updater()
        {
            string pythonPath = ThisAddIn.GetSetting("PathToPython");
            if (!File.Exists(pythonPath))
                throw new Exception(string.Format("Path to Python '{0}' cannot be found.", pythonPath));

            updateScriptPath = Path.Combine(Path.GetDirectoryName(pythonPath), "pyxelrest_auto_update.exe");
            if (!File.Exists(updateScriptPath))
                throw new Exception(string.Format("PyxelRest auto update script '{0}' cannot be found.", updateScriptPath));

            if (!bool.TryParse(ThisAddIn.GetSetting("CheckPreReleases"), out checkPreReleases))
                checkPreReleases = false; // Do not check for pre-releases by default
        }

        internal void CheckUpdate()
        {
            string commandLine = string.Empty;
            if (checkPreReleases)
                commandLine += " --check_pre_releases";

            Log.DebugFormat("Check for PyxelRest update: {0} {1}", updateScriptPath, commandLine);
            Process updateScript = new Process();
            updateScript.StartInfo.FileName = updateScriptPath;
            updateScript.StartInfo.Arguments = commandLine;
            updateScript.StartInfo.UseShellExecute = false;
            updateScript.StartInfo.CreateNoWindow = true;
            updateScript.Start();
        }
    }
}
