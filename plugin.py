#!/usr/bin/env python
# *-* coding: utf-8 *-*

import sys
import re
import os
import os.path as path
import zlib
import imp

from sec_utils.logger import PrintLog

'''
\brief Firebytes plugin class.

This class is used to search for and load up firebytes plugins (*.fireplug). These plugins are actually GZipped python scripts.
For every plugin this class finds, it attempts to load the plugin, gunzip it, and then inject it into the runtime. If any of that fails,
the plugin is skipped and a message is logged with what went wrong.
'''
class PluginManager:
    m_pluginList = []

    m_pluginDir = "{0}/plugins".format(path.dirname(path.realpath(__file__)))
    m_nxtUID = 0

    def __init__(self):
        global PrintLog

        self.m_pluginList = []
        self.m_nxtUID = 0

        PrintLog("Firebytes plugin manager ready", "Info")

    '''
    \brief Load all plugins

    This function will iterate through the plugin directory and attempt to load up all the plugins.

    \return True if successfully loaded (any) plugins, False if plugin(s) failed to load.
    '''
    def LoadPlugins(self, rhost=""):
        global PrintLog

        PrintLog("Looking for plugins in {0}".format(self.m_pluginDir), "Info")
        bSuccess = False

        try:
            iFailTimes = 0
            iNumPlugins = 0
            for fName in os.listdir(self.m_pluginDir):
                if path.isfile("{0}/{1}".format(self.m_pluginDir, fName)):
                    if re.match('^.*?\.fireplug$', fName, re.IGNORECASE):
                        iNumPlugins += 1
                        plugName, plugObj, plugUID = self.__Util_LoadPlugin("{0}/{1}".format(self.m_pluginDir, fName))
                        self.m_nxtUID += 1

                        if plugObj != None:
                            # Run the plugin's Init() function.
                            if plugObj.Init(args=[rhost], plug_id=self.m_nxtUID) == True:
                                self.m_pluginList.append((self.m_nxtUID, plugName, plugObj, plugUID))
                                PrintLog("Successfully loaded plugin \"{0}\" ({1})!".format(plugName, self.m_nxtUID), "Success")
                            else:
                                PrintLog("Failed to initialize plugin \"{0}\"!".format(plugName), "Failure")
                                iFailTimes += 1
                        else:
                            PrintLog("Failed to load plugin \"{0}\"!".format(fName), "Failure")
                            iFailTimes += 1
                    else:
                        PrintLog("Found non-plugin file \"{0}\", skipping...".format(fName), "Debug")

            if iFailTimes <= 0:
                bSuccess = True
                PrintLog("Loaded {0} plugin(s)!".format(iNumPlugins), "Success")
            else:
                PrintLog("{0} plugin(s) failed to load! Please check them!".format(iFailTimes), "Failure")
        except (IOError, OSError) as err:
            PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Critical")

        return bSuccess

    '''
    \brief Validate plugins

    This function will run each plugin's "_VGVzdEZpcmVQbHVn()" function to have them validate themselves.
    This function is at the end of the python code, so it's the last thing the parser will read and therefor safe to assume the script is valid
    if this function fires without issue.
    '''
    def ValidatePlugins(self):
        bSuccess = False

        iFailCnt = 0
        for uid, name, plugin, plugUID in self.m_pluginList:
            if hasattr(plugin, '_VGVzdEZpcmVQbHVn') and callable(plugin._VGVzdEZpcmVQbHVn):
                if True == plugin._VGVzdEZpcmVQbHVn():
                    PrintLog("Plugin \"{0}\" ({1}) successfully validated!".format(name, uid), "Success")
                else:
                    PrintLog("Plugin \"{0}\" ({1}) failed to validate!".format(name, uid), "Failure")
                    iFailCnt += 1
            else:
                PrintLog("Plugin \"{0}\" ({1}) failed to validate!".format(name, uid), "Failure")
                iFailCnt += 1

        if iFailCnt <= 0:
            bSuccess = True

        return bSuccess

    '''
    \brief Call/Invoke a plugin method

    Function will attempt to call a plugin's function and return it's return code.

    \param[in] plugin_id - String name, string UID, or int ID for the plugin.
    \param[in] call - String representing the call to make.

    \return Returns the call's return value.
    '''
    def CallPlugin(self, plugin_id, call, args=[]):
        global PrintLog

        bFound = False
        for uid, name, plugin, plugUID in self.m_pluginList:
            if (isinstance(plugin_id, int) and uid == plugin_id) or plugin_id == name or plugin_id == plugUID:
                bFound = True
                PrintLog("DIR() <<< plugin:\n{0}".format(dir(plugin)), "Debug")

                if plugin != None:
                    if call == "Init":
                        callRtn = plugin.Init(args=args, plug_id=name)
                    elif call == "Run":
                        callRtn = plugin.Run(args=args, plug_id=name)
                    elif call == "Destroy":
                        callRtn = plugin.Destroy(args=args, plug_id=name)
                    else:
                        PrintLog("Unrecognized plugin call!", "Critical")

        if bFound == False:
            PrintLog("Was unable to locate plugin \"{0}\"".format(plugin_id), "Critical")

        return callRtn

    '''
    \brief Batch call plugins

    This function is used to batch call a function on ALL plugins.

    \param[in] call - String representing the call to make.

    \return Returns a dict, keys are the plugin UID and the values are the call returns.
    '''
    def CallAll(self, call, args=[]):
        global PrintLog

        callRtn = {}
        for uid, name, plugin, plugUID in self.m_pluginList:
            if plugin != None:
                if call == "Init":
                    callRtn[plugUID] = plugin.Init(args=args, plug_id=name)
                elif call == "Run":
                    callRtn[plugUID] = plugin.Run(args=args, plug_id=name)
                elif call == "Destroy":
                    callRtn[plugUID] = plugin.Destroy(args=args, plug_id=name)
                else:
                    PrintLog("Unrecognized plugin call!", "Critical")

        return callRtn

    '''
    \brief Worker function to actually load plugins.

    This function takes a file path and will attempt to load up the plugin at said path, INFLATE it and then actually load in the module to be run.
    Once all loaded successfully, the function will then instantiate a plugin object to be used later.

    \param[in] plugin_loc - Path to the *.fireplug file to be loaded.

    \return Tuple containing the plugin name and the loaded plugin object.
    '''
    def __Util_LoadPlugin(self, plugin_loc):
        global PrintLog

        lPlugName = ""
        lPlugObj = None
        lPlugUID = ""

        if path.exists(plugin_loc):
            # Attempt to open the file in GZip.
            try:
                hPlug = open(plugin_loc, "rb")

                mCompressData = ""
                for blob in hPlug:
                    mCompressData = "{0}{1}".format(mCompressData, blob)

                hPlug.close()

                if mCompressData != None and mCompressData != "":
                    # Attempt to INFLATE the data.
                    mData = zlib.decompress(mCompressData)

                    # Extract the plugin name.
                    for line in mData.split("\n"):
                        if lPlugName != "" and lPlugUID != "":
                            break

                        PrintLog("Checking for name in line: '{0}'".format(line), "Debug")
                        lRegExp = re.search('^#\s+FIREPLUG\_NAME\:\s+(.*)$', line, re.IGNORECASE)
                        if lRegExp != None:
                            lPlugName = lRegExp.group(1)

                        PrintLog("Checking for UID in line: '{0}'".format(line), "Debug")
                        lRegExp = re.search('^#\s+FIREPLUG\_UID\:\s+(.*)$', line, re.IGNORECASE)
                        if lRegExp != None:
                            lPlugUID = lRegExp.group(1)

                    if lPlugName != None and lPlugName != "" and lPlugUID != None and lPlugUID != "":
                        # Attempt to inject the plugin into the runtime.
                        try:
                            # Create module for runtime.
                            lPlugObj = imp.new_module(lPlugName)

                            # Inject the code.
                            exec mData in lPlugObj.__dict__

                            # Add newly injected module to system modules.
                            sys.modules[lPlugName] = lPlugObj

                            # Done!
                        except (IOError, OSError, ValueError, TypeError, KeyError) as err:
                            PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Critical")
                    else:
                        PrintLog("Invalid plugin name in plugin!", "Critical")
                else:
                    PrintLog("Unable to read plugin data!", "Critical")
            except (IOError, OSError, RuntimeError, zlib.error) as err:
                PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Critical")
        else:
            PrintLog("Unable to locate plugin @ \"{0}\"!".format(plugin_loc), "Critical")

        return (lPlugName, lPlugObj, lPlugUID)