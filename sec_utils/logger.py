#!/usr/bin/env python
# *-* coding: utf-8 *-*

from io import IOBase
import sys
import re
import os
import os.path
from datetime import datetime as dt

global fireIO

# For legacy support.
global PrintLog
global DumpLog
global TruncateLog

def PrintLog(line, level, debug_info="", plugin_id=0):
    global fireIO
    fireIO.write(line, level=level, debug_info=debug_info, plugin_id=plugin_id)
    fireIO.flush()

def DumpLog():
    global fireIO
    fireIO.DumpLog()
    fireIO.flush()

def TruncateLog():
    global fireIO
    fireIO.TruncateLog()
    fireIO.flush()

class FirebytesIO(IOBase):
    m_logFile = "./firebytes.log"
    m_allowDebug = False

    m_baseString = "\033[33m<\033[34m{0}\033[33m> [\033[32m{1}\033[33m]"
    m_debugString = "\033[33m<\033[34m{0}\033[33m> [\033[32m{1}\033[33m] \033[35mDEBUG INFO:\033[0m {2}\n"

    def __init__(self):
        self.m_logFile = "./firebytes.log"
        self.m_allowDebug = False
        self.m_baseString = "\033[33m<\033[34m{0}\033[33m> [\033[32m{1}\033[33m]"
        self.m_debugString = "\033[33m<\033[34m{0}\033[33m> [\033[32m{1}\033[33m] \033[35mDEBUG INFO:\033[0m {2}\n"
        self.m_dataBuffer = ""

    def set_debug(self, enabled=True):
        self.m_allowDebug = enabled

    def write(self, line, level="Info", debug_info="", plugin_id=0):
        # Grab a time stamp.
        dateStamp = dt.now().strftime("%x")
        timeStamp = dt.now().strftime("%X")

        self.m_baseString = self.m_baseString.format(dateStamp, timeStamp)
        self.m_debugString = self.m_debugString.format(dateStamp, timeStamp, debug_info)

        if line is not None and level is not None:
            if re.match("^Fatal(\sError)?$", level, re.IGNORECASE):
                sys.stderr.write("{0} \033[1;31m{1}:\033[0m {2}\n".format(self.m_baseString, level, line))

            elif re.match("^(Critical|Error)$", level, re.IGNORECASE):
                sys.stderr.write("{0} \033[31m{1}:\033[0m {2}\n".format(self.m_baseString, level, line))

            elif re.match("^Warn(ing)?$", level, re.IGNORECASE):
                sys.stderr.write("{0} \033[1;33m{1}:\033[0m {2}\n".format(self.m_baseString, level, line))

            elif re.match("^Info(rmation)?$", level, re.IGNORECASE):
                sys.stdout.write("{0} \033[34m{1}:\033[0m {2}\n".format(self.m_baseString, level, line))

            elif self.m_allowDebug == True and re.match("^(Debug|Trace)$", level, re.IGNORECASE):
                sys.stderr.write("{0} \033[35m{1}:\033[0m {2}\n".format(self.m_baseString, level, line))

            elif re.match('^Failure$', level, re.IGNORECASE):
                sys.stderr.write("{0} \033[1;31m{1}:\033[0m {2}\n".format(self.m_baseString, level.upper(), line))

            elif re.match('^Success$', level, re.IGNORECASE):
                sys.stderr.write("{0} \033[1;32m{1}:\033[0m {2}\n".format(self.m_baseString, level.upper(), line))

            elif re.match('^Plugin$', level, re.IGNORECASE):
                if os.environ['TERM'] == "xterm-256color":
                    sys.stdout.write("{0} \033[38;5;202m[{1} {2}]:\033[0m {3}\n".format(self.m_baseString, level, plugin_id, line))
                else:
                    sys.stdout.write("{0} \033[1;33m[{1} {2}]:\033[0m {3}\n".format(self.m_baseString, level, plugin_id, line))

            if self.m_allowDebug == True and debug_info != "":
                sys.stderr.write(self.m_debugString)


        if sys.version_info[0] >= 3:
            sys.stdout.flush()
            sys.stderr.flush()

        self.flush()

        if self.m_logFile is not None and self.m_logFile != "":
            if self.m_allowDebug != True and (level == "Debug" or level == "Trace"):
                return # Skip
            else:
                try:
                    hLogFile = open(self.m_logFile, "a+")

                    hLogFile.write("<{0}> [{1}] {2}: {3}\n".format(dateStamp, timeStamp, level, line))

                    if self.m_allowDebug == True and debug_info != "":
                        hLogFile.write("<{0}> [{1}] DEBUG INFO: {2}\n".format(dateStamp, timeStamp, debug_info))

                    hLogFile.close()
                except (IOError, OSError):
                    sys.stderr.write("{0} \033[1;31m{1}:\033[0m {2}\n".format(self.m_baseString, 'CRITICAL', "Unable to write to {0}".format(self.m_logFile)))

    def DumpLog(self):
        logRtn = ""
        if self.m_logFile is not None and self.m_logFile != "":
            try:
                hLogFile = open(self.m_logFile, "r")

                for line in hLogFile:
                    logRtn += line
                    self.flush()

                hLogFile.close()
            except (IOError, OSError):
                sys.stderr.write("{0} \033[1;31m{1}:\033[0m {2}\n".format(self.m_baseString, 'CRITICAL', "Unable to write to {0}".format(self.m_logFile)))

        return logRtn

    def TruncateLog(self):
        if self.m_logFile is not None and self.m_logFile != "":
            try:
                hLogFile = open(self.m_logFile, "w+")
                hLogFile.close()
            except (IOError, OSError):
                sys.stderr.write("{0} \033[1;31m{1}:\033[0m {2}\n".format(self.m_baseString, 'CRITICAL', "Unable to write to {0}".format(self.m_logFile)))

# Setup the global instance.
fireIO = FirebytesIO()
# fireIO.set_debug(True)