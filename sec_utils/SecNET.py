#!/usr/bin/env python
# *-* coding: utf-8 *-*

import sys
import re
import socket

if sys.version_info[0] < 3:
    import pyping
    from logger import PrintLog
else:
    from sec_utils.logger import PrintLog

'''
\brief This is a basic network testing class.

This class's sole purpose is to test for REALLY basic network vulnerabilities. It'll run through these battery of tests:
    o  Connection testing (is the connection stable?)
    o  Port testing (any ports open we don't want?)
    o  ICMP testing (can I DoS you?)

If ANY of those fail, the class reports a SEC_FAILURE status.
'''
class SecNET:
    SEC_SUCCESS = 0x0
    SEC_FAILURE = 0xccffccff
    SEC_UNTESTED = 0xffaaffaa

    m_result = SEC_UNTESTED

    m_testResults = {'connection': SEC_UNTESTED, 'port': SEC_UNTESTED, 'icmp': SEC_UNTESTED}

    def __init__(self):
        global PrintLog # Global functor for PrintLog.

        # Setup the defaults.
        self.m_result = self.SEC_UNTESTED
        self.m_testResults = {'connection': self.SEC_UNTESTED, 'port': self.SEC_UNTESTED, 'icmp': self.SEC_UNTESTED}

        PrintLog("Network Pen-Tester ready.", "Info")

    '''
    \brief Test connectivity.

    This function will attempt to test connectivity to the host.

    \param[in] host - Hostname/IP to connect to.
    \param[in] port - Port to connect to.

    \return True upon success, False upon failure.
    '''
    def ConnectionTest(self, host, port):
        global PrintLog # Global functor for PrintLog.

        PrintLog("Attempting to establish connection to {0}:{1}".format(host, port), "Debug")
        bSuccess = False

        try:
            lSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            lSock.connect((host, port))
            lSock.close()

            # Success!
            self.m_result = self.SEC_SUCCESS
            self.m_testResults['connection'] = self.SEC_SUCCESS
            bSuccess = True

            PrintLog("Successfully connected to {0}:{1}: PASS".format(host, port), "Success")
        except (IOError, OSError, socket.error, TypeError, ValueError) as err:
            self.m_result = self.SEC_FAILURE
            self.m_testResults['connection'] = self.SEC_FAILURE
            
            PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")

        return bSuccess

    '''
    \brief Test unsecured/unwanted ports.

    This function will probe for unsecured/unwanted ports on the given host. It will fail if ANY are fount.

    \param[in] host - Hostname/IP to connect to.
    \param[in] port_list - Acceptable ports (wanted).

    \return True upon success, False upon failure.
    '''
    def PortTest(self, host, port_list=[443, 587, 993, 995, 8080], full_range=False):
        global PrintLog # Global functor for PrintLog.

        PrintLog("Scanning for unwanted ports...", "Debug")
        bSuccess = False

        try:
            if full_range == True:
                PrintLog("Scanning ALL 65,535 ports!", "Debug")
            else:
                PrintLog("Scanning ports {0}".format(port_list), "Debug")
                unwantedPorts = [25, 26, 80, 110, 143, 3306, 5432]

                for port in unwantedPorts:
                    if port in port_list:
                        PrintLog("Skipping potentially unsafe port: {0}".format(port), "Warning")
                        continue
                    else:
                        # Scan this port.
                        try:
                            lSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            lSock.settimeout(1.0)
                            lSock.connect((host, port))
                            lSock.close()

                            PrintLog("Port {0} is open on {1}".format(port, host), "Failure")
                            self.m_result = self.SEC_FAILURE
                            self.m_testResults['port'] = self.SEC_FAILURE

                            break
                        except (IOError, OSError, socket.error, socket.timeout, TypeError, ValueError) as err:
                            if type(err) == socket.error or type(err) == socket.timeout:
                                PrintLog("Port {0} is NOT open on {1}".format(port, host), "Success")
                            else:
                                PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                                sys.exit(255)

                if self.m_result != self.SEC_FAILURE and self.m_testResults['port'] != self.SEC_FAILURE:
                    PrintLog("Port scan complete: PASS!", "Success")
                    self.m_result = self.SEC_SUCCESS
                    self.m_testResults['port'] = self.SEC_SUCCESS
                    bSuccess = True

        except (IOError, OSError, socket.error, TypeError, ValueError) as err:
            self.m_result = self.SEC_FAILURE
            self.m_testResults['port'] = self.SEC_FAILURE
            
            PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")

        return bSuccess

    '''
    \brief Test for ICMP echos.

    This function will check to see if the host is responding to ICMP. If it is, it's an automatic FAIL.

    \param[in] host - Hostname/IP to connect to.

    \return True upon success, False upon failure.
    '''
    def IcmpTest(self, host):
        global PrintLog # Global functor for PrintLog.

        if sys.version_info[0] < 3:
            PrintLog("Checking for ICMP echo...", "Debug")
            bSuccess = False

            try:
                icmpResp = pyping.ping(host)

                if None != icmpResp.max_rtt:
                    PrintLog("ICMP responding!", "Failure")
                    self.m_result = self.SEC_FAILURE
                    self.m_testResults['icmp'] = self.SEC_FAILURE
                else:
                    PrintLog("ICMP dropped: PASS!", "Success")
                    self.m_result = self.SEC_SUCCESS
                    self.m_testResults['icmp'] = self.SEC_SUCCESS
                    bSuccess = True
            except (IOError, OSError, socket.error, TypeError, ValueError) as err:
                if type(err) == socket.error or type(err) == socket.timeout:
                    PrintLog("ICMP not available!", "Failure")
                    self.m_result = self.SEC_FAILURE
                    self.m_testResults['icmp'] = self.SEC_FAILURE
                else:
                    PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                    sys.exit(255)
        else:
            PrintLog("Version of Python (python>=3) doesn't suppot PyPing! Assuming OK (please check manually)", "Success")
            self.m_result = self.SEC_SUCCESS
            self.m_testResults['icmp'] = self.SEC_SUCCESS
            bSuccess = True

        return bSuccess