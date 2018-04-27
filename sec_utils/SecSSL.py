#!/usr/bin/env python
# *-* coding: utf-8 *-*

import sys
import re
import socket
import ssl
from datetime import datetime as dt
import cryptography.x509
import cryptography.hazmat.backends.openssl

if sys.version_info[0] < 3:
    from logger import PrintLog
else:
    from sec_utils.logger import PrintLog

'''
\brief This is a basic SSL testing class.

This classes sole purpose is to test for common SSL issues that most eCommerce sites run into when attempting to gain PCI DSS compliance.
The class will test the following:
    o  SSL connectivity
    o  SSL Version (Must be above 1.0)
    o  Is SSL valid (within valid date range)?
    o  Is SSL self-signed?
    o  Is SSL certificate chain valid and unbroken?
    o  Is SSL using weak ciphers?
    o  Is SSLv3 enabled? (Weak to POODLE)
    o  Is the key bigger than 2048 bits? (MUST be at least 4096)
    o  Is the SSL signed with an MD5 or SHA1? (Must use SHA2 or SHA256)
    o  SSL Renegotiation attacks

If ANY of those fail, the class reports a SEC_FAILURE status.
'''
class SecSSL:
    SEC_SUCCESS = 0x0
    SEC_FAILURE = 0xccffccff
    SEC_UNTESTED = 0xffaaffaa

    m_result = SEC_UNTESTED

    m_testResults = {'connection': SEC_UNTESTED, 
    'version': SEC_UNTESTED,
    'self-signed': SEC_UNTESTED,
    'valid': SEC_UNTESTED,
    'weak-cipher': SEC_UNTESTED,
    'SSLv3': SEC_UNTESTED,
    'key-size': SEC_UNTESTED,
    'weak-sign': SEC_UNTESTED}

    m_lastHost = ""
    m_lastCrt = None

    def __init__(self):
        global PrintLog # Global functor for PrintLog.

        # Setup the defaults.
        self.m_result = self.SEC_UNTESTED
        self.m_testResults = {
        'connection': self.SEC_UNTESTED, 
        'version': self.SEC_UNTESTED,
        'self-signed': self.SEC_UNTESTED,
        'valid': self.SEC_UNTESTED,
        'weak-cipher': self.SEC_UNTESTED,
        'SSLv3': self.SEC_UNTESTED,
        'key-size': self.SEC_UNTESTED,
        'weak-sign': self.SEC_UNTESTED
        }

        PrintLog("SSL Pen-Tester ready.", "Info")

    '''
    \brief Test SSL connection.

    This function will attempt to connect out to the provided host over SSL.

    \param[in] host - Hostname to connect to.
    \param[in] port - Port to connect to (default is 443)

    \return True upon success, False upon failure.
    '''
    def TestSSLConnection(self, host, port=443):
        PrintLog("Attempting to test SSL connection to {0}:{1}...".format(host, port), "Debug")
        bSuccess = False

        try:
            sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sslContext.options |= ssl.OP_NO_SSLv2
            sslContext.options |= ssl.OP_NO_SSLv3
            sslContext.load_default_certs()
            sslContext.verify_mode = ssl.CERT_REQUIRED
            sslContext.check_hostname = True
            
            sslConn = sslContext.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            sslConn.connect((host, port))
            sslConn.close()

            PrintLog("SSL Connection: PASS!", "Success")
            bSuccess = True

            self.m_result = self.SEC_SUCCESS
            self.m_testResults['connection'] = self.SEC_SUCCESS
            self.m_lastHost = host

        except (IOError, OSError, socket.error, ssl.SSLError) as err:
            if type(err) == ssl.SSLError or type(err) == socket.error:
                PrintLog("SSL Connection: FAIL! ({0})".format(err), "Failure")
                self.m_testResults['connection'] = self.SEC_FAILURE
                self.m_lastHost = ""
                self.m_lastCrt = None
            else:
                PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                sys.exit(255)

        return bSuccess

    '''
    \brief Test the SSL version

    This function will connect out to the server and make sure that the version of the SSL being served isn't 1.0 (must be at least 2) with x509.v3

    \param[in] host - Hostname to connect to and test.
    \param[in] port - Port to connect to

    \return True upon success, False upon failure.
    '''
    def TestSSLVersion(self, host, port=443):
        PrintLog("Test SSL version for {0}...".format(host), "Debug")
        bSuccess = False

        try:
            if self.m_lastCrt == None or 0 == len(self.m_lastCrt):
                sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sslContext.options |= ssl.OP_NO_SSLv2
                sslContext.options |= ssl.OP_NO_SSLv3
                sslContext.load_default_certs()
                sslContext.verify_mode = ssl.CERT_REQUIRED
                sslContext.check_hostname = True
                
                sslConn = sslContext.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
                sslConn.connect((host, port))

                # Get the certificate.
                self.m_lastCrt = sslConn.getpeercert()
                sslVer = sslConn.version()
                sslConn.close()
            
            # Test the version.
            if self.m_lastCrt['version'] >= 2 and sslVer != "SSLv3":
                PrintLog("SSL Version is >=2: PASS!", "Success")
                self.m_result = self.SEC_SUCCESS
                self.m_testResults['version'] = self.SEC_SUCCESS
                self.m_testResults['SSLv3'] = self.SEC_SUCCESS
                bSuccess = True

                if self.m_lastHost == ""  or self.m_lastHost == None:
                    self.m_lastHost = host
            else:
                PrintLog("SSL Version is <2: FAIL!", "Failure")
                self.m_testResults['version'] = self.SEC_FAILURE
                self.m_testResults['SSLv3'] = self.SEC_FAILURE
                self.m_lastHost = ""
                self.m_lastCrt = None
            

        except (IOError, OSError, socket.error, ssl.SSLError, KeyError) as err:
            if type(err) == ssl.SSLError or type(err) == socket.error:
                PrintLog("SSL Connection: FAIL! ({0})".format(err), "Failure")
                self.m_testResults['connection'] = self.SEC_FAILURE
                self.m_lastHost = ""
                self.m_lastCrt = None
            elif type(err) == KeyError:
                PrintLog("Unable to find key {0}! Check debug for more info!".format(err), "Critical", "{0}".format(self.m_lastCrt))
                sys.exit(2)
            else:
                PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                sys.exit(255)

        return bSuccess

    '''
    \brief Test the SSL validation

    This function will connect out to the server and make sure that the certificate  being served isn't invalid (date-wise).

    \param[in] host - Hostname to connect to and test.
    \param[in] port - Port to connect to

    \return True upon success, False upon failure.
    '''
    def TestSSLValid(self, host, port=443):
        PrintLog("Test SSL validation for {0}...".format(host), "Debug")
        bSuccess = False

        try:
            if self.m_lastCrt == None or 0 == len(self.m_lastCrt):
                sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sslContext.options |= ssl.OP_NO_SSLv2
                sslContext.options |= ssl.OP_NO_SSLv3
                sslContext.load_default_certs()
                sslContext.verify_mode = ssl.CERT_REQUIRED
                sslContext.check_hostname = True
                
                sslConn = sslContext.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
                sslConn.connect((host, port))

                # Get the certificate.
                self.m_lastCrt = sslConn.getpeercert()
                sslConn.close()
            
            # Get the current date.
            epochStamp = dt.now().strftime("%s")

            sslNotBefore = dt.strptime(self.m_lastCrt['notBefore'], '%b %d %H:%M:%S %Y %Z').strftime("%s")
            sslNotAfter = dt.strptime(self.m_lastCrt['notAfter'], '%b %d %H:%M:%S %Y %Z').strftime("%s")

            # Test the version.
            if epochStamp > sslNotBefore and epochStamp < sslNotAfter:
                PrintLog("SSL is Valid: PASS!", "Success")
                self.m_result = self.SEC_SUCCESS
                self.m_testResults['valid'] = self.SEC_SUCCESS
                bSuccess = True

                if self.m_lastHost == ""  or self.m_lastHost == None:
                    self.m_lastHost = host
            else:
                PrintLog("SSL is Invalid/Expired: FAIL!", "Failure")
                self.m_testResults['valid'] = self.SEC_FAILURE
                self.m_lastHost = ""
                self.m_lastCrt = None

        except (IOError, OSError, socket.error, ssl.SSLError) as err:
            if type(err) == ssl.SSLError or type(err) == socket.error:
                PrintLog("SSL Connection: FAIL! ({0})".format(err), "Failure")
                self.m_testResults['connection'] = self.SEC_FAILURE
                self.m_lastHost = ""
                self.m_lastCrt = None
            else:
                PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                sys.exit(255)

        return bSuccess

    '''
    \brief Test for Self-Signed SSL

    This function will connect out (if needed) and check to see if the peer cert is self-signed. It will fail if it is.

    \param[in] host - Hostname to connect to and test.
    \param[in] port - Port to connect to

    \return True upon success, False upon failure.
    '''
    def TestSSLSelfSign(self, host, port=443):
        PrintLog("Test if SSL is self-signed for {0}...".format(host), "Debug")
        bSuccess = False

        try:
            sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sslContext.options |= ssl.OP_NO_SSLv2
            sslContext.options |= ssl.OP_NO_SSLv3
            sslContext.load_default_certs()
            sslContext.verify_mode = ssl.CERT_REQUIRED
            sslContext.check_hostname = True
            
            sslConn = sslContext.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            sslConn.connect((host, port))

            # Get the certificate.
            self.m_lastCrt = sslConn.getpeercert()
            sslConn.close()
            
            # Check to see if the SSL is self-signed or not.
            if self.m_lastCrt['issuer'] != self.m_lastCrt['subject'] and 1 <= len(sslContext.get_ca_certs()):
                PrintLog("SSL is not self-signed: PASS!", "Success")
                self.m_result = self.SEC_SUCCESS
                self.m_testResults['self-signed'] = self.SEC_SUCCESS
                bSuccess = True

                if self.m_lastHost == ""  or self.m_lastHost == None:
                    self.m_lastHost = host
            else:
                PrintLog("SSL is self-signed: FAIL!", "Failure")
                self.m_testResults['self-signed'] = self.SEC_FAILURE
                self.m_lastHost = ""
                self.m_lastCrt = None

        except (IOError, OSError, socket.error, ssl.SSLError) as err:
            if type(err) == ssl.SSLError or type(err) == socket.error:
                PrintLog("SSL Connection: FAIL! ({0})".format(err), "Failure")
                self.m_testResults['connection'] = self.SEC_FAILURE
                self.m_lastHost = ""
                self.m_lastCrt = None
            else:
                PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                sys.exit(255)

        return bSuccess

    '''
    \brief Test for weak ciphers

    This function tests the ciphers being served by the server to see if they're strong.

    \param[in] host - Hostname to connect to and test.
    \param[in] port - Port to connect to

    \return True upon success, False upon failure.
    '''
    def TestSSLCiphers(self, host, port=443):
        PrintLog("Test for weak ciphers on {0}...".format(host), "Debug")
        bSuccess = False

        try:
            sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sslContext.options |= ssl.OP_NO_SSLv2
            sslContext.options |= ssl.OP_NO_SSLv3
            sslContext.load_default_certs()
            sslContext.verify_mode = ssl.CERT_REQUIRED
            sslContext.check_hostname = True

            # Some weak ass ciphers.
            weakAssCiphers = "aNULL:MD5:DSS:RC4:SHA1:!HIGH"
            sslContext.set_ciphers(weakAssCiphers)

            sslConn = sslContext.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            sslConn.connect((host, port))
            sslConn.close()

            PrintLog("SSL ciphers are weak: FAIL! ({0})".format(err), "Failure")
            self.m_testResults['weak-cipher'] = self.SEC_FAILURE
            self.m_lastHost = ""
            self.m_lastCrt = None

        except (IOError, OSError, socket.error, ssl.SSLError) as err:
            if type(err) == ssl.SSLError:
                PrintLog("SSL ciphers are strong: PASS!", "Success")
                self.m_result = self.SEC_SUCCESS
                self.m_testResults['weak-cipher'] = self.SEC_SUCCESS
                bSuccess = True

                if self.m_lastHost == ""  or self.m_lastHost == None:
                    self.m_lastHost = host
            else:
                PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                sys.exit(255)

        return bSuccess

    '''
    \brief Test for weak hash in signature

    This function will test to see if the signature is signed using a weak hash.

    \param[in] host - Hostname to connect to and test.
    \param[in] port - Port to connect to

    \return True upon success, False upon failure.
    '''
    def TestSSLHash(self, host, port=443):
        PrintLog("Test if SSL has weak signature for {0}...".format(host), "Debug")
        bSuccess = False

        try:
            sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sslContext.options |= ssl.OP_NO_SSLv2
            sslContext.options |= ssl.OP_NO_SSLv3
            sslContext.load_default_certs()
            sslContext.verify_mode = ssl.CERT_REQUIRED
            sslContext.check_hostname = True
            
            sslConn = sslContext.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            sslConn.connect((host, port))
            
            # Check to see if the SSL has a strong signature or not.
            x509Cert = cryptography.x509.load_der_x509_certificate(sslConn.getpeercert(True), cryptography.hazmat.backends.openssl.backend)
            sslConn.close()

            if x509Cert.signature_hash_algorithm.name != "MD5" and x509Cert.signature_hash_algorithm.name != "SHA1":
                PrintLog("SSL has strong hash in signature: PASS!", "Success")
                self.m_result = self.SEC_SUCCESS
                self.m_testResults['weak-sign'] = self.SEC_SUCCESS
                bSuccess = True

                if self.m_lastHost == ""  or self.m_lastHost == None:
                    self.m_lastHost = host
            else:
                PrintLog("SSL has weak hash in signature: FAIL!", "Failure")
                self.m_testResults['weak-sign'] = self.SEC_FAILURE
                self.m_lastHost = ""
                self.m_lastCrt = None

        except (IOError, OSError, socket.error, ssl.SSLError) as err:
            if type(err) == ssl.SSLError or type(err) == socket.error:
                PrintLog("SSL Connection: FAIL! ({0})".format(err), "Failure")
                self.m_testResults['connection'] = self.SEC_FAILURE
                self.m_lastHost = ""
                self.m_lastCrt = None
            else:
                PrintLog("{0} \033[1;34m{1}\033[0m".format(err, type(err)), "Fatal")
                sys.exit(255)

        return bSuccess