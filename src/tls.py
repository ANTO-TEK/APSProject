from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from key_management import KeyManagement
import subprocess
import inspect
import math
import os
import time

from constants import Constants

class Utils():

    """
    This class contains some utility methods.
    """

    @staticmethod
    def loadCertificate(filePath):
        """
        Loads a certificate from the given file path.
        
        Args:
            filePath (str): The path of the file containing the certificate.
        """
        with open(filePath, 'rb') as file:
            certData = file.read()
        return x509.load_pem_x509_certificate(certData, default_backend())

    @staticmethod
    def verifyCertificate(certPath, caCertPath):
        """
        Verifies the given certificate using the given CA certificate.

        Args:
            certPath (str): The path of the file containing the certificate to be verified.
            caCertPath (str): The path of the file containing the CA certificate.

        Returns:
            bool: True if the certificate is valid, False otherwise.
        """
        cert = Utils.loadCertificate(certPath)
        caCert = Utils.loadCertificate(caCertPath)

        publicKey = caCert.public_key()
        try:
            publicKey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False


class TLSClientHandler():

    """
    This class handles the TLS handshake with the server.
    """

    def __init__(self, user, folderName, server):
        """
        Initialize the TLS handler with the given user, folder name and server.
        
        Args:
            user (User): The user.
            folderName (str): The name of the folder containing the user's files.
            server (Server): The server.
        """
        self._keyManagement = KeyManagement()
        self._server = server
        self._folderName = folderName
        self._user = user
    
    @property
    def q(self):
        """
        Returns:
            int: The order of the elliptic curve used for the ECDSA algorithm.
        """
        return self._q
    
    @property
    def g(self):
        """
        Returns:
            int: The generator of the elliptic curve used for the ECDSA algorithm.
        """
        return self._g
    
    @property
    def p(self):
        """
        Returns:
            int: The prime modulus of the elliptic curve used for the ECDSA algorithm.
        """
        return self._p
    
    @property
    def x(self):
        """
        Returns:
            int: The private key of the user.
        """
        return self._x
    
    @property
    def pks(self):
        """
        Returns:
            int: The public key of the server.
        """
        return self._pks

    def handshakeStep(self, step, params = None):
        """
        Performs a specific step of the TLS handshake.

        Parameters:
            step (int): The step number of the handshake to be executed (1, 2, or 3).
            params (dict): Additional parameters required for specific steps. Optional.
        """
        if step == 1:
            self._step1Handshake()

        elif step == 2 and params is not None:
            self._step2KeyDerivation(params)

        elif step == 3 and params is not None:
            self._step3MessageDecryptionAndVerification(params)

    def _step1Handshake(self):
        """
        Performs the first step of the TLS handshake.
        """
        print('[User {}]: '.format(self._user), 'generating DH parameters...\n')
        self.dhParamFile = self._folderName + Constants.DH_PARAM_FILENAME
        self.dhKeyFile = self._folderName + Constants.DH_KEY_FILENAME
        
        # Generate DH parameters and key
        com = [Constants.OPENSSL, 'dhparam', '-out', self.dhParamFile, '2048']
        subprocess.check_output(com)

        com = [Constants.OPENSSL, 'genpkey', '-paramfile', self.dhParamFile, '-out', self.dhKeyFile]
        subprocess.check_output(com)

        with open(self.dhParamFile, 'rb') as f:
            dhparams = serialization.load_pem_parameters(f.read())
        self._g = dhparams.parameter_numbers().g
        self._p = dhparams.parameter_numbers().p
        self._q = (self._p - 1) // 2

        with open(self.dhKeyFile, 'rb') as f:
            keys = serialization.load_pem_private_key(f.read(), password=None)
        self._x = keys.private_numbers().x

        A = pow(self._g, self._x, self._p)

        print('\n[User {}]: '.format(self._user), 'sending DH contribution...')
        time.sleep(1)
        self._server.tlsHandler.tlsHandshake({'user': self._user, 'p': self._p, 'q': self._q, 'g': self._g, 'A': A}) 

    def _step2KeyDerivation(self, params):
        """
        Performs the second step of the TLS handshake.
        
        Args:
            params (dict): The parameters received from the server.
        """
        print('[User {}]: '.format(self._user), 'generating DH key...')
        time.sleep(1)
        print('[User {}]: '.format(self._user), 'creating TLS keys...')
        time.sleep(1)
        K = pow(params['B'], self._x, self._p)

        labels = [b'key 1', b'key 2', b'key 3', b'key 4']
        self.keys = []
        for label in labels:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=label,
                backend=default_backend()
            )

            key = hkdf.derive(K.to_bytes(256, byteorder='big'))
            self.keys.append(key)

    def _step3MessageDecryptionAndVerification(self, params):
        """
        Performs the third step of the TLS handshake.
        
        Args:
            params (dict): The parameters received from the server.
        """
        print('[User {}]: '.format(self._user), 'verifing certificate...')
        time.sleep(1)
        com = [Constants.OPENSSL, 'enc', '-d', '-aes-256-ctr', '-K', self.keys[0].hex(), '-iv', params['iv']]
        decryptedMessage = subprocess.check_output(com, input=params['encryptedMessage']).decode().strip()

        self._pks = decryptedMessage.split('\n')[0].strip()
        serverCertificate = decryptedMessage.split('\n')[1].strip()

        if Utils.verifyCertificate(serverCertificate, Constants.CA_FILE_PATH):
            com = [Constants.OPENSSL, 'enc', '-d', '-aes-256-ctr', '-K', self.keys[0].hex(), '-iv', params['iv']]
            decryptedSignature = subprocess.check_output(com, input=params['encryptedSignature']).decode().strip()

            if self._keyManagement.verifySign(decryptedMessage, decryptedSignature, self._pks):
                os.remove(decryptedSignature)
                print('[User {}]: '.format(self._user), 'certificate verified!')
                time.sleep(1)
                print('[User {}]: '.format(self._user), 'TLS handshake completed')
                time.sleep(1)
            else:
                print('[User {}]: '.format(self._user), 'certificate not verified!')
                self._user.closeConnection()
                return

    def encryptMessage(self, message):
        """
        Encrypts a message using AES-256-CTR. The message is also authenticated using HMAC-SHA256.

        Args:
            message (str): The message to be encrypted.

        Returns:
            tuple: The encrypted message, the HMAC tag, and the IV used for encryption.
        """
        com = [Constants.OPENSSL, 'rand', '16']
        iv = subprocess.check_output(com)

        com = [Constants.OPENSSL, 'enc', '-e', '-aes-256-ctr', '-K', self.keys[2].hex(), '-iv', iv.hex()]
        encryptedMessage = subprocess.check_output(com, input=str(message).encode('latin-1'))

        com = [Constants.OPENSSL, 'mac', '-digest', 'sha256', '-macopt', 'hexkey:' + self.keys[3].hex(), 'HMAC']
        tagMac = subprocess.check_output(com, input=encryptedMessage)

        return encryptedMessage, tagMac, iv
    
    def decryptMessage(self, encryptedMessage, tagMac, iv):
        """
        Decrypts a message using AES-256-CTR. The message is also authenticated using HMAC-SHA256.
        
        Args:
            encryptedMessage (str): The encrypted message.
            tagMac (str): The HMAC tag.
            iv (str): The IV used for encryption.
            
        Returns:    
            str: The decrypted message.
        """
        com = [Constants.OPENSSL, 'mac', '-digest', 'sha256', '-macopt', 'hexkey:' + self.keys[3].hex(), 'HMAC']
        tagMacTemp = subprocess.check_output(com, input=encryptedMessage)

        if tagMacTemp == tagMac:
            com = [Constants.OPENSSL, 'enc', '-d', '-aes-256-ctr', '-K', self.keys[2].hex(), '-iv', iv.hex()]
            decryptedMessage = subprocess.check_output(com, input=encryptedMessage).decode('latin-1').strip()
            return decryptedMessage
        else:
            print(Constants.AUTHENTICATION_MESSAGE_ERR)
            self._user.closeConnection()
            return


class TLSServerHandler():

    """
    This class handles the TLS handshake from the server side.
    """

    def __init__(self, server, folderName):
        """
        Initializes the class.

        Args:
            server (Server): The server object.
            folderName (str): The name of the folder where the server's files are stored.
        """
        self._folderName = folderName
        self._server = server
        self._connections = {}
        self._keyManagement = KeyManagement()

    @property
    def q(self):
        """
        Returns the q parameter of the Diffie-Hellman key exchange.
        """
        return self._q
    
    @property
    def g(self):
        """
        Returns the g parameter of the Diffie-Hellman key exchange.
        """
        return self._g
    
    @property
    def p(self):
        """
        Returns the p parameter of the Diffie-Hellman key exchange.
        """
        return self._p
    
    @property
    def connections(self):
        """
        Returns the connections dictionary.
        """
        return self._connections

    def tlsHandshake(self, params):
        """
        Performs the TLS handshake.
        
        Args:
            params (dict): The parameters received from the client.
        """
        callerFrame = inspect.currentframe().f_back
        callerSelf = callerFrame.f_locals.get('self', None)

        if params is not None:
            self._step1GenerateBAndK(params, callerSelf)
            self._step2SignAndEncrypt(params['user'], callerSelf)

    def _step1GenerateBAndK(self, params, callerSelf):
        """
        Performs the first step of the TLS handshake.

        Args:
            params (dict): The parameters received from the client.
            callerSelf (object): The object that called the function.
        """
        print('[Server {}]: '.format(self._server), 'sending DH contribution...')
        time.sleep(1)
        print('[Server {}]: '.format(self._server), 'generating DH key...')
        time.sleep(1)
        print('[Server {}]: '.format(self._server), 'creating TLS keys...')
        time.sleep(1)
        self._q = params['q']
        self._g = params['g']
        self._p = params['p']

        bytes_q = math.ceil((math.log2(abs(self._q) + 1)) / 8)
        com = [Constants.OPENSSL, 'rand', str(bytes_q)]
        y = int.from_bytes(subprocess.check_output(com), byteorder='big')

        B = pow(self._g, y, self._p)
        callerSelf.handshakeStep(2, {'B': B})

        K = pow(params['A'], y, self._p)

        labels = [b'key 1', b'key 2', b'key 3', b'key 4']
        self.keys = []
        for label in labels:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=label,
                backend=default_backend()
            )

            key = hkdf.derive(K.to_bytes(256, byteorder='big'))
            self.keys.append(key)
        
        self._connections[params['user']] = self.keys

    def _step2SignAndEncrypt(self, user, callerSelf):
        """ 
        Performs the second step of the TLS handshake.

        Args:
            user (str): The user that is performing the handshake.
            callerSelf (object): The object that called the function.
        """
        print('[Server {}]: '.format(self._server), 'sending public key and certificate...')
        time.sleep(1)
        signatureFile = self._folderName + Constants.SIGNATURE_FILENAME
        message = self._folderName + Constants.ECDSA_PUB_FILENAME + "\n" + self._folderName + Constants.CERTIFICATE_FILENAME
        self._keyManagement.sign(message, self._folderName + Constants.ECDSA_KEY_FILENAME, signatureFile)

        message = self._folderName + Constants.ECDSA_PUB_FILENAME + "\n" + self._folderName + Constants.CERTIFICATE_FILENAME

        com = [Constants.OPENSSL, 'rand', '16']
        self.iv = subprocess.check_output(com)

        com = [Constants.OPENSSL, 'enc', '-e', '-aes-256-ctr', '-K', self._connections[user][0].hex(), '-iv', self.iv.hex()]
        encryptedMessage = subprocess.check_output(com, input=message.encode()).strip()

        message = self._folderName + Constants.SIGNATURE_FILENAME
        
        com = [Constants.OPENSSL, 'enc', '-e', '-aes-256-ctr', '-K', self._connections[user][0].hex(), '-iv', self.iv.hex()]
        encryptedSignature = subprocess.check_output(com, input=message.encode())

        callerSelf.handshakeStep(3, {
                'encryptedMessage': encryptedMessage,
                'encryptedSignature': encryptedSignature,
                'iv': self.iv.hex()
            })
    
    def encryptMessage(self, message, user):
        """
        Encrypts a message.

        Args:
            message (str): The message to be encrypted.
            user (str): The user that is sending the message.
        """
        com = [Constants.OPENSSL, 'rand', '16']
        iv = subprocess.check_output(com)

        com = [Constants.OPENSSL, 'enc', '-e', '-aes-256-ctr', '-K', self._connections[user][2].hex(), '-iv', iv.hex()]
        encryptedMessage = subprocess.check_output(com, input=str(message).encode('latin-1'))

        com = [Constants.OPENSSL, 'mac', '-digest', 'sha256', '-macopt', 'hexkey:' + self._connections[user][3].hex(), 'HMAC']
        tagMac = subprocess.check_output(com, input=encryptedMessage)

        return encryptedMessage, tagMac, iv
    
    def decryptMessage(self, encryptedMessage, tagMac, iv, user):
        """
        Decrypts a message.

        Args:
            encryptedMessage (bytes): The encrypted message.
            tagMac (bytes): The MAC tag.
            iv (bytes): The initialization vector.  
            user (str): The user that is receiving the message.

        Returns:
            str: The decrypted message.
        """           
        com = [Constants.OPENSSL, 'mac', '-digest', 'sha256', '-macopt', 'hexkey:' + self._connections[user][3].hex(), 'HMAC']
        tagMacTemp = subprocess.check_output(com, input=encryptedMessage)

        if tagMacTemp == tagMac:
            com = [Constants.OPENSSL, 'enc', '-d', '-aes-256-ctr', '-K', self._connections[user][2].hex(), '-iv', iv.hex()]
            decryptedMessage = subprocess.check_output(com, input=encryptedMessage).decode('latin-1').strip()
            return decryptedMessage
        else:
            print(Constants.AUTHENTICATION_MESSAGE_ERR)
            self._server.closeConnection(user)
            return
