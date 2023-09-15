from cryptography.hazmat.primitives import serialization
import subprocess
import os

from constants import Constants

class KeyManagement:

    """
    This class manages the keys of the users and the possibility of signing messages.
    """                

    __slots__ = '_privateKey', '_publicKey'
   
    def _checkFileExtension(self, filePath, extension):
        """Checks if the file extension is correct.
        
        Args:
            file_path (str): The path of the file.
            extension (str): The correct extension of the file.
            
        Returns:
            True if the extension is correct, False otherwise.
            
        Raises:
            Exception: If the extension is not correct.
        """
        _, fileExtension = os.path.splitext(filePath)
        if fileExtension == extension:
            return True
        else:
            raise Exception(Constants.FILE_EXTENSION_MESSAGE_ERR)
    
    def generateKey(self, ecdsaParamFile, ecdsaKeyFile, ecdsaPubFile):
        """
        Generate the ECDSA key pair for the user.
        
        The key pair is generated in a folder named "User_IP" where IP is the IP address of the user.
        
        The folder contains the following files:
            - ecdsa_key.pem: the private key of the user
            - ecdsa_pub.pem: the public key of the user
            - prime256v1.pem: the parameters of the elliptic curve used for the ECDSA algorithm
            
        If the folder already exists, the key pair is not generated
        
        Args:
            ecdsaParamFile (str): The path of the file containing the parameters of the elliptic curve used for the ECDSA algorithm.
            ecdsaKeyFile (str): The path of the file containing the private key of the user.
            ecdsaPubFile (str): The path of the file containing the public key of the user.
        """
        if not os.path.isfile(ecdsaKeyFile) and not os.path.isfile(ecdsaPubFile) and not os.path.isfile(ecdsaParamFile):

            if self._checkFileExtension(ecdsaKeyFile, '.pem') and self._checkFileExtension(ecdsaPubFile, '.pem') and self._checkFileExtension(ecdsaParamFile, '.pem'):

                com = [Constants.OPENSSL, 'ecparam', '-name', 'prime256v1', '-out', ecdsaParamFile]
                subprocess.check_output(com)
                com = [Constants.OPENSSL, 'genpkey', '-paramfile', ecdsaParamFile, '-out', ecdsaKeyFile]
                subprocess.check_output(com)
                com = [Constants.OPENSSL, 'pkey', '-in', ecdsaKeyFile, '-pubout', '-out', ecdsaPubFile]
                subprocess.check_output(com)

                with open(ecdsaKeyFile, 'rb') as f:
                    keys = serialization.load_pem_private_key(f.read(), password=None)
                self._privateKey = keys.private_numbers().private_value
                self._publicKey = keys.public_key().public_numbers().y

    def getPublicKey(self, ecdsaKeyFile):
        """
        Returns the public key of the user.
        
        Args:
            ecdsaKeyFile (str): The path of the file containing the private key of the user.

            REPLACE WITH: return self.publicKey
        """
        with open(ecdsaKeyFile, 'rb') as f:
            keys = serialization.load_pem_private_key(f.read(), password=None)
        return keys.public_key().public_numbers().y
    
    def getPrivateKey(self):
        """
        Returns the private key of the user.
        """
        return self._privateKey
    
    def sign(self, message, ecdsaKeyFile, signatureFile):
        """
        Signs the message with the private key of the user.
        
        Args:
            message (str): The message to sign.
            ecdsaKeyFile (str): The path of the file containing the private key of the user.
            signatureFile (str): The path of the file where the signature will be saved.
        """
        if self._checkFileExtension(ecdsaKeyFile, '.pem') and self._checkFileExtension(signatureFile, '.bin'):
            com = [Constants.OPENSSL, 'dgst', '-sign', ecdsaKeyFile, '-out', signatureFile]
            subprocess.check_output(com, input=str(message).encode())

    def verifySign(self, message, signature, publicKey):
        """
        Verifies the signature of the message.
        
        Args:
            message (str): The message to verify.
            signature (str): The path of the file containing the signature.
            publicKey (str): The path of the file containing the public key to verify.
            
        Returns:
            True if the signature is correct, False otherwise.
        """
        com = [Constants.OPENSSL, 'dgst', '-verify', publicKey, '-signature', signature]
        out = subprocess.check_output(com, input=str(message).encode())
        return out == b'Verified OK\n'