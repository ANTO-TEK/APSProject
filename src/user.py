import os
import shutil
import math
import subprocess
import ast
import time

from server import Server
from constants import Constants
from key_management import KeyManagement
from tls import TLSClientHandler
from green_pass import GPField
from blockchain import Blockchain

class User():

    """
    This class represents a user.
    """

    __slots__ = '_ecdsaKeyFile', '_ecdsaPubFile', '_ecdsaParamFile', '_IP', '_server', '_tlsHandler', '_greenPass', '_otp', '_keyManagement', '_folderName'

    def __init__(self, IP):
        """
        Initialize the user with the given IP address.

        Args:
            IP (str): The IP address of the user.
        """
        self._IP = IP
        self._folderName = "User_" + self._IP
        self._server = None
        self._greenPass = None
        self._otp = None
        self._keyManagement = KeyManagement()
        self._generateKey()
        
    def _generateKey(self):
        """
        Generate the ECDSA key pair for the user.
        
        The key pair is generated in a folder named "User_IP" where IP is the IP address of the user.
        
        The folder contains the following files:
            - ecdsa_key.pem: the private key of the user
            - ecdsa_pub.pem: the public key of the user
            - prime256v1.pem: the parameters of the elliptic curve used for the ECDSA algorithm
            
            If the folder already exists, the key pair is not generated
        """
        self._ecdsaKeyFile = self._folderName + Constants.ECDSA_KEY_FILENAME
        self._ecdsaPubFile = self._folderName + Constants.ECDSA_PUB_FILENAME
        self._ecdsaParamFile = self._folderName + Constants.ECDSA_PARAM_FILENAME
        
        if not os.path.exists(self._folderName):
            os.mkdir(self._folderName)
            self._keyManagement.generateKey(self._ecdsaParamFile, self._ecdsaKeyFile, self._ecdsaPubFile)

    def connect(self, server):
        """
        Connect the user to the given server.

        Args:
            server (Server): The server to connect to.
        
        Raises:
            TypeError: If server is not an instance of Server.
        """
        if not isinstance(server, Server):
            print('[User {}]: '.format(self), Constants.SERVER_MESSAGE_ERR)
            return Constants.ERR
        
        self._server = server
        print('[User {}]: '.format(self), 'connecting to {}...'.format(server))
        time.sleep(1)
        self._server.startConnection(self) 

        # TLS handshake 
        print('\n[User {}]: '.format(self), 'starting TLS handshake...')
        time.sleep(1)
        self._tlsHandler = TLSClientHandler(self, self._folderName, self._server)
        self._tlsHandler.handshakeStep(1) 
    
    def closeConnection(self):
        """
        Close the connection with the server.
        """
        self._server.closeConnection(self)
        self._server = None
        self._tlsHandler = None
        self._otp = None
    
    def sendSanityInfo(self, IDHealthCard, expirationDateHealthCard):
        """
        Send the sanity information to the server.
        
        Args:
            IDHealthCard (str): The ID of the health card.
            expirationDateHealthCard (str): The expiration date of the health card.
        """
        print('\n[User {}]: '.format(self), 'sending sanity information...')
        time.sleep(1)
        message = (IDHealthCard, expirationDateHealthCard)
        encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(message)
        return self._server.receiveSanityInfo({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)
    
    def receiveOTP(self, params):
        """
        Receive the OTP from the server.
        
        Args:
            params (dict): The dictionary containing the encrypted message, the tagMac and the iv.
            server (Server): The server that sent the OTP.
        """
        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'])
        self._otp = message
        print('[User {}]: '.format(self), 'OTP received {}'.format(self._otp))
        
    def sendOTP(self, otp):
        """
        Send the OTP to the server.
        """
        print('\n[User {}]: '.format(self), 'sending OTP and public key...')
        time.sleep(1)
        message = (otp, self._ecdsaPubFile)
        encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(message)
        return self._server.receiveUserOtpAndPublicContribute({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)

    def receiveGreenPass(self, greenPass):
        """
        Receive the green pass from the server.

        Args:
            greenPass (GreenPass): The green pass received from the server.
            server (Server): The server that sent the green pass.
        """
        print('[User {}]: '.format(self), 'green pass received')
        self._greenPass = greenPass
        shutil.move(self._greenPass.getSignature(), self._folderName + Constants.GP_SIGNATURE_FILENAME)
        self._greenPass.setSignature(self._folderName + Constants.GP_SIGNATURE_FILENAME)

        print('[User {}]: '.format(self), 'closing connection...')
        time.sleep(1)
        self.closeConnection()
        return

    def __str__(self) -> str:
        """
        Return the string representation of the user.
        """
        return self._IP


class Player(User):

    """
    This class represents a player.
    """

    __sloots__ = 'r', '_blockchain', '_smartContract', '_serverCommitment'

    def __init__(self, IP):
        """
        Initialize the player with the given IP address.

        Args:
            IP (str): The IP address of the player.
        """
        super().__init__(IP)
    
    def sendInitialInformation(self):
        """
        Send the initial information to the server. In particular, the public key of the user (present in the green pass) 
        and the unique identifier of the green pass (V_CI) in order to verify that it hadn't been revoked.
        """
        if self._greenPass is not None:
            print('\n[User {}]: '.format(self), 'sending green pass footprint...')
            time.sleep(1)
            message = (self._greenPass.getData(GPField.PUB_KEY.value), self._greenPass.getDataProof(GPField.PUB_KEY.value),
                       self._greenPass.getData(GPField.V_CI.value), self._greenPass.getDataProof(GPField.V_CI.value),
                       self._greenPass.getGreenPassFootprint(), self._greenPass.getSignature())
            
            encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(message)
            self._server.receiveInitialInformation({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)

        else:
            print(Constants.GREENPASS_MESSAGE_ERR)
            self.closeConnection()
            return Constants.ERR
    
    def identificationScheme(self):
        """
        Execute the identification scheme with the server.
        """
        print('\n[User {}]: '.format(self), 'starting identification...')
        time.sleep(1)
        bytes_q = math.ceil((math.log2(abs(self._tlsHandler.q) + 1)) / 8)
        com = [Constants.OPENSSL, 'rand', str(bytes_q)]
        self.r = int.from_bytes(subprocess.check_output(com), byteorder='big')
        a = pow(self._tlsHandler.g, self.r, self._tlsHandler.p)
        
        message = (pow(self._tlsHandler.g, self._tlsHandler.x, self._tlsHandler.p), a)
        encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(message)
        return self._server.identificationSchemeStep1({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)

    def identificationSchemeStep2(self, params):
        """
        Execute the second step of the identification scheme with the server.

        Args:
            params (dict): The dictionary containing the encrypted message, the tagMac and the iv.
        """
        if params is not None:
            message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'])
            z = self.r + ast.literal_eval(message) * self._tlsHandler.x
            encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(z)
            self._server.identificationSchemeStep2({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)

    def sendPolicyGDPRInfo(self):
        """
        Send the policy GDPR information to the server.
        """
        print('\n[User {}]: '.format(self), 'sending policy GDPR information...')
        time.sleep(1)
        policyGDPRInfo = {}
        with open(Constants.POLICY_FILE_PATH, 'r') as f:
            policyGDPR = f.readlines()
            for line in policyGDPR:
                line = line.split(' ')
                policyGDPRInfo[line[0]] = self._greenPass.getData(line[0].strip())
                policyGDPRInfo[line[0] + 'Proof'] = self._greenPass.getDataProof(line[0].strip())

        policyGDPRInfo['greenPassFootprint'] = self._greenPass.getGreenPassFootprint()
        policyGDPRInfo['signature'] = self._greenPass.getSignature()

        encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(policyGDPRInfo)
        return self._server.receivePolicyGDPRInfo({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)

    def receiveSmartContract(self, params):
        """
        Receive the smart contract from the server.

        Args:
            params (dict): The dictionary containing the encrypted message, the tagMac and the iv.
        """
        if self._keyManagement.verifySign(params['message'], params['signature'], self._tlsHandler.pks):
            os.remove(params['signature'])

            message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'])
            self._blockchain = Blockchain.getBlockchain()
            self._smartContract = self._blockchain.getSmartContract(int(message))
            print('[User {}]: '.format(self), 'smart contract received')
        else:
            print('[User {}]: '.format(self), Constants.IDSC_SIGNATURE_MESSAGE_ERR)
            self.closeConnection()
            return
    
    def receiveCommitment(self, params):    
        """
        Receive the commitment from the server.

        Args:
            params (dict): The dictionary containing the encrypted message, the tagMac and the iv.
        """
        if self._keyManagement.verifySign(params['message'], params['signature'], self._tlsHandler.pks):
            os.remove(params['signature'])
            message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'])
            self._serverCommitment = message
            print('[User {}]: '.format(self), 'server commitment received')
        else:
            print('[User {}]: '.format(self), Constants.COMM_SIGNATURE_MNESAGE_ERR)
            self.closeConnection()
            return
    
    def sendContribution(self):
        """
        Send the contribution to the smart contract. 
        """
        print('\n[User {}]: '.format(self), 'sending contribution to the smart contract...')
        time.sleep(1)
        com = [Constants.OPENSSL, 'rand', '32']
        self.contribute = subprocess.check_output(com)
        self._smartContract.contribute(self._keyManagement.getPublicKey(self._folderName + Constants.ECDSA_KEY_FILENAME), self.contribute)
    
    def receiveFinalContribute(self, params):
        """
        Receive the final contribute from the server. Verify the signature and the commitment.  
        If the verification is successful, compute the random string and verify it.

        Args:
            params (dict): The dictionary containing the encrypted message, the tagMac and the iv.
        """
        if self._keyManagement.verifySign(params['message'], params['signature'], self._tlsHandler.pks):
            os.remove(params['signature'])

            message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'])
            message = ast.literal_eval(message)
            randomString = message[0]
            serverContribute = message[1]
            print('[User {}]: '.format(self), 'final random string and server contribution received')
            print('[User {}]: '.format(self), 'verifying server commitment...')
            time.sleep(1)
            if self._verifyCommitment(serverContribute, self._serverCommitment):
                print('[User {}]: '.format(self), 'server commitment verified')

                print('[User {}]: '.format(self), 'verifying random string...')
                time.sleep(1)
                allContribuitions = self._smartContract.getContributions(self._smartContract.roundNumber)
                computedRandomString = int(0).to_bytes(32, byteorder='big') 

                for contribuition in allContribuitions:
                    computedRandomString = self._xorBytes(computedRandomString, contribuition)
                computedRandomString = self._xorBytes(computedRandomString, serverContribute)

                if computedRandomString == randomString:
                    print('[User {}]: '.format(self), 'random string verified')
                else:
                    print('[User {}]: '.format(self), Constants.RS_VERIFY_MESSAGE_ERR)
                    self.closeConnection()
                    return
            else:
                print('[User {}]: '.format(self), Constants.COMM_VERIFY_MESSAGE_ERR)
                self.closeConnection()
                return
        else:
            print('[User {}]: '.format(self), Constants.RS_SC_SIGNATURE_MESSAGE_ERR)
            self.closeConnection()
            return
    
    def _verifyCommitment(self, contirbute, commitment):
        """
        Verify the commitment.

        Args:
            contirbute (bytes): The contribute.
            commitment (bytes): The commitment.

        Returns:
            bool: True if the commitment is valid, False otherwise.
        """
        com = [Constants.OPENSSL, 'dgst', '-sha256']
        return str(subprocess.check_output(com, input=contirbute)) == str(commitment)
    
    def _xorBytes(self, bytes1, bytes2):
        """
        Perform the XOR operation between two bytes.

        Args:   
            bytes1 (bytes): The first bytes.
            bytes2 (bytes): The second bytes.

        Returns:
            bytes: The result of the XOR operation.
        """
        # Ensure the input bytes have the same length
        if len(bytes1) != len(bytes2):
            raise ValueError(Constants.XOR_MESSAGE_ERR)

        # Perform the XOR operation
        result = bytes([a ^ b for a, b in zip(bytes1, bytes2)])
        return result
        
        
        
        
    
