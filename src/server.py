import os
import subprocess
import datetime
import math
import ast
import time 
from tls import TLSServerHandler
from key_management import KeyManagement
from blockchain import ContributionGame
from green_pass import GreenPass, GPField
from database import Database
from green_pass import GreenPassVerifier
from blockchain import Blockchain
from constants import Constants

class Server():

    """ 
    Server class. It manages the connection with the client and the database.

    Attributes:
        _ecdsaKeyFile (str): ECDSA key file path
        _ecdsaPubFile (str): ECDSA public key file path
        _ecdsaParamFile (str): ECDSA parameter file path
        _connections (dict): dictionary of the active connections
        _IP (str): IP address of the server
        _keyManagement (KeyManagement): key management object
        _folderName (str): folder name of the server
        _tlsHandler (TLSServerHandler): TLS handler object
    """

    __slots__ = '_ecdsaKeyFile', '_ecdsaPubFile', '_ecdsaParamFile', '_IP', '_keyManagement', '_connections', \
                '_folderName', '_tlsHandler'

    def __init__(self, IP):
        """
        Constructor of the Server class.
        
        Args:
            IP (str): IP address of the server
        """
        self._connections = {}
        self._IP = IP
        self._folderName = "Server_" + self._IP
        self._tlsHandler = TLSServerHandler(self, self._folderName)
        self._keyManagement = KeyManagement()
        self._generateKey()

    def _generateKey(self):
        """
        Generate the ECDSA key pair.
        """
        self._ecdsaKeyFile = self._folderName + '/ecdsa_key.pem'
        self._ecdsaPubFile = self._folderName + '/ecdsa_pub.pem'
        self._ecdsaParamFile = self._folderName + '/prime256v1.pem'
        if not os.path.exists(self._folderName):
            os.mkdir(self._folderName)
            self._keyManagement.generateKey(self._ecdsaParamFile, self._ecdsaKeyFile, self._ecdsaPubFile)

    def startConnection(self, user):
        """
        Start a new connection with the client.
        
        Args:
            user (User): user object
        """
        print('[Server {}]: '.format(self), 'new connection from {}'.format(user))
        self._connections[user] = None 
    
    def closeConnection(self, user):
        """
        Close the connection with the client.

        Args:
            user (User): user object
        """
        print('[Server {}]: '.format(self), 'closing connection with {}...'.format(user))
        time.sleep(1)
        del self._connections[user]
        del self._tlsHandler._connections[user]
        print('[Server {}]: '.format(self), 'connection closed')
    
    @property
    def tlsHandler(self):
        """
        Getter of the TLS handler object.
        """
        return self._tlsHandler
    
    @property
    def connections(self):
        """
        Getter of the active connections dictionary.
        """
        return self._connections

    
class ServerMinistero(Server):

    """
    Class that extends the Server class. It represents the server of the Ministero della Salute.

    Attributes:
        _internalDB (Database): internal database object
        _otp (dict): dictionary of the one-time passwords
    """

    __slots__ = '_internalDB', '_otp'

    def __init__(self, IP):
        """
        Constructor of the ServerMinistero class.

        Args:
            IP (str): IP address of the server
        """
        super().__init__(IP)
        self._internalDB = Database()
        self._otp = {}
    
    def receiveSanityInfo(self, params, user):
        """
        Receive the sanity info from the client. If the info is correct, it sends the OTP to the client. Otherwise, it closes the connection. 

        Args:
            params (dict): dictionary of the parameters
            user (User): user object       
        """
        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
        message = ast.literal_eval(message)
        IDHealthCard = message[0]
        expirationDateHealthCard = message[1]
        print('[Server {}]: '.format(self), 'sanity info received')

        print('[Server {}]: '.format(self), 'checking info...')
        time.sleep(1)
        if not self._internalDB.checkUser(IDHealthCard):
            print('[Server {}]: '.format(self), Constants.USER_MESSAGE_ERR)
            self.closeConnection(user)
            return Constants.ERR

        if datetime.datetime.strptime(expirationDateHealthCard, '%Y-%m-%d') < datetime.datetime.now():
            print('[Server {}]: '.format(self), Constants.HC_MESSAGE_ERR)
            self.closeConnection(user)
            return Constants.ERR
        
        print('[Server {}]: '.format(self), 'user info correct')
        print('[Server {}]: '.format(self), 'sending OTP...')
        time.sleep(1)
        self._otp[user] = {'otp': self._sendOTP_SMS(user), 'IDHealthCard': IDHealthCard}

    def _sendOTP_SMS(self, user):
        """
        Send the OTP to the client.

        Args:
            user (User): user object
        """
        otp = self._generate_otp()
        encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(otp, user)
        user.receiveOTP({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv})
        return otp
    
    def _generate_otp(self):
        """
        Generate the OTP.
        """
        com = ["openssl", "rand", "-hex", "3"]

        openssl_output = subprocess.check_output(com)  
        return openssl_output.decode().strip()
    
    def receiveUserOtpAndPublicContribute(self, params, user):
        """
        Receive the OTP and the public key from the client. If the OTP is correct, it adds the public key to the database. Otherwise, it closes the connection.

        Args:
            params (dict): dictionary of the parameters
            user (User): user object
        """
        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
        message = ast.literal_eval(message)
        otp = message[0]
        userPublicKey = message[1]
        print('[Server {}]: '.format(self), 'OTP and public key received')
        time.sleep(1)

        if self._otp[user]['otp'] != otp:
            print('[Server {}]: '.format(self), Constants.OTP_MESSAGE_ERR)
            self.closeConnection(user)
            return Constants.ERR
  
        print('[Server {}]: '.format(self), 'OTP correctly verified')
        self._internalDB.addUserPubKey(self._otp[user]['IDHealthCard'], userPublicKey)
        greenPass = GreenPass(list(self._internalDB.getUserInfo(self._otp[user]['IDHealthCard']).items()))

        signatureFile = self._folderName + Constants.GP_SIGNATURE_FILENAME
        self._keyManagement.sign(greenPass.getGreenPassFootprint().decode(), self._ecdsaKeyFile, signatureFile)
        greenPass.setSignature(signatureFile)
        print('[Server {}]: '.format(self), 'sending green pass...')
        time.sleep(1)
        user.receiveGreenPass(greenPass)
    
    def __str__(self) -> str:
        """
        String representation of the object.
        """
        return Constants.SERVER_MS_NAME


class ServerMJ(Server):

    """
    Class that extends the Server class. It represents the server of Mister Joker's Sala Bingo.

    Attributes:
        _a, _c, _y (bytes): parameters identification scheme
        _blockchain (Blockchain): blockchain object
        _smartContract (ContributionGame): contribution game object
        _contribution (bytes): contribution of the server
        _commitment (bytes): commitment of the server contribution
    """

    __slots__ = '_a', '_c', '_y', '_blockchain', '_contribution', '_commitment', '_smartContract'

    def __init__(self, IP):
        """
        Constructor of the ServerMJ class.

        Args:
            IP (str): IP address of the server
        """
        super().__init__(IP)

    def receiveInitialInformation(self, params, user):
        """
        Receive the initial information from the client in order to verify that the green pass is valid e has not been revoked.

        Args:
            params (dict): dictionary of the parameters
            user (User): user object
        """
        if user not in self._connections:
            print('[Server {}]: '.format(self), Constants.USER_MESSAGE_ERR)
            self.closeConnection(user)
            return
        
        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
        message = ast.literal_eval(message)
        pubkey, pubkeyProof = message[0], message[1]
        v_ci, v_ciProof = message[2], message[3]
        greenPassFootprint, signature = message[4], message[5]

        if(GreenPassVerifier.greenPassVerify(greenPassFootprint, pubkey, pubkeyProof) and
           GreenPassVerifier.greenPassVerify(greenPassFootprint, v_ci, v_ciProof)):
            
            with open(Constants.REVOCATION_LIST_FILE_PATH, 'r') as f:
                revokedGPs = f.readlines()
                if v_ci in revokedGPs:
                    print('[Server {}]: '.format(self), Constants.GREENPASS_REVOKED_MESSAGE_ERR)
                    self.closeConnection(user)
                    return

            if(self._keyManagement.verifySign(greenPassFootprint.decode(), signature, Constants.PUBLIC_KEY_MINISTRY_FILE_PATH)):
                self._connections[user] = {'pubkey': pubkey, 'greenPassFootprint': greenPassFootprint}
                print('[Server {}]: '.format(self), 'green pass correctly verified')
            else:
                print('[Server {}]: '.format(self), Constants.GREENPASS_SIGNATURE_MESSAGE_ERR)
                self.closeConnection(user)
                return
        else:
            print('[Server {}]: '.format(self), Constants.GREENPASS_VERIFIED_MESSAGE_ERR)
            self.closeConnection(user)
            return

    def identificationSchemeStep1(self, params, user):
        """
        First step of the identification scheme. The server receive 'y' and 'a' from the client and sends 'c' to him.

        Args:
            params (dict): dictionary of the parameters
            user (User): user object
        """
        if params is not None:

            if user not in self._connections:
                print(Constants.USER_MESSAGE_ERR)
                self.closeConnection(user)
                return Constants.ERR
            
            message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
            message = ast.literal_eval(message)
            self._y = message[0]
            self._a = message[1]
            bytes_q = math.ceil((math.log2(abs(self._tlsHandler.q) + 1)) / 8)
            com = [Constants.OPENSSL, 'rand', str(bytes_q)]

            self._c = int.from_bytes(subprocess.check_output(com), byteorder='big')
            encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(self._c, user)
            user.identificationSchemeStep2({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv})
    
    def identificationSchemeStep2(self, params, user):
        """
        Second step of the identification scheme. The server receive 'z' from the client and verifies that 'z' is equal to 'a * y^c mod p'.

        Args:
            params (dict): dictionary of the parameters
            user (User): user object
        """
        if params is not None:
            message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
            val1 = pow(self._tlsHandler.g, ast.literal_eval(message), self._tlsHandler.p)
            val2 = (self._a * pow(self._y, self._c, self._tlsHandler.p)) % self._tlsHandler.p
            if(val1 == val2):
                print('[Server {}]: '.format(self), Constants.IDENTIFICATION_MESSAGE_OK)
                time.sleep(1)
                print('[Server {}]: '.format(self), 'guaranteed profile access')
            else:
                print('[Server {}]: '.format(self), Constants.IDENTIFICATION_MESSAGE_ERR)
                self.closeConnection(user)
                return
    
    def receivePolicyGDPRInfo(self, params, user):
        """
        Receive the policy GDPR information from the client. The server verifies that the green pass is the same
        that the client has sent before and that the signature is valid. Then it verifies the policy GDPR.
        
        Args:
            params (dict): dictionary of the parameters
            user (User): user object
        """
        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
        message = ast.literal_eval(message)
        print('[Server {}]: '.format(self), 'policy GDPR information received')
        print('[Server {}]: '.format(self), 'verifying policy GDPR information...')
        time.sleep(1)

        if self._connections[user]['greenPassFootprint'] != message['greenPassFootprint']:
            if(not self._keyManagement.verifySign(message['greenPassFootprint'].decode(), message['signature'], 'PublicInfo/public_key_MS.pem')):
                print('[Server {}]: '.format(self), Constants.GREENPASS_VERIFIED_MESSAGE_ERR)
                self.closeConnection(user)
                return Constants.ERR
        with open(Constants.POLICY_FILE_PATH, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.split()
                if line[0].strip() in message:
                    if(GreenPassVerifier.greenPassVerify(message['greenPassFootprint'], message[line[0].strip()], message[line[0].strip() + 'Proof'])):
                        if(not self._verifyPolicy(line[0].strip(), message[line[0].strip()], line[2].strip(), line[1].strip(), user)):
                            print('[Server {}]: '.format(self), Constants.POLICY_MESSAGE_ERR)
                            self.closeConnection(user)
                            return Constants.ERR
                    else:
                        print('[Server {}]: '.format(self), Constants.GREENPASS_VERIFIED_MESSAGE_ERR)
                        self.closeConnection(user)
                        return Constants.ERR
                else:
                    print('[Server {}]: '.format(self), Constants.POLICY_CHECK_MESSAGE_ERR)
                    self.closeConnection(user)
                    return Constants.ERR
        print('[Server {}]: '.format(self), Constants.POLICY_MESSAGE_OK)
        time.sleep(1)
        print('[Server {}]: '.format(self), 'user enabled to play')
    
    def _verifyPolicy(self, field, userValue, policyValue, operator, user):
        """
        Verify the policy GDPR. 

        Args:
            field (str): field of the policy
            userValue (str): value of the field of the user
            policyValue (str): value of the field of the policy
            operator (str): operator of the policy
            user (User): user object
        """
        if field == GPField.DOB.value:
            userValue = datetime.datetime.strptime(userValue, '%Y-%m-%d')
            if operator == '+=':

                current_date = datetime.datetime.now()
                age_timedelta = current_date - userValue
                age_years = age_timedelta.days // 365

                return age_years >= int(policyValue)
            
            print('[Server {}]: '.format(self), Constants.OPERATOR_MESSAGE_ERR + GPField.DOB.value)
            self.closeConnection(user)
            return
            
        elif field == GPField.V_DN.value:
            if operator == '+=':
                return userValue >= policyValue
            
            print('[Server {}]: '.format(self), Constants.OPERATOR_MESSAGE_ERR + GPField.V_DN.value)
            self.closeConnection(user)
            return

        elif field == GPField.V_CO.value:
            if operator == '=':
                return userValue == policyValue
            
            print('[Server {}]: '.format(self), Constants.OPERATOR_MESSAGE_ERR + GPField.V_CO.value)
            self.closeConnection(user)
            return
        
        elif field == GPField.V_DT.value:
            userValue = datetime.datetime.strptime(userValue, '%Y-%m-%d')
            if operator == '-=':

                current_date = datetime.datetime.now()
                time_difference = current_date - userValue
                return time_difference.days <= int(policyValue)
            
            print('[Server {}]: '.format(self), Constants.OPERATOR_MESSAGE_ERR + GPField.V_DT.value)
            self.closeConnection(user)
            return
        
        print('[Server {}]: '.format(self), Constants.FIELD_MESSAGE_ERR)
        self.closeConnection(user)
        return

    def startGame(self):
        """
        Start the game. The server sends the smart contract to all the players. 
        """
        print('\n[Server {}]: '.format(self), 'starting game...')
        time.sleep(1)
        self._blockchain = Blockchain.getBlockchain()

        print('[Server {}]: '.format(self), 'creating smart contract...')
        time.sleep(1)
        self._smartContract = ContributionGame(len(self._connections))
        self._smartContract.allPlayersContributed.subscribe(self.roundCompleted)

        print('[Server {}]: '.format(self), 'sending smart contract to the blockchain...')
        time.sleep(1)
        id = self._blockchain.addSmartContract(self._smartContract)
        
        for player in self._connections:
            print('\n[Server {}]: '.format(self), 'sending smart contract to player {}...'.format(player))
            time.sleep(1)
            encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(id, player)
            signatureFile = self._folderName + Constants.SIGNATURE_FILENAME
            self._keyManagement.sign(encryptedMessage, self._ecdsaKeyFile, signatureFile)
            player.receiveSmartContract({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv, 'signature': signatureFile})
    
    def round(self):
        """
        Start a round. The server generates a random number and computes the commitment. Then it sends the commitment to all the players.
        """
        print('[Server {}]: '.format(self), 'generating contribution...')
        time.sleep(1)
        com = [Constants.OPENSSL, 'rand', '32']
        self._contribution = subprocess.check_output(com)
        print('[Server {}]: '.format(self), 'creating commitment...')
        time.sleep(1)
        com = [Constants.OPENSSL, 'dgst', '-sha256']
        self._commitment = subprocess.check_output(com, input=self._contribution)
        for player in self._connections:
            print('\n[Server {}]: '.format(self), 'sending contribution to player {}...'.format(player))
            time.sleep(1)
            encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(self._commitment, player)
            signatureFile = self._folderName + Constants.SIGNATURE_FILENAME
            self._keyManagement.sign(encryptedMessage, self._ecdsaKeyFile, signatureFile)
            player.receiveCommitment({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv, 'signature': signatureFile})

    def roundCompleted(self, roundNumber):
        """
        Round completed. The server computes the final contribute and sends it to all the players.
        """
        time.sleep(1)
        print('[Server {}]: '.format(self), 'retreiving players contributions...')
        time.sleep(1)
        allContribuitions = self._smartContract.getContributions(roundNumber)
        
        print('[Server {}]: '.format(self), 'computing final random string...')
        time.sleep(1)
        finalContribute = int(0).to_bytes(32, byteorder='big') 
        for contribuition in allContribuitions:
            finalContribute = self._xorBytes(finalContribute, contribuition)
        finalContribute = self._xorBytes(finalContribute, self._contribution)
        print('[Server {}]: '.format(self), 'Random string: {}'.format(finalContribute.hex()))

        message = (finalContribute, self._contribution)
        for player in self._connections:
            print('\n[Server {}]: '.format(self), 'sending final random string and server contribution to player {}...'.format(player))
            time.sleep(1)
            encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(message, player)
            signatureFile = self._folderName + Constants.SIGNATURE_FILENAME
            self._keyManagement.sign(encryptedMessage, self._ecdsaKeyFile, signatureFile)
            player.receiveFinalContribute({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv, 'signature': signatureFile})

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
        
    def __str__(self) -> str:
        """
        Return the string representation of the user.
        """
        return Constants.SERVER_MJ_NAME
    





        
        

            

        

