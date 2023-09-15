
class Constants():

    """
    Constants class.
    """

    __sloots__ = ()

    ERR = -1

    # main.py constants
    IP_MS = '193.205.162.73'
    IP_MJ = '214.23.65.7'
    ROUNDS = 5

    # openssl path
    OPENSSL = '/Users/antonio/Documents/openssl/bin/ProjectWorkWP4/openssl'

    ECDSA_KEY_FILENAME = '/ecdsa_key.pem'
    ECDSA_PUB_FILENAME = '/ecdsa_pub.pem'
    ECDSA_PARAM_FILENAME = '/prime256v1.pem'
    DH_PARAM_FILENAME = '/dhparam.pem'
    DH_KEY_FILENAME = '/dhkey.pem'

    GP_SIGNATURE_FILENAME = '/GPsignature.bin'
    POLICY_FILE_PATH = 'PublicInfo/policyGDPR.txt'
    REVOCATION_LIST_FILE_PATH = 'PublicInfo/revokedGP.txt'
    PUBLIC_KEY_MINISTRY_FILE_PATH = 'PublicInfo/public_key_MS.pem'

    XOR_MESSAGE_ERR = 'Input bytes must have the same length'

    # tls.py constants
    TLS_SIGNATURE_MESSAGE_OK = 'TLS signature verified'
    TLS_SIGNATURE_MESSAGE_ERR = 'TLS signature not verified'

    CA_FILE_PATH = 'CA/cacert.pem'

    AUTHENTICATION_MESSAGE_ERR = 'Message authentication failed'

    SIGNATURE_FILENAME = '/signature.bin'
    CERTIFICATE_FILENAME = '/cert.pem'

    # key_management.py constants
    FILE_EXTENSION_MESSAGE_ERR = 'Invalid file extension'

    # blockchain.py constants
    CONTRIBUTION_MESSAGE_ERR = 'Player has already contributed for this round'
    UNIQUE_CONTRIBUTION_MESSAGE_ERR = 'Contribution must be unique'

    BLOCKCHAIN_FILE_PATH = 'PublicInfo/contribution_info.txt'

    # user.py constants
    SERVER_MESSAGE_ERR = 'invalid server'
    
    GREENPASS_MESSAGE_ERR = '\nAttention! You have not a green pass\n'

    IDSC_SIGNATURE_MESSAGE_ERR = 'smart contract signature not verified'

    COMM_SIGNATURE_MNESAGE_ERR = 'commitment signature not verified'
    COMM_VERIFY_MESSAGE_ERR = 'commitment not verified'

    RS_VERIFY_MESSAGE_ERR = 'random string not verified'
    
    RS_SC_SIGNATURE_MESSAGE_ERR = 'final random string and server contribution signature not verified'

    # server.py constants
    USER_MESSAGE_ERR = 'user not found'
    HC_MESSAGE_ERR = 'health card expired'
    OTP_MESSAGE_ERR = 'invalid OTP'

    GREENPASS_REVOKED_MESSAGE_ERR = 'green pass revoked'
    GREENPASS_VERIFIED_MESSAGE_OK = 'green pass verified'
    GREENPASS_VERIFIED_MESSAGE_ERR = 'green pass not verified'
    GREENPASS_SIGNATURE_MESSAGE_OK = 'green pass signature verified'
    GREENPASS_SIGNATURE_MESSAGE_ERR = 'green pass signature not verified'

    IDENTIFICATION_MESSAGE_OK = 'user identified'
    IDENTIFICATION_MESSAGE_ERR = 'user not identified'

    POLICY_MESSAGE_OK = 'policy accepted'
    POLICY_MESSAGE_ERR = 'policy rejected'
    POLICY_CHECK_MESSAGE_ERR = 'not all the policy info are present'
    OPERATOR_MESSAGE_ERR = 'invalid operator for field '
    FIELD_MESSAGE_ERR = 'invalid field'

    SERVER_MS_NAME = 'Ministero della Salute'
    SERVER_MJ_NAME = 'Sala Bingo Mister Joker'
    SMART_CONTRACT_NAME = 'Contribution Game'