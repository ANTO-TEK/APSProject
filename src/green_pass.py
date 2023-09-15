from merkle_tree import MerkleTree
from enum import Enum

class GPField(Enum):

    """
    GPField is an enum class that contains all the fields of the Green Pass.
    """

    NAM_FN = "nam/fn"
    DOB = "dob"                    
    V_TG = "v/tg"
    V_VP = "v/vp"
    V_MP = "v/mp"
    V_MA = "v/ma"
    V_DN = "v/dn"
    V_SD = "v/sd"
    V_DT = "v/dt"
    V_CO = "v/co"
    V_IS = "v/is"
    V_CI = "v/ci"
    PUB_KEY = "pubKey"

class GreenPass():

    """
    Class that represents the Green Pass.

    Attributes: 
        _merkleTree (MerkleTree): The Merkle Tree that contains the Green Pass data.
        _signature (str): The signature of the Green Pass.
    """

    __slots__ = '_merkleTree', '_signature'

    def __init__(self, data):
        """
        Constructor for the GreenPass class.

        Args:
            data (dict): The data to be stored in the Merkle Tree.
        """
        self._merkleTree = MerkleTree(data)

    def getData(self, id):
        """
        Return the data with the given id.
        """
        return self._merkleTree.getDataFromId(id)

    def getDataProof(self, data):
        """
        Return the proof of the given data.

        Args:
            data (str): The data to be proved.

        Returns:
            list: The proof of the given data.
        """
        return self._merkleTree.getProof(data)
    
    def getGreenPassFootprint(self):
        """
        Return the root hash of the Merkle Tree.
        """
        return self._merkleTree.getRootHash()
    
    def setSignature(self, signature):
        """
        Set the signature of the Green Pass.
        
        Args:
            signature (str): The signature of the Green Pass.
        """
        self._signature = signature
    
    def getSignature(self):
        """
        Return the signature of the Green Pass.
        """
        return self._signature
    

class GreenPassVerifier():

    """
    Class that contains the methods to verify the Green Pass.
    """

    @staticmethod
    def greenPassVerify(greenPassFootprint, data, proof):
        """
        Verify the Green Pass.

        Args:
            greenPassFootprint (str): The root hash of the Merkle Tree.
            data (str): The data to be proved.
            proof (list): The proof of the given data.

        Returns:
            bool: True if the Green Pass is valid, False otherwise.
        """
        return MerkleTree.verifyProof(greenPassFootprint, data, proof)
    