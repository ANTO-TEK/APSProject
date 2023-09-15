
import subprocess

from constants import Constants

class Node():

    """
    Node class, used to build the Merkle Tree
    
    Attributes:
        left (Node): The left child of the node.
        right (Node): The right child of the node.
        father (Node): The father of the node.
        data (str): The data of the node.
    """

    __slots__ = '_left', '_right', '_father' ,'_data'

    def __init__(self, data):
        """
        Constructor of the Node class.

        Args:
            data (str): The data of the node.
        """
        self._left = None
        self._right = None
        self._father = None
        self._data = data

    def __str__(self):
        """
        Returns the string representation of the node.
        """
        return str(self._data)
    
    
class LeafNode(Node):
        
        """
        LeafNode class, used to build the Merkle Tree
        
        Attributes:
            rowData (str): The data of the node.
        """

        __slots__ = '_rowData'
    
        def __init__(self, data):
            """
            Constructor of the LeafNode class.

            Args:
                data (str): The data of the node.
            """
            com = [Constants.OPENSSL, 'dgst', '-sha256']
            super().__init__(subprocess.check_output(com, input=data.encode('utf-8')).strip())
            self._rowData = data 
        
        def __str__(self):
            """
            Returns the string representation of the node.
            """
            return "Leaf Node: " + str(self._rowData) + " " + str(self._data)


class MerkleTree():

    """
    Merkle Tree class

    Attributes:
        _root (Node): The root of the Merkle Tree.
        _leaves (dict): The leaves of the Merkle Tree.
    """

    __slots__ = '_root', '_leaves'

    def __init__(self, data):
        """
        Constructor of the MerkleTree class.
        
        Args:
            data (list): The data to be stored in the Merkle Tree.
        """
        self._leaves = {}
        if len(data) % 2 != 0:
            data.append(data[-1])
        self._root = self._buildTree(data)
    
    def _buildTree(self, data):
        """
        Builds the Merkle Tree from the given data.
        
        Args:
            data (list): The data to be stored in the Merkle Tree.
            
        Returns:
            Node: The root of the Merkle Tree.
        """
        queue = []
        for elem in data:
            temp = LeafNode(elem[1])
            self._leaves[elem[0]] = temp
            queue.append(temp)
        while len(queue) > 1:
            left = queue.pop(0)
            right = queue.pop(0)
            queue.append(self._makeNode(left, right))
        return queue.pop(0)
    
    def getDataFromId(self, id):
        """
        Returns the data with the given id.
        
        Args:
            id (str): The id of the data to be returned.
        
        Returns:
            str: The data with the given id.
        """
        return self._leaves[id]._rowData

    def getProof(self, data):
        """
        Returns the proof of the given data.
        
        Args:
            data (str): The data to be proved.
            
        Returns:
            list: The proof of the given data.
        """
        proof = []
        node = self._leaves[data]
        if node == None:
            raise Exception("Data not found")
        while node._father != None:
            if node._father._left == node:
                proof.append((node._father._right._data, True))
            else:
                proof.append((node._father._left._data, False))
            node = node._father
        return proof
    
    @staticmethod
    def verifyProof(root, data, proof):
        """
        Verifies the proof of the given data.
        
        Args:
            root (str): The root of the Merkle Tree.
            data (str): The data to be proved.
            proof (list): The proof of the given data.
            
        Returns:
            bool: True if the proof is valid, False otherwise.
        """
        if data is None or proof is None or len(proof) == 0:
            return False 
        com = [Constants.OPENSSL, 'dgst', '-sha256']
        res = subprocess.check_output(com, input=data.encode('utf-8')).strip()
        while len(proof) > 0:
            elem = proof.pop(0)
            if not elem[1]:
                # elem is a left child
                com = [Constants.OPENSSL, 'dgst', '-sha256']
                res = subprocess.check_output(com, input=elem[0] + res).strip()
            else:
                # elem is a right child
                com = [Constants.OPENSSL, 'dgst', '-sha256']
                res = subprocess.check_output(com, input=res + elem[0]).strip()
        return res == root
    
    def getRoot(self):
        """
        Returns the root of the Merkle Tree.
        """
        return self._root
    
    def getRootHash(self):
        """
        Returns the hash of the root of the Merkle Tree.
        """
        return self._root._data

    def _makeNode(self, left, right):
        """
        Creates a new node from the given nodes.
        
        Args:
            left (Node): The left child of the new node.
            right (Node): The right child of the new node.
            
        Returns:
            Node: The new node.
        """
        com = [Constants.OPENSSL, 'dgst', '-sha256']
        node = Node(subprocess.check_output(com, input=left._data + right._data).strip())
        node._left = left
        node._right = right
        node._left._father = node
        node._right._father = node
        return node
    
    def __str__(self):
        """
        Returns the string representation of the Merkle Tree.
        """
        return self._printTree(self._root, 0)
    
    def _printTree(self, node, level):
        """
        Returns the string representation of the Merkle Tree.
        
        Args:
            node (Node): The node to be printed.
            level (int): The level of the node.
                
        Returns:
            str: The string representation of the Merkle Tree.
        """
        if node == None:
            return ""
        else:
            return self._printTree(node._left, level+1) + "\n" + "\t"*level + str(node) + self._printTree(node._right, level+1)
        
    