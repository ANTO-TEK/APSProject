
from constants import Constants

class Blockchain():

    """
    Blockchain class.

    _smartContracts: dict   # dictionary of smart contracts
    _id: int                # id of the smart contract
    """

    __sloots__ = '_smartContracts', '_id'

    blockchain = None  # singleton instance

    @staticmethod
    def getBlockchain():
        """
        Return the singleton instance of the blockchain.
        """
        if Blockchain.blockchain is None:
            Blockchain.blockchain = Blockchain()
        return Blockchain.blockchain

    def __init__(self):
        """
        Initialize the blockchain.
        """
        self._smartContracts = {}
        self._id = 0

    def addSmartContract(self, smartContract):
        """
        Add a smart contract to the blockchain.

        Args:
            smartContract: SmartContract 
        """
        self._id += 1
        self._smartContracts[self._id] = smartContract
        return self._id
    
    def getSmartContract(self, id):
        """
        Return the smart contract with the given id.

        Args:
            id: int
        """
        return self._smartContracts[id]


class Event():

    """
    Event class.
    
    _observers: list    # list of observers
    """

    def __init__(self):
        """
        Initialize the event.
        """
        self._observers = []

    def subscribe(self, observer):
        """
        Subscribe an observer to the event.
        
        Args:
            observer: function
        """
        self._observers.append(observer)

    def unsubscribe(self, observer):
        """
        Unsubscribe an observer from the event.

        Args:
            observer: function
        """
        self._observers.remove(observer)

    def notify(self, *args, **kwargs):
        """
        Notify all the observers of the event.

        Args:
            *args: list
            **kwargs: dict
        """
        for observer in self._observers:
            observer(*args, **kwargs)


class ContributionGame():

    """
    ContributionGame class.

    numberOfPlayers: int    # number of players
    roundNumber: int        # number of the current round
    contributions: dict     # dictionary of contributions
    uniqueContributions: dict   # dictionary of unique contributions
    allPlayersContributed: Event    # event that notifies when all the players have contributed
    """

    def __init__(self, _numberOfPlayers):
        """
        Initialize the contribution game.

        Args:
            _numberOfPlayers: int
        """
        self.numberOfPlayers = _numberOfPlayers
        self.roundNumber = 1
        self.contributions = {}
        self.uniqueContributions = {}
        self.allPlayersContributed = Event()

    class Contribution():

        """
        Contribution class.

        contribution: bytes       # contribution
        contributed: bool       # True if the player has contributed, False otherwise
        """

        def __init__(self, contribution, contributed):
            """
            Initialize the contribution.

            Args:
                contribution: bytes
                contributed: bool
            """
            self.contribution = contribution
            self.contributed = contributed

    def contribute(self, sender, _contribution):
        """
        Add a contribution to the game.

        Args:
            sender: Player
            _contribution: bytes
        """
        if not self.contributions.get(self.roundNumber):
            self.contributions[self.roundNumber] = {}
        
        if not self.uniqueContributions.get(self.roundNumber):
            self.uniqueContributions[self.roundNumber] = {}

        if self.contributions[self.roundNumber].get(sender) and self.contributions[self.roundNumber][sender].contributed:
            raise ValueError(Constants.CONTRIBUTION_MESSAGE_ERR)
        
        if self.uniqueContributions[self.roundNumber].get(_contribution):
            raise ValueError(Constants.UNIQUE_CONTRIBUTION_MESSAGE_ERR)

        self.contributions[self.roundNumber][sender] = self.Contribution(_contribution, True)
        self.uniqueContributions[self.roundNumber][_contribution] = True

        self._writeContributionInfoToFile(sender)

        if self._allPlayersHaveContributed():
            print('\n[SmartContract {}]: '.format(self), 'all players have contributed\n')
            self.allPlayersContributed.notify(self.roundNumber)
            self.roundNumber += 1

    def getContributions(self, roundNumber):
        """
        Return the contributions of the given round.    

        Args:
            roundNumber: int
        """
        if not self.contributions.get(roundNumber):
            return []
        playersContributions = []
        for contribution in self.contributions[roundNumber].values():
            playersContributions.append(contribution.contribution)
        return playersContributions

    def _allPlayersHaveContributed(self):
        """
        Return True if all the players have contributed, False otherwise.
        """
        return len(self.contributions[self.roundNumber].values()) == self.numberOfPlayers
    
    def _writeContributionInfoToFile(self, sender):
        """
        Write the contribution info to a file.

        Args:
            sender: Player
        """
        with open(Constants.BLOCKCHAIN_FILE_PATH, 'a') as file:
            file.write(f"Player: {sender}\n")
            file.write(f"Round: {self.roundNumber}\n")
            file.write("Contribution: ")
            file.write(str(self.contributions[self.roundNumber][sender].contribution))
            file.write("\n\n")
    
    def __str__(self):
        """
        Return the string representation of the contribution game.
        """
        return Constants.SMART_CONTRACT_NAME
