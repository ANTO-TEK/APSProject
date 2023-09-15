
class Database():

    """
    The Database class represents a simple in-memory database that stores information about users and their COVID-19 vaccination certificates. 
    Each user is uniquely identified by their IDHealthCard, and their corresponding vaccination information is stored as a dictionary. 
    The class provides methods to check the existence of a user, add a public key for a user, and retrieve user information from the database.
    """
    
    users = {"11111111": 
                {
                    "nam/fn": "John Doe",                   # Name of the Green Pass holder
                    "dob": "1985-07-15",                    # Date of birth (YYYY-MM-DD format)
                    "v/tg": "840539006",                    # Disease or agent targeted (COVID-19)
                    "v/vp": "1119305005",                   # COVID-19 vaccine or prophylaxis
                    "v/mp": "EU/1/21/1529",                 # COVID-19 vaccine product (Pfizer-BioNTech Comirnaty)
                    "v/ma": "ORG-100030215",                # COVID-19 vaccine marketing authorisation holder or manufacturer (Pfizer Europe MA EEIG)
                    "v/dn": "2",                            # Number in a series of doses (Second dose)
                    "v/sd": "2",                            # The overall number of doses in the series (Two doses)
                    "v/dt": "2023-01-28",                   # Date of vaccination (YYYY-MM-DD format)
                    "v/co": "IT",                           # Member State or third country in which the vaccine was administered (Italy)
                    "v/is": "Italian Health Ministry",      # Certificate issuer (Italian Health Ministry)
                    "v/ci": "ABC123XYZ456"                  # Unique certificate identifier
                },
                "22222222": {
                    "nam/fn": "Jane Smith",
                    "dob": "1990-11-20",
                    "v/tg": "840539006",
                    "v/vp": "1119305005",
                    "v/mp": "EU/1/21/1529",
                    "v/ma": "ORG-100030215",
                    "v/dn": "2",
                    "v/sd": "2",
                    "v/dt": "2023-07-10",
                    "v/co": "IT",
                    "v/is": "Italian Health Ministry",
                    "v/ci": "XYZ456ABC123"
                },
                "33333333": {
                    "nam/fn": "Alice Johnson",
                    "dob": "1978-03-12",
                    "v/tg": "840539006",
                    "v/vp": "1119305005",
                    "v/mp": "EU/1/21/1529",
                    "v/ma": "ORG-100030215",
                    "v/dn": "2",
                    "v/sd": "2",
                    "v/dt": "2023-04-05",
                    "v/co": "IT",
                    "v/is": "Italian Health Ministry",
                    "v/ci": "XYZ123ABC456"
                },
                "44444444": {
                    "nam/fn": "Bob Roberts",
                    "dob": "1995-09-28",
                    "v/tg": "840539006",
                    "v/vp": "1119305005",
                    "v/mp": "EU/1/21/1529",
                    "v/ma": "ORG-100030215",
                    "v/dn": "2",
                    "v/sd": "2",
                    "v/dt": "2023-03-15",
                    "v/co": "IT",
                    "v/is": "Italian Health Ministry",
                    "v/ci": "DEF456GHI789"
                },
                "55555555": {
                    "nam/fn": "Carol Lee",
                    "dob": "1989-12-02",
                    "v/tg": "840539006",
                    "v/vp": "1119305005",
                    "v/mp": "EU/1/21/1529",
                    "v/ma": "ORG-100030215",
                    "v/dn": "2",
                    "v/sd": "2",
                    "v/dt": "2023-02-10",
                    "v/co": "IT",
                    "v/is": "Italian Health Ministry",
                    "v/ci": "XYZ789ABC123"
                },
                "66666666": {
                    "nam/fn": "David Wilson",
                    "dob": "1973-06-18",
                    "v/tg": "840539006",
                    "v/vp": "1119305005",
                    "v/mp": "EU/1/21/1529",
                    "v/ma": "ORG-100030215",
                    "v/dn": "2",
                    "v/sd": "2",
                    "v/dt": "2023-06-30",
                    "v/co": "IT",
                    "v/is": "Italian Health Ministry",
                    "v/ci": "JKL456MNO789"
                },
                "77777777": {
                    "nam/fn": "Eva Hernandez",
                    "dob": "1980-04-25",
                    "v/tg": "840539006",
                    "v/vp": "1119305005",
                    "v/mp": "EU/1/21/1529",
                    "v/ma": "ORG-100030215",
                    "v/dn": "2",
                    "v/sd": "2",
                    "v/dt": "2023-08-01",
                    "v/co": "IT",
                    "v/is": "Italian Health Ministry",
                    "v/ci": "OPQ789RST123"
                },
                "88888888": {
                    "nam/fn": "Frank Brown",
                    "dob": "1997-01-09",
                    "v/tg": "840539006",
                    "v/vp": "1119305005",
                    "v/mp": "EU/1/21/1529",
                    "v/ma": "ORG-100030215",
                    "v/dn": "2",
                    "v/sd": "2",
                    "v/dt": "2023-05-20",
                    "v/co": "IT",
                    "v/is": "Italian Health Ministry",
                    "v/ci": "UVW456XYZ789"
                },
            }


    def checkUser(self, user):
        """
        Check if the given user IDHealthCard exists in the database.

        Args:
            user (str): The IDHealthCard of the user to check.

        Returns:
            bool: True if the user exists in the database, False otherwise.
        """
        if user not in self.users.keys():
            return False
        return True

    def addUserPubKey(self, user, pubKey):
        """
        Add the public key for a user in the database.

        Args:
            user (str): The IDHealthCard of the user.
            pubKey (str): The public key associated with the user.

        """
        self.users[user]['pubKey'] = pubKey
    
    def getUserInfo(self, user):
        """
        Get the vaccination information for a specific user from the database.

        Parameters:
            user (str): The IDHealthCard of the user.

        Returns:
            dict: A dictionary containing the vaccination information of the user.
        """
        return self.users[user]
    





