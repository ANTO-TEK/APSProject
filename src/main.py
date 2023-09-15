from user import Player
from server import ServerMinistero, ServerMJ
from constants import Constants

serverMS = ServerMinistero(Constants.IP_MS)
serverMJ = ServerMJ(Constants.IP_MJ)

print("\n#####################################################")
print("\n#                     WELCOME                       #")
print("\n#####################################################")

print("\nHow many users do you want to simulate? ", end="")
numUsers = int(input())

users = []
for _ in range(numUsers):
    print("\nInsert the IP address of the user: ", end="")
    ip = input()
    users.append(Player(ip))

print("\n#####################################################")
print("\n#                Green Pass request                 #")
print("\n#####################################################")

for user in users:
    print("\n## User " + str(user) + " is requesting the Green Pass... ##\n")
    if(user.connect(serverMS) == Constants.ERR):
        continue
    print("\nInsert the last 8 digits of your HealthCard: ", end="")
    idHealthCard = input()
    print("\nInsert the HealthCard expiration date (format YYYY-mm-dd): ", end="")
    expDate = input()
    if(user.sendSanityInfo(idHealthCard, expDate) == Constants.ERR):
        continue
    print("\nInsert the OTP received on your phone: ", end="")
    otp = input()
    if(user.sendOTP(otp) == Constants.ERR):
        continue

print("\n#####################################################")
print("\n#              Sala Bingo Mister Joker              #")
print("\n#####################################################")

players = []
for user in users:
    print("\n## User " + str(user) + " is accessing to Sala Bingo Mister Joker... ##\n")
    if(user.connect(serverMJ) == Constants.ERR or 
       user.sendInitialInformation() == Constants.ERR or
       user.identificationScheme() == Constants.ERR or
       user.sendPolicyGDPRInfo() == Constants.ERR):
        continue
    players.append(user)

print("\n#####################################################")
print("\n#                Game initialization                #")
print("\n#####################################################")

serverMJ.startGame()
for round in range(1, Constants.ROUNDS + 1):
    print("\n## Starting round {}... ##\n".format(round))
    serverMJ.round()
    for player in players:
        player.sendContribution()
    print("\n## Round {} completed. ##\n".format(round))

print("\n#####################################################")
print("\n#                      GOODBYE                      #")
print("\n#####################################################\n")