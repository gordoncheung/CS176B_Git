
from socket import *
import sys

#check that 3 args were give
if (len(sys.argv) != 3):
  print 'ERROR: Invalid number of args. Terminating.'
  exit()

serverName = sys.argv[1]
serverPort = int(sys.argv[2])

#check for valid port
if (serverPort > 65535) or (serverPort < 1025):
  print 'ERROR: Invalid port. Terminating.'
  exit()


clientSocket = socket(AF_INET, SOCK_DGRAM)
print 'Connected.'

while 1:
  sentence = raw_input()

  #exit when commanded
  if sentence == 'exit':
    break

  clientSocket.sendto(sentence, (serverName, serverPort))
  modSentence, serverAddress = clientSocket.recvfrom(4096)
  print(modSentence)

print 'exiting...'
clientSocket.close()
  
