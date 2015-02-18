from socket import *
import sys

serverPort = int(sys.argv[1])

#check for valid ports                                                        
if (serverPort > 65535) or (serverPort < 0):
  print 'ERROR: Invalid port. Terminating.'
  exit()

#set up socket information                                                    
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('', serverPort))
print "The server is ready to receive"

clients = []
sentences = []

while 1:
  sentence, clientAddress = serverSocket.recvfrom(4096)
  #sentences.append(sentence)                                                 
  #print('sentence: ', sentence, ' address: ', clientAddress)
  if clientAddress not in clients:
    clients.append(clientAddress)
  modSentence = 'Your string is ' + sentence
  #sentences.append(modSentence)

  for i in range(0, len(clients)):
    #print('from list ',  clients[i])                                         
    #print('client address variable = ', clientAddress)                       
    serverSocket.sendto(modSentence, clients[i])
    #print('Message sent to address pair ', clients[i])                       
  #serverSocket.sendto(modSentence, clientAddress)                            

serverSocket.close()
