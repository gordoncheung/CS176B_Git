import socketserver
import sys
import struct
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import rsa
import socket
import json
import base64
#https://docs.python.org/3.4/library/socketserver.html


class MyTCPHandler(socketserver.BaseRequestHandler):

    postNumber = 0

    def __init__(self, request, client_address, server):
        super().__init__(request,client_address,server)
        
    def send(self, stringmessage):#Helper function to send messages, not completed, no time
        bytemsg = bytes(stringmessage, "utf-8")
        self.request.sendall(struct.pack("I",len(stringmessage)))
        self.request.sendall(bytes(value,"utf-8"))
        
    def receive(self):
        size = self.request.recv(4)
        size = struct.unpack("I",size)[0]
        data = self.request.recv(int(size))
        data = str(data,"utf-8")
        return data
        
    def recvBytes(self):
        size = self.request.recv(4)
        size = struct.unpack("I",size)[0]
        data = self.request.recv(int(size))
        return data

    def handle(self):
        #List of Flags:
        #'00000000': Receive the client key + Addr
        #'00000001': Decrypt whatever I have received       
        #'10000000': Exit Flag
        #'00000011': Print messages(send messageList to client)
        
        self.data = ""
        while(self.data != "exit"):
            self.size = self.request.recv(4)
            if self.size:
                self.size = struct.unpack("I", self.size)[0]
                if(int(self.size) != 0):   
                    self.data = self.request.recv(int(self.size))#.strip()
                    self.data = str(self.data, 'utf-8')
                    if(self.data == '00000000'): #This is flag for receiving client Key + Addr
                        #Receive Client's Information first.             
                        clientKey = self.recvBytes()
                        clientServerHost = self.receive()
                        clientServerPort = self.receive()
                        clientMap[str(clientKey,'utf-8')] = (clientServerHost, int(clientServerPort))
                        
                        print("New Connection from: ", clientServerHost, clientServerPort)
                        
                        #Sending Server's Key + HostPort to client 
                        self.request.sendall(struct.pack("I",len(pubKeyInBytes)))
                        self.request.sendall(pubKeyInBytes)
                        self.request.sendall(struct.pack("I",len(str(HOST))))
                        self.request.sendall(bytes(str(HOST),"utf-8"))
                        self.request.sendall(struct.pack("I",len(str(PORT))))
                        self.request.sendall(bytes(str(PORT),"utf-8"))
                     
                        #Create map of key:(host,port) and send to all clients
                        mapToSend = json.dumps(clientMap)
                        #Send the newly updated map to all clients
                        for client in clientMap:
                            if(client != (clientServerHost,clientServerPort)):
                                sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sockt.connect(clientMap[client])
                                #Broadcast the new client data to all previous clients
                                sockt.sendall(struct.pack("I",len(b'00000000')))
                                sockt.sendall(b'00000000')
                                sockt.sendall(struct.pack("I",len(bytes(mapToSend,'utf-8'))))
                                sockt.sendall(bytes(mapToSend,'utf-8'))
                                sockt.shutdown(socket.SHUT_RDWR)
                                sockt.close()                                                    
                    
                    elif(self.data == '00000001'): #Flag to decrypt message
                        #size = self.request.recv(4)
                        #size = struct.unpack("I", size)[0]
                        #jsonString = self.request.recv(int(size))
                        #jsonString = str(jsonString, 'utf-8')
                        #jsonData = json.loads(jsonString)
                        
                        
                        size = self.request.recv(4)
                        size = struct.unpack("I", size)[0]
                        #jsonString = self.request.recv(int(size))
                        #jsonString = str(jsonString, 'utf-8')
                        #jsonData = json.loads(jsonString)
                        numSegments = self.request.recv(int(size))
                        numSegments = int(str(numSegments,'utf-8'))
                        jsonString = ''
                        for i in range(numSegments):
                            size = self.request.recv(4)
                            size = struct.unpack("I",size)[0]
                            currString = self.request.recv(int(size))
                            currString = str(currString,'utf-8')
                            jsonString += currString
                        jsonData = json.loads(jsonString)
                        
                        
                        #print(jsonData)
                        mySymIV = jsonData.pop()
                        mySymKey = jsonData.pop()

                        #Next step is to decrypt the IV and Key using my privateKey
                        mySymIV = rsa.decrypt(base64.b16decode(bytes(mySymIV,'utf-8')),privKey)
                        mySymKey = rsa.decrypt(base64.b16decode(bytes(mySymKey,'utf-8')),privKey)
                        mySymIV = base64.b16decode(mySymIV)
                        mySymKey = base64.b16decode(mySymKey)

                        for i in range(len(jsonData)):
                            jsonData[i] = base64.b16decode(jsonData[i])
                            myAES = AES.new(mySymKey, AES.MODE_CFB, mySymIV)
                            jsonData[i] = myAES.decrypt(jsonData[i])
                                                  
                        print("Received from client: ", str(jsonData[0],'utf-8'))
                        MyTCPHandler.postNumber += 1
                        votableMessage = [str(jsonData[0],'utf-8'), MyTCPHandler.postNumber, 0]
                        messageList.append(votableMessage)
                        
                        #Broadcast the message to all clients
                        for client in clientMap:
                            sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sockt.connect(clientMap[client])
                            sockt.sendall(struct.pack("I",len(b'00000005')))#Flag 00000005 to notify client to print msg
                            sockt.sendall(b'00000005')
                            sockt.sendall(struct.pack("I",len(jsonData[0])))
                            sockt.sendall(jsonData[0])
                            sockt.shutdown(socket.SHUT_RDWR)
                            sockt.close()
                    
                    elif(self.data == '00000011'):
                        clientKey = self.recvBytes()
                        listToSend = json.dumps(messageList)
                        sockt=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        clientHost, clientPort = clientMap[(str(clientKey,'utf-8'))]
                        sockt.connect((clientHost,int(clientPort)))
                        sockt.sendall(struct.pack("I",len(b'00000011')))
                        sockt.sendall(b'00000011')  
                        sockt.sendall(struct.pack("I",len(bytes(listToSend,'utf-8'))))
                        sockt.sendall(bytes(listToSend,'utf-8'))
                        sockt.shutdown(socket.SHUT_RDWR)
                        sockt.close()
                        
                    elif(self.data == '10000000'):
                        clientKey = self.recvBytes()
                        #If client disconnects, then need to remove from clientMap, and resend map to all other clients
                        clientServerHost, clientServerPort = clientMap.pop(str(clientKey,'utf-8'))
                        mapToSend = json.dumps(clientMap)
                        for client in clientMap:
                            if(client != (clientServerHost,clientServerPort)):
                                sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sockt.connect(clientMap[client])
                                sockt.sendall(struct.pack("I",len(b'00000000')))
                                sockt.sendall(b'00000000')
                                sockt.sendall(struct.pack("I",len(bytes(mapToSend,'utf-8'))))
                                sockt.sendall(bytes(mapToSend,'utf-8'))
                                sockt.shutdown(socket.SHUT_RDWR)
                                sockt.close()
                        break                      

    def finish(self):
        return

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass
                
if __name__ == "__main__":
    
    myKey = rsa.newkeys(1024) #Tuple of Private and Public Key
    pubKey = myKey[0]
    privKey = myKey[1]
    pubKeyInBytes = pubKey.save_pkcs1(format='PEM')#This key is ready to be sent
    keyToRemove = []
    print("Server Ready")
    if len(sys.argv) != 3:
        print("ERROR: Invalid number of args. Terminating.")
        sys.exit(0)
    hostname = socket.gethostname()
    HOST, PORT = sys.argv[1],  int(sys.argv[2])
    if (PORT > 65535 or PORT < 1024):
        print("ERROR: Invalid port. Terminating.", file=sys.stderr)
        sys.exit(0)

    dictionary = {}
    clientMap = {}
    messageList = []
    postNumber = 0
    
    try:
        print("Hosting on: ", HOST, PORT)
        server = ThreadedTCPServer((HOST,PORT), MyTCPHandler)#9999 is main port for now
        HOST, PORT = server.server_address
        #server.server_activate()
        #server.server_bind()
        server.allow_reuse_address=True
        server.serve_forever()
        
    except:
        print("ERROR: Could not bind port. Terminating", file=sys.stderr)
