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
        print("Socket Info: ",self.client_address)
    
        self.data = ""
        while(self.data != "exit"):
            self.size = self.request.recv(4)
            self.size = struct.unpack("I", self.size)[0]
            if(int(self.size) != 0):   
                self.data = self.request.recv(int(self.size))#.strip()
                self.data = str(self.data, 'utf-8')
                
                if(self.data == '0'): #This is flag for receiving client Key + Addr
                    #Receive Client's Information first.
                    clientKey = self.recvBytes()
                    clientServerHost = self.receive()
                    clientServerPort = self.receive()
                    clientMap[str(clientKey,'utf-8')] = (clientServerHost, int(clientServerPort))
                    
                    mapToSend = json.dumps(clientMap)
                    #Send the newly updated map to all clients
                    for client in clientMap:
                        if(client != (clientServerHost,clientServerPort)):
                            sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sockt.connect(clientMap[client])
                            #Broadcast the new client data to all previous clients
                            #Flag is b'00000000'
                            sockt.sendall(struct.pack("I",len(b'00000000')))
                            sockt.sendall(b'00000000')
                            #Data is in form of dictionary
                            print('mapToSend: ', mapToSend)
                            sockt.sendall(struct.pack("I",len(bytes(mapToSend,'utf-8'))))
                            sockt.sendall(bytes(mapToSend,'utf-8'))
                            sockt.close()
                    
                    #Sending Server's Key + HostPort to client
                    self.request.sendall(struct.pack("I",len(pubKeyInBytes)))
                    self.request.sendall(pubKeyInBytes)
                    self.request.sendall(struct.pack("I",len(str(HOST))))
                    self.request.sendall(bytes(str(HOST),"utf-8"))
                    self.request.sendall(struct.pack("I",len(str(PORT))))
                    self.request.sendall(bytes(str(PORT),"utf-8"))
        
                
                elif(self.data == '00000001'): #Flag to decrypt message
                    
                    size = self.request.recv(4)
                    size = struct.unpack("I", size)[0]
                    jsonString = self.request.recv(int(size))
                    jsonString = str(jsonString, 'utf-8')
                    jsonData = json.loads(jsonString)
                    print('received json: ',jsonString)

                 
                #print(str(data) + " received")
      
                #print(str(self.data,"utf-8") + " received from: " + str(self.client_address))

                #for client in clientMap:
                  
                #    sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #    sockt.connect(clientMap[client])
                #    sockt.sendall(struct.pack("I",len(self.data)))
                #    sockt.sendall(self.data)
                #    sockt.close()
                    #self.request.sendto(struct.pack("I",len(str(self.data))),client)
                    #self.request.sendto(bytes(str(self.data),"utf-8"),client)  
                #self.request.sendall(struct.pack("I",len(str(self.data))))
                #self.request.sendall(bytes(str(self.data),"utf-8"))                           

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass
                
if __name__ == "__main__":

    myKey = rsa.newkeys(1024) #Tuple of Private and Public Key
    pubKey = myKey[0]
    privKey = myKey[1]
    pubKeyInBytes = pubKey.save_pkcs1(format='PEM')#This key is ready to be sent

    print("Server Ready")
    #if len(sys.argv) != 2:
    #    print("ERROR: Invalid number of args. Terminating.")
    #    sys.exit(0)
    HOST, PORT = "localhost",  9999
    #if (PORT > 65535 or PORT < 1024):
    #    print("ERROR: Invalid port. Terminating.", file=sys.stderr)
    #    sys.exit(0)

    dictionary = {}
    # Create the server, binding to localhost on port 9999
    clientMap = {}
    
    try:
        server = ThreadedTCPServer((HOST,9999), MyTCPHandler)#9999 is main port for now
        HOST, PORT = server.server_address
        #server_thread = threading.Thread(target=server.server_forever)
        #server_thread.daemon = True
        #server_thread.start()
        #server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)
        server.allow_reuse_address=True
        server.serve_forever()
        
    except:
        print("ERROR: Could not bind port. Terminating", file=sys.stderr)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C

