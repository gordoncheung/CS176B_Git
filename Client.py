import socketserver
import sys
import struct
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import rsa
from multiprocessing import Process
import socket
import os
import json
import base64

#https://docs.python.org/3.4/library/socketserver.html

clientMap = {}

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
        
        self.data = ""
        while(self.data != "exit"):
            self.size = self.request.recv(4)
            if self.size:
                self.size = struct.unpack("I", self.size)[0]
                if(int(self.size) != 0):   
                    self.data = self.request.recv(int(self.size))#.strip()
                    self.data = str(self.data,"utf-8")
                    if(self.data == '00000000'):#00000000 is publicKey:(host,port) form
                        mapSize = self.request.recv(4)
                        mapSize = struct.unpack("I",mapSize)[0]
                        updatedMap = self.request.recv(int(mapSize))
                        updatedMap = str(updatedMap,'utf-8')
                        updatedMap = json.loads(updatedMap)
                        for key in updatedMap:
                            clientMap[key]=updatedMap[key]
                        #print("ClientMap: ",clientMap)
                    elif(self.data == '00000001'):#00000001 means decrypt this segment
                        dataSize = self.request.recv(4)
                        dataSize = struct.unpack("I", dataSize)[0]
                        encData = self.request.recv(int(dataSize))
                        encData = str(encData,'utf-8')
                        recAESKey = bytes(encData[0:35],'utf-8')
                        recAESKey = base64.b16decode(recAESKey)
                        recIV = bytes(encData[35:70],'utf-8')
                        recIV = base64.b16decode(recIV)
                        print('AES Stuff from Server: ',recAESKey,recIV)
                    print(self.data)                         

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass
                
if __name__ == "__main__":

    myKey = rsa.newkeys(1024) #Tuple of Private and Public Key
    pubKey = myKey[0]
    privKey = myKey[1]
    pubKeyInBytes = pubKey.save_pkcs1(format='PEM')#This key is ready to be sent
    
    print("Server Ready")
    HOST, PORT = "localhost",  0 #0 finds an arbitrary available port

    clientMap = {}
    # Create the server, binding to localhost on port 9999
    
    print("Begin Client Interaction: \n", file = sys.stdout)
    
##############################################################################
######################CLIENT##################################################
##############################################################################    
    
    #Client callback function for threading
    def client():
           # Create a socket (SOCK_STREAM means a TCP socket)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        def receive():
            size = sock.recv(4)
            size = struct.unpack("I",size)[0]
            data = sock.recv(int(size))
            data = str(data,"utf-8")
            return data
            
        def recvBytes():
            size = sock.recv(4)
            size = struct.unpack("I", size)[0]
            data = sock.recv(int(size))
            return data
            
        try:
            sock.connect(('localhost',9999))#9999 is the main server
            #All sends must now have a flag before them
            #Here are codes(using 1 byte flags currently)
            #0 - Sending Key + Address
            
            
            # Upon connection, send key to server + info on MAIN Server
            sock.sendall(struct.pack("I", 1))
            sock.sendall(bytes('0', 'utf-8'))#<-- Flag 0
            sock.sendall(struct.pack("I",len(pubKeyInBytes)))
            sock.sendall(pubKeyInBytes)
            sock.sendall(struct.pack("I",len(str(HOST))))
            sock.sendall(bytes(str(HOST),"utf-8"))
            sock.sendall(struct.pack("I",len(str(PORT))))
            sock.sendall(bytes(str(PORT),"utf-8"))
            
            #receive clientKey and add to map
            serverPubKey = recvBytes()
            #clientPubKey = rsa.load_pkcs1(clientPubKey)
            serverHost = receive()
            serverPort = receive()
                
            print("Connected.")
            dictionary = {}
            while True:
                #aes = AES.new(AESKey, AES.MODE_CFB, IV)
                try:
                    command = input()
                    #print('CL2: ', clientMap)
                    if command:
                        #Generate a packet with a path
                        
                        serverAESKey = os.urandom(16)
                        serverIV = os.urandom(16)
                        encryptedData=[command, str(serverPubKey,'utf-8'), '0']
                        for i in range(len(encryptedData)):
                            serverAES = AES.new(serverAESKey, AES.MODE_CFB, serverIV)
                            encryptedData[i] = serverAES.encrypt(encryptedData)
                        enc = base64.b16encode(serverAESKey)
                        encIV = base64.b16encode(serverIV)
                        encSKey = rsa.encrypt(str(enc,'utf-8'),pubKey.load_pkcs1(bytes(key,'utf-8')))
                        encsIV = rsa.encrypt(str(encIV,'utf-8'),pubKey.load_pkcs1(bytes(key,'utf-8')))
                        encryptedData.append(encSKey)
                        encrypedData.append(encsIV)
                        
                        firstDestination=str(serverPubKey,'utf-8')
                        
                        for key in clientMap:
                            AESKey = os.urandom(16)
                            IV = os.urandom(16)
                            for i in range(len(encryptedData)):
                                AES = AES.new(AESkey, AES.MODE_CFB, IV)
                                encryptedData[i] = AES.encrypt(encryptedData)
                            encodedKey = base64.b16encode(AESKey) #this is informat b'xxxx'
                            encryptedKey = rsa.encrypt(str(encodedKey,'utf-8'), pubKey.load_pkcs1(bytes(key,'utf-8')))#convert to bytes and decode before using
                            encodedIV = base64.b16encode(IV)
                            encryptedIV = rsa.encrypt(str(encodedIV,'utf-8'), pubKey.load_pkcs1(bytes(key,'utf-8')))
                            
                            encryptedData.append(key)
                            encryptedData.append('0')
                            encryptedData.append(encryptedKey)
                            encryptedData.append(encryptedIV)
                            
                            firstDestination = key
                        
                        
                                
                        
                        jsonData = json.dumps(encryptedData)
                        aSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        aSock.connect((serverHost,serverPort))
                        aSock.sendall(struct.pack("I",len(b'00000001')))
                        aSock.sendall(b'00000001')
                        aSock.sendall(struct.pack("I",len(bytes(jsonData,'utf-8'))))
                        aSock.sendall(bytes(jsonData,'utf-8'))
                        aSock.close()
                        
                       
                        
                        #command = rsa.encrypt(bytes(command,"utf-8"), pubKey.load_pkcs1(serverPubKey))
                        #command = aes.encrypt(command)
                        #sock.sendall(bytes(command,"utf-8"))          
                        #size = len(command)
                        #size32bit = struct.pack("I",size)
                        #sock.sendall(size32bit)#sendalling the size of the command
                        #sock.sendall(command)#command to sendall
                    
                except:
                    print("ERROR: Invalid packet from server. Terminating", file=sys.stderr)
                    sys.exit(0)
        except:
            #print("ERROR: Could not connect to server. Terminating.", file=sys.stderr)
            sys.exit(0)    
            
        finally:
            print("End Client")
    
    server = ThreadedTCPServer((HOST,PORT), MyTCPHandler)
    HOST, PORT = server.server_address
    c = threading.Thread(target = client)
    s = threading.Thread(target = server.serve_forever)
    s.start()
    c.start()
    

