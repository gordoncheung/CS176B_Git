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
        #Flag List:
        #'00000000': Receiving map of all {keys:(host,port)}
        #'00000001': Decrypt this segment
        
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
            #'00000000': Sending Key + Address
            
            
            # Upon connection, send key to server + info on MAIN Server
            sock.sendall(struct.pack("I",len(b'00000000')))
            sock.sendall(b'00000000')#<-- Flag 0
            sock.sendall(struct.pack("I",len(pubKeyInBytes)))
            sock.sendall(pubKeyInBytes)
            sock.sendall(struct.pack("I",len(str(HOST))))
            sock.sendall(bytes(str(HOST),"utf-8"))
            sock.sendall(struct.pack("I",len(str(PORT))))
            sock.sendall(bytes(str(PORT),"utf-8"))
            
            #receive clientKey and add to map.
            #Does NOT receive a Flag back from the server. Expects this data upon connection
            serverPubKey = recvBytes()
            serverHost = receive()
            serverPort = receive()
            print("serverPubKey: ", serverPubKey)
            print("Connected to: ", serverHost, serverPort)
            dictionary = {}
            while True:
                #aes = AES.new(AESKey, AES.MODE_CFB, IV)
                try:
                    command = input()
                    #print('CL2: ', clientMap)
                    #MAP is in SavedKeyBytes:["IP",NUM]
                    if command != "/show":
                        #Generate a packet with a path
                    
                        
                        serverAESKey = os.urandom(16)
                        serverIV = os.urandom(16)
                        encryptedData=[command, str(serverPubKey,'utf-8'), '0']
                        #Encrypt each index of the list. 
                        #The list acts as the packet that we are sending
                        #It will be sent via JSON.
                        for i in range(len(encryptedData)):
                            #All of this needs to be undone by the receiver...
                            serverAES = AES.new(serverAESKey, AES.MODE_CFB, serverIV)
                            newData = serverAES.encrypt(encryptedData[i])
                            newData = base64.b16encode(newData)
                            encryptedData[i] = str(newData,'utf-8')
                        enc = base64.b16encode(serverAESKey)
                        encIV = base64.b16encode(serverIV)
                        #rsa.encrypt takes a Bytes object, and a LoadedKey.
                        #Whoever receives this needs to undo.
                        #Sequence is b16Encode, rsaEncrypt, b16Encode, Str.
                        #Do reverse.
                        encSKey = rsa.encrypt(enc,pubKey.load_pkcs1(serverPubKey))
                        encsIV = rsa.encrypt(encIV,pubKey.load_pkcs1(serverPubKey))
                        enc16Key = base64.b16encode(encSKey)
                        enc16IV = base64.b16encode(encsIV)
                        encryptedData.append(str(enc16Key,'utf-8'))
                        encryptedData.append(str(enc16IV,'utf-8'))
                        print("EncryptedData: ",encryptedData, len(encryptedData))
                        firstDestination=str(serverPubKey,'utf-8')
                        print("Packet Constructed")
                        #for key in clientMap:
                        #    AESKey = os.urandom(16)
                        #    IV = os.urandom(16)
                        #    for i in range(len(encryptedData)):
                        #        AES = AES.new(AESkey, AES.MODE_CFB, IV)
                        #        encryptedData[i] = AES.encrypt(encryptedData[i])
                        #    encodedKey = base64.b16encode(AESKey) #this is informat b'xxxx'
                        #    encryptedKey = rsa.encrypt(encodedKey, pubKey.load_pkcs1(bytes(key,'utf-8')))#convert to bytes and decode before using
                        #    encodedIV = base64.b16encode(IV)
                        #    encryptedIV = rsa.encrypt(encodedIV, pubKey.load_pkcs1(bytes(key,'utf-8')))
                        #    
                        #    encryptedData.append(key)
                        #    encryptedData.append('0')
                        #    encryptedData.append(encryptedKey)
                        #    encryptedData.append(encryptedIV)
                            
                        #    firstDestination = key
                        
                        
                                
                        #Send packet to server
                        print(str(serverHost), int(serverPort))
                        jsonData = json.dumps(encryptedData)
                        print("nomake")
                        aSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        
                        aSock.connect((str(serverHost),int(serverPort)))
                        aSock.sendall(struct.pack("I",len(b'00000001')))
                        #Send the flag 00000001
                        #This flag indicates that the receiver needs to decrypt the message
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
                    print("ERROR: Something unexpected happened while sending packet", file=sys.stderr)
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
    

