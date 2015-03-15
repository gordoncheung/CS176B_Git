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
        #'00000011': Receive messageList from server and print
        
        self.data = ""
        while(True):
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
                        clientMap.clear()
                        for key in updatedMap:
                            clientMap[key]=updatedMap[key]
                        #print("ClientMap: ",clientMap)
                    elif(self.data == '00000001'):#00000001 means decrypt this segment
                        #print("00000001 Flag. Server Decrypt")
                        size = self.request.recv(4)
                        size = struct.unpack("I", size)[0]
                        jsonString = self.request.recv(int(size))
                        jsonString = str(jsonString, 'utf-8')
                        jsonData = json.loads(jsonString)
                        #print(jsonData)
                        #print('received json: ',jsonString)
                        #The last TWO elements are guaranteed to be the SYMMETRIC Key
                        #Pop these two off and handle separately
                        mySymIV = jsonData.pop()
                        mySymKey = jsonData.pop()

                        #Next step is to decrypt the IV and Key using my privateKey
                        mySymIV = rsa.decrypt(base64.b16decode(bytes(mySymIV,'utf-8')),privKey)
                        mySymKey = rsa.decrypt(base64.b16decode(bytes(mySymKey,'utf-8')),privKey)
                        mySymIV = base64.b16decode(mySymIV)
                        mySymKey = base64.b16decode(mySymKey)
                        #print("SymIV & Key: ", mySymIV, mySymKey)                        
                        #In a loop, decode everything back to utf-8
                        #Now, decrypt everything using the Symmetric Key
                        for i in range(len(jsonData)):
                            jsonData[i] = base64.b16decode(jsonData[i])
                            myAES = AES.new(mySymKey, AES.MODE_CFB, mySymIV)
                            jsonData[i] = myAES.decrypt(jsonData[i])
                            jsonData[i] = str(jsonData[i],'utf-8')
                        
                        
                        
                        #Handle Destination
                        flag = jsonData.pop()
                        destKey = jsonData.pop()
                        jsonData = json.dumps(jsonData)
                        tmpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        if destKey == str(serverData[0],'utf-8'):
                            tmpSock.connect((serverData[1],int(serverData[2])))
                        else:
                            tmpSock.connect((clientMap[destKey][0],int(clientMap[destKey][1])))
                        tmpSock.sendall(struct.pack("I",len(b'00000001')))
                        #Send the flag 00000001
                        #This flag indicates that the receiver needs to decrypt the message
                        tmpSock.sendall(b'00000001')
                        tmpSock.sendall(struct.pack("I",len(bytes(jsonData,'utf-8'))))
                        tmpSock.sendall(bytes(jsonData,'utf-8'))
                        tmpSock.shutdown(SHUT_RDWR)
                        tmpSock.close()
                    
                    elif(self.data == '00000011'):
                        listSize = self.request.recv(4)
                        listSize = struct.unpack("I",listSize)[0]
                        msgList = self.request.recv(int(listSize))
                        msgList = str(msgList,'utf-8')
                        msgList = json.loads(msgList)
                        print("#     Votes  Message\n")
                        for item in msgList:
                            print(str(item[1]) + "     " + str(item[2]) + "   |  " + str(item[0]))
                        
                    elif(self.data == '00000005'):#Receiving msg and printing
                        msgSize = self.request.recv(4)
                        msgSize = struct.unpack("I",msgSize)[0]
                        msgF = self.request.recv(int(msgSize))
                        msgF = str(msgF,'utf-8')
                        print("Received message from server: ", msgF)
                        
                    #print(self.data)                         

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
    serverData = []
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
            serverData.append(serverPubKey)
            serverData.append(serverHost)
            serverData.append(serverPort)
            #print("serverPubKey: ", serverPubKey)
            print("Connected to: ", serverHost, serverPort)
            dictionary = {}
            while True:
                #aes = AES.new(AESKey, AES.MODE_CFB, IV)
                try:
                    command = input()
                    if(len(command) > 350):
                        print("350 is the character limit. Please adjust your message. Or send multiple messages")
                        continue
                    #print('Client Map!!: ', clientMap)
                    #MAP is in SavedKeyBytes:["IP",NUM]
                    if command == "$exit":
                        sock.sendall(struct.pack("I",len(b'10000000')))
                        #Send the flag 10000000 for exit
                        sock.sendall(b'10000000')
                        sock.sendall(struct.pack("I",len(pubKeyInBytes)))
                        sock.sendall(pubKeyInBytes)
                        print("Ending Client.")
                        sock.shutdown(SHUT_RDWR)
                        sock.close()
                        sys.exit(0)
                    
                    elif command == "$users":#command to print number of users
                        print("Number of users connected: ", len(clientMap))
                        
                    elif command == "$print":#Print all messages stored on server
                        sock.sendall(struct.pack("I",len(b'00000011')))
                        sock.sendall(b'00000011')
                        sock.sendall(struct.pack("I",len(pubKeyInBytes)))
                        sock.sendall(pubKeyInBytes)
                        
                    elif command != "$show":
                        #Generate a packet with a path
                    
                        #Packet looks like: [data, dst,flag,aesKey,aesIv,dst2,flag2,aeskey2,...]
                        serverAESKey = os.urandom(16)
                        serverIV = os.urandom(16)
                        encryptedData=[command, ' ', '0']
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
                        #print("SymIV & Key: ", encIV, enc)
                        #rsa.encrypt takes a Bytes object, and a LoadedKey.
                        #Whoever receives this needs to undo.
                        encSKey = rsa.encrypt(enc,pubKey.load_pkcs1(serverPubKey))
                        encsIV = rsa.encrypt(encIV,pubKey.load_pkcs1(serverPubKey))
                        enc16Key = base64.b16encode(encSKey)
                        enc16IV = base64.b16encode(encsIV)
                        encryptedData.append(str(enc16Key,'utf-8'))
                        encryptedData.append(str(enc16IV,'utf-8'))
                        
                        #print("EncryptedData: ",encryptedData, len(encryptedData))
                        firstDestination=str(serverPubKey,'utf-8')
                        #print("Packet Constructed")
                        previousKey = str(serverPubKey,'utf-8')
                        
                        #Now encrypting by each path
                        for key in clientMap:
                            #print("Compare: ",key, pubKeyInBytes)
                            if bytes(key,'utf-8') == pubKeyInBytes:
                                #print("Keys are the same, skip")
                                continue
                            else:
                                AESKey = os.urandom(16)
                                IV = os.urandom(16)
                                encryptedData.append(previousKey)#Destination
                                encryptedData.append('0')
                                for i in range(len(encryptedData)):
                                    aes = AES.new(AESKey, AES.MODE_CFB, IV)
                                    newData = aes.encrypt(encryptedData[i])
                                    newData = base64.b16encode(newData)
                                    encryptedData[i] = str(newData,'utf-8')
                                encodedKey = base64.b16encode(AESKey) #this is informat b'xxxx'
                                encodedIV = base64.b16encode(IV)
                                #print("16Key & IV: ", encodedKey, encodedIV)
                                encryptedKey = rsa.encrypt(encodedKey, pubKey.load_pkcs1(bytes(key,'utf-8')))#convert to bytes and decode before using
                                encryptedIV = rsa.encrypt(encodedIV, pubKey.load_pkcs1(bytes(key,'utf-8')))
                                encrypted16Key = base64.b16encode(encryptedKey)
                                encrypted16IV = base64.b16encode(encryptedIV)
                                

                                encryptedData.append(str(encrypted16Key,'utf-8'))
                                encryptedData.append(str(encrypted16IV,'utf-8'))
                                
                                previousKey = key
                                
                                firstDestination = key
                    
                        
                                
                        #Send packet to server
                        #print(str(serverHost), serverPort)
                        jsonData = json.dumps(encryptedData)
                        #print("Connecting to: ", clientMap[firstDestination])
                        aSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
                        if(firstDestination) == str(serverPubKey,'utf-8'):
                            aSock.connect((serverHost,int(serverPort)))
                        else:
                            aSock.connect((clientMap[firstDestination][0],int(clientMap[firstDestination][1])))
                        aSock.sendall(struct.pack("I",len(b'00000001')))
                        #Send the flag 00000001
                        #This flag indicates that the receiver needs to decrypt the message
                        aSock.sendall(b'00000001')
                        aSock.sendall(struct.pack("I",len(bytes(jsonData,'utf-8'))))
                        aSock.sendall(bytes(jsonData,'utf-8'))
                        aSock.shutdown(SHUT_RDWR)
                        aSock.close()
                        
                       
                        
                        #command = rsa.encrypt(bytes(command,"utf-8"), pubKey.load_pkcs1(serverPubKey))
                        #command = aes.encrypt(command)
                        #sock.sendall(bytes(command,"utf-8"))          
                        #size = len(command)
                        #size32bit = struct.pack("I",size)
                        #sock.sendall(size32bit)#sendalling the size of the command
                        #sock.sendall(command)#command to sendall
                    
                except:
                    sock.close()
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
    
