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
import random
#import fcntl

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

                    elif(self.data == '00000001'):#00000001 means decrypt this segment
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
                        

                        mySymIV = jsonData.pop()
                        mySymKey = jsonData.pop()

                        #Next step is to decrypt the IV and Key using my privateKey
                        mySymIV = rsa.decrypt(base64.b16decode(bytes(mySymIV,'utf-8')),privKey)
                        mySymKey = rsa.decrypt(base64.b16decode(bytes(mySymKey,'utf-8')),privKey)
                        mySymIV = base64.b16decode(mySymIV)
                        mySymKey = base64.b16decode(mySymKey)
                        
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

                        #Send the flag 00000001
                        #This flag indicates that the receiver needs to decrypt the message
                        tmpSock.sendall(struct.pack("I",len(b'00000001')))
                        tmpSock.sendall(b'00000001')
                        #tmpSock.sendall(struct.pack("I",len(bytes(jsonData,'utf-8'))))
                        #tmpSock.sendall(bytes(jsonData,'utf-8'))
                        
                        segments = []
                        currString = ''
                        for i in range(len(jsonData)):
                            currString += jsonData[i]
                            if((i % 4000 == 0) and i>0):
                                segments.append(currString)
                                currString = ''
                        segments.append(currString)
                        #print('jsonData ',jsonData)
                        #print('segments: ',segments)
                        numSegments = len(segments)
                        tmpSock.sendall(struct.pack("I",1))
                        tmpSock.sendall(bytes(str(numSegments),'utf-8'))
                        for seg in segments:
                            tmpSock.sendall(struct.pack("I",len(seg)))
                            tmpSock.sendall(bytes(seg,'utf-8'))
                        
                        tmpSock.shutdown(socket.SHUT_RDWR)
                        tmpSock.close()
                    
                    elif(self.data == '00000011'):
                        listSize = self.request.recv(4)
                        listSize = struct.unpack("I",listSize)[0]
                        msgList = self.request.recv(int(listSize))
                        msgList = str(msgList,'utf-8')
                        msgList = json.loads(msgList)
                        print("#   Message\n")
                        for item in msgList:
                            print(str(item[1]) + " | " + str(item[0]))
                        
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

    #def get_ip_address(ifname):
    #    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #    return socket.inet_ntoa(fcntl.ioctl(
    #        s.fileno(),
    #        0x8915,  # SIOCGIFADDR
    #        struct.pack('256s', ifname[:15])
    #    )[20:24])

    #get_ip_address('eth0')
    hostname = socket.gethostname()

    myKey = rsa.newkeys(1024) #Tuple of Private and Public Key
    pubKey = myKey[0]
    privKey = myKey[1]
    pubKeyInBytes = pubKey.save_pkcs1(format='PEM')#This key is ready to be sent
    
    print("Server Ready")
    HOST, PORT = socket.gethostbyname(hostname),  0 #0 finds an arbitrary available port
    clientMap = {}
    # Create the server, binding to localhost on port 9999
    if len(sys.argv) != 3:
        print("ERROR: Invalid number of args. Terminating.")
        sys.exit(0)
    serverHOST, serverPORT = sys.argv[1], int(sys.argv[2])
    
    if (serverPORT > 65535 or serverPORT < 1024):
        print("ERROR: Invalid port. Terminating.", file=sys.stderr)
        sys.exit(0)
    if serverHOST == HOST:
        HOST = 'localhost'
        
    print("Begin Client Interaction: \n", file = sys.stdout)
    serverData = []
    
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
            sock.connect((serverHOST,serverPORT))
            
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
            serverPubKey = recvBytes()
            serverHost = receive()
            serverPort = receive()
            serverData.append(serverPubKey)
            serverData.append(serverHost)
            serverData.append(serverPort)
            print("Connected to: ", serverHost, serverPort)
            dictionary = {}
            
            while True:
            
                try:
                    command = input()
                    if(len(command) > 350):
                        print("350 is the character limit. Please adjust your message. Or send multiple messages")
                        continue
                       
                    if command == "$exit":
                        sock.sendall(struct.pack("I",len(b'10000000')))
                        #Send the flag 10000000 for exit
                        sock.sendall(b'10000000')
                        sock.sendall(struct.pack("I",len(pubKeyInBytes)))
                        sock.sendall(pubKeyInBytes)
                        print("Ending Client.")
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                        break
                    
                    elif command == "$users":#command to print number of users
                        print("Number of users connected: ", len(clientMap))
                        
                    elif command == "$print":#Print all messages stored on server
                        sock.sendall(struct.pack("I",len(b'00000011')))
                        sock.sendall(b'00000011')
                        sock.sendall(struct.pack("I",len(pubKeyInBytes)))
                        sock.sendall(pubKeyInBytes)
                        
                    elif command != "":
                        #Generate a packet with a path
                    
                        serverAESKey = os.urandom(16)
                        serverIV = os.urandom(16)
                        encryptedData=[command, ' ', '0']
                        
                        for i in range(len(encryptedData)):
                            #All of this needs to be undone by the receiver...
                            serverAES = AES.new(serverAESKey, AES.MODE_CFB, serverIV)
                            newData = serverAES.encrypt(encryptedData[i])
                            newData = base64.b16encode(newData)
                            encryptedData[i] = str(newData,'utf-8')
                            
                        enc = base64.b16encode(serverAESKey)
                        encIV = base64.b16encode(serverIV)
                        encSKey = rsa.encrypt(enc,pubKey.load_pkcs1(serverPubKey))
                        encsIV = rsa.encrypt(encIV,pubKey.load_pkcs1(serverPubKey))
                        enc16Key = base64.b16encode(encSKey)
                        enc16IV = base64.b16encode(encsIV)
                        encryptedData.append(str(enc16Key,'utf-8'))
                        encryptedData.append(str(enc16IV,'utf-8'))
                        
                        firstDestination=str(serverPubKey,'utf-8')
                        
                        previousKey = str(serverPubKey,'utf-8')
                        
                        #Now encrypting by each path
                        counter = 0
                        
                        allKeys = list(clientMap.keys())
                        random.shuffle(allKeys)
                        for key in allKeys:

                            if bytes(key,'utf-8') == pubKeyInBytes:
                                continue
                                
                            elif counter == 5:
                                break
                                
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
                                encodedKey = base64.b16encode(AESKey)
                                encodedIV = base64.b16encode(IV)
                                encryptedKey = rsa.encrypt(encodedKey, pubKey.load_pkcs1(bytes(key,'utf-8')))
                                encryptedIV = rsa.encrypt(encodedIV, pubKey.load_pkcs1(bytes(key,'utf-8')))
                                encrypted16Key = base64.b16encode(encryptedKey)
                                encrypted16IV = base64.b16encode(encryptedIV)                                

                                encryptedData.append(str(encrypted16Key,'utf-8'))
                                encryptedData.append(str(encrypted16IV,'utf-8'))
                                
                                previousKey = key
                                
                                firstDestination = key
                                
                                counter += 1
                                                                            
                        #Send packet to server
                        jsonData = json.dumps(encryptedData)
                        aSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
                        if(firstDestination) == str(serverPubKey,'utf-8'):
                            aSock.connect((serverHost,int(serverPort)))
                        else:
                            aSock.connect((clientMap[firstDestination][0],int(clientMap[firstDestination][1])))

                        #Send the flag 00000001
                        #This flag indicates that the receiver needs to decrypt the message
                        aSock.sendall(struct.pack("I",len(b'00000001')))
                        aSock.sendall(b'00000001')
                        #aSock.sendall(struct.pack("I",len(bytes(jsonData,'utf-8'))))
                        #aSock.sendall(bytes(jsonData,'utf-8'))
                        #print(jsonData)
                        segments = []
                        currString = ''
                        for i in range(len(jsonData)):
                            currString += jsonData[i]
                            if((i % 4000 == 0) and i>0):
                                segments.append(currString)
                                currString = ''
                        segments.append(currString)
                        #print('jsonData ',jsonData)
                        #print('segments: ',segments)
                        numSegments = len(segments)
                        aSock.sendall(struct.pack("I",1))
                        aSock.sendall(bytes(str(numSegments),'utf-8'))
                        for seg in segments:
                            aSock.sendall(struct.pack("I",len(seg)))
                            aSock.sendall(bytes(seg,'utf-8'))
                        aSock.shutdown(socket.SHUT_RDWR)
                        aSock.close()
                        
                except:
                    sock.close()
                    print("ERROR: Something unexpected happened while sending packet", file=sys.stderr)
                    sys.exit(0)
        except:
            print("ERROR: Could not connect to server. Terminating.", file=sys.stderr)
            sys.exit(0)    
            
        finally:
            sock.close()
            print("End Client")
    
    server = ThreadedTCPServer((HOST,PORT), MyTCPHandler)
    HOST, PORT = server.server_address
    c = threading.Thread(target = client)
    s = threading.Thread(target = server.serve_forever)
    s.start()
    c.start()
    
