import socketserver
import sys
import struct
import threading
from Crypto.PublicKey import RSA
import rsa
import socket
#https://docs.python.org/3.4/library/socketserver.html

class MyTCPHandler(socketserver.BaseRequestHandler):

    def send(self, stringmessage):#Helper function to send messages, not completed, no time
        bytemsg = bytes(stringmessage, "utf-8")
        self.request.sendall(struct.pack("I",len(stringmessage)))
        self.request.sendall(bytes(value,"utf-8"))

    def handle(self):
        print("Socket Info: ",self.client_address)
        #clientList.append(self.client_address)
        contKey=0
        clientKeySize = self.request.recv(4)
        clientKeySize = struct.unpack("I",clientKeySize)[0]
        clientKey = self.request.recv(int(clientKeySize))
        clientServerHostSize = self.request.recv(4)
        clientServerHostSize = struct.unpack("I",clientServerHostSize)[0]
        clientServerHost = self.request.recv(int(clientServerHostSize))
        clientServerPortSize = self.request.recv(4)
        clientServerPortSize = struct.unpack("I",clientServerPortSize)[0]
        clientServerPort = self.request.recv(int(clientServerPortSize))
        clientList.append((clientServerHost,int(clientServerPort)))
        
        print("Client's Key: ",clientKey)
        self.data = ""
        while(self.data != "exit"):
            self.size = self.request.recv(4)
            self.size = struct.unpack("I", self.size)[0]
            if(int(self.size) != 0):   
                self.data = self.request.recv(int(self.size))#.strip()
                #self.data = str(self.data,"utf-8")
                print(self.data)
                #Just want to send back SizeofMessage + Message
                #returnData = bytes(self.data,"utf-8")
                print(clientList)
                for client in clientList:
                    sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sockt.connect(client)
                    sockt.sendall(struct.pack("I",len(self.data)))
                    sockt.sendall(self.data)
                    sockt.close()
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
    HOST, PORT = "localhost",  int(sys.argv[1])
    #if (PORT > 65535 or PORT < 1024):
    #    print("ERROR: Invalid port. Terminating.", file=sys.stderr)
    #    sys.exit(0)

    dictionary = {}
    # Create the server, binding to localhost on port 9999
    clientList =[]
    
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

