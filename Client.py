import socketserver
import sys
import struct
import threading
from Crypto.PublicKey import RSA
import rsa
from multiprocessing import Process
import socket

#https://docs.python.org/3.4/library/socketserver.html

clientList = []

class MyTCPHandler(socketserver.BaseRequestHandler):

    def send(self, stringmessage):#Helper function to send messages, not completed, no time
        bytemsg = bytes(stringmessage, "utf-8")
        self.request.sendall(struct.pack("I",len(stringmessage)))
        self.request.sendall(bytes(value,"utf-8"))

    def handle(self):
        #print("Socket Info: ",self.client_address)
        #clientList.append(self.client_address)
        #clientKeySize = self.request.recv(4)
        #clientKeySize = struct.unpack("I",clientKeySize)[0]
        #clientKey = self.request.recv(int(clientKeySize))
        #print("Client's Key: ",clientKey)
        
        self.data = ""
        while(self.data != "exit"):
            self.size = self.request.recv(4)
            if self.size:
                self.size = struct.unpack("I", self.size)[0]
                if(int(self.size) != 0):   
                    self.data = self.request.recv(int(self.size))#.strip()
                    self.data = str(self.data,"utf-8")
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

    dictionary = {}
    # Create the server, binding to localhost on port 9999
    
    print("Begin Client Interaction: \n", file = sys.stdout)
    
##############################################################################
######################CLIENT##################################################
##############################################################################    
    
    #Client callback function for threading
    def client():
           # Create a socket (SOCK_STREAM means a TCP socket)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.connect(('localhost',9999))#9999 is the main server
            # Upon connection, send key to server + info on client's Server
            sock.sendall(struct.pack("I",len(pubKeyInBytes)))
            sock.sendall(pubKeyInBytes)
            sock.sendall(struct.pack("I",len(str(HOST))))
            sock.sendall(bytes(str(HOST),"utf-8"))
            sock.sendall(struct.pack("I",len(str(PORT))))
            sock.sendall(bytes(str(PORT),"utf-8"))
            
            print("Connected.")
            dictionary = {}
            while True:
                try:
                    command = input()
                    if command:
                        #sock.sendall(bytes(command,"utf-8"))          
                        size = len(command)
                        size32bit = struct.pack("I",size)
                        sock.sendall(size32bit)#sendalling the size of the command
                        sock.sendall(bytes(command, "utf-8"))#command to sendall
                    
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
    

