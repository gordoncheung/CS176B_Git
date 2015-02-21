import socket
import sys
import struct
from Crypto.PublicKey import RSA
import rsa
#myKey = RSA.generate(1024)
#pubKey = myKey.publickey()
#print("myKey: ",myKey.exportKey())
#print("pubKey: ",pubKey.exportKey())
myKey = rsa.newkeys(1024) #Tuple of Private and Public Key
pubKey = myKey[0]
privKey = myKey[1]
pubKeyInBytes = pubKey.save_pkcs1(format='PEM')#This is ready to be sent

'''
The link to the code that I used for this is in the server_python_tcp.py file
This code mostly consists of sends and recv's. Just some logic added in
to determine what to do with certain commands
'''
if len(sys.argv) != 3:
    print("ERROR: Invalid number of args. Terminating.", file=sys.stderr)
    sys.exit(0)
HOST, PORT = sys.argv[1], int(sys.argv[2])

if (PORT > 65535 or PORT < 1024):
    print("ERROR: Invalid port. Terminating.", file=sys.stderr)
    sys.exit(0)

# Create a socket (SOCK_STREAM means a TCP socket)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to server and sendall data
    sock.connect((HOST, PORT))
    # Upon connection, send key to server
    sock.sendall(struct.pack("I",len(pubKeyInBytes)))
    sock.sendall(pubKeyInBytes)
    
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
            else:
                receivedValSize = sock.recv(4)#Receive back size of message returned from server
                if receivedValSize:
                    receivedValSizeUnpack=struct.unpack("I",receivedValSize)[0]#Unpack the size packet
                if int(receivedValSizeUnpack) >0:
                    receivedValue = str(sock.recv(int(receivedValSizeUnpack)),"utf-8")#Final Message received from server
                    print(receivedValue)
            
        except:
            print("ERROR: Invalid packet from server. Terminating", file=sys.stderr)
            sys.exit(0)
except:
    #print("ERROR: Could not connect to server. Terminating.", file=sys.stderr)
    sys.exit(0)    
    
finally:
    print("End Client")
    #sock.close()

