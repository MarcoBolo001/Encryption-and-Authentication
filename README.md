# From Key Exchange to Message Authentication: Building Secure Communication Channels  

The entire experiment is presented in a simple jupiter notebook file: main.ipynb  
The only libreries needed are hashlib for the sha-256 method and secrets to generate random numbers  
  
ciphers.py contains all the ciphers used along with the deciphers  
diffie_hellman.py contains all the methods to implement the Diffie-Hellman protocol  
hmac_.py contains the methods to implement xor-hmac and sha256_hmac, and methods to verify weaknesses of xor_hmac  
ratchet.py contains the class Partecipant with his methods send_message and receive_message, and methods to simulate a chat between two Partecipants, using Single or Double Ratchet  