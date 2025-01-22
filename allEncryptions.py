# Write your script here

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, cmac
from cryptography.hazmat.primitives import padding as padding1
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as padding2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecdsa import SigningKey, NIST384p
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES


# plaintext = b"suraj is very very clever boy..."
# key = os.urandom(16)
# nonce = os.urandom(16)
# cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
# encryptor = cipher.encryptor()
# padder = padding.PKCS7(128).padder()
# padded_data = padder.update(plaintext)
# padded_data += padder.finalize()
# ciphertext = encryptor.update(padded_data) + encryptor.finalize()
# print(ciphertext)

# decryptor = cipher.decryptor()
# msg = decryptor.update(ciphertext) + decryptor.finalize()
# unpadder = padding.PKCS7(128).unpadder()
# msg = unpadder.update(msg)
# print(msg)

# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives.asymmetric import padding as padding2
# private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
# public_key = private_key.public_key()
# message = b"This is the message we want to encrypt..."
# ciphertext = public_key.encrypt(message, padding2.PKCS1v15())
# plaintext = private_key.decrypt(ciphertext, padding2.PKCS1v15())

# signature = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
# print("signature getting printed : ")
# print(signature)


# ans = public_key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
# if(ans == None):
#     print("success..")
# else:
#     print("unsuccess...")


# key = os.urandom(16)
# c = cmac.CMAC(algorithms.AES(key))
# c.update(b"new message...")
# signature = c.finalize()
# print(signature)

# c = cmac.CMAC(algorithms.AES(key))
# c.update(b"new message...")
# c_copy = c.copy()
# ans = c.verify(signature)
# print(ans)
# c_copy.verify(b"different message...")

# key = os.urandom(16)
# h = hmac.HMAC(key, hashes.SHA256())
# h.update(b"suraj is very clever boy...")
# signature = h.finalize()
# print(signature)

# h = hmac.HMAC(key, hashes.SHA256())
# h.update(b"suraj is very clever boy...")
# h_copy = h.copy() # get a copy of `h' to be reused
# h.verify(signature)
# print("signature verified...")
# # h_copy.verify(b"an incorrect signature")


# private_key = ec.generate_private_key(ec.SECP384R1())
# data = b"this is some data I'd like to sign"
# signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))


# sk = SigningKey.generate(curve=NIST384p)
# vk = sk.verifying_key
# signature = sk.sign(b"message")
# ans = vk.verify(signature, b"newmessage")
# print(ans)



# data = b"a secret message from very ugly person..."
# aad = b"authenticated but unencrypted data"
# key = AESGCM.generate_key(bit_length=128)
# aesgcm = AESGCM(key)
# print(aesgcm)
# nonce = os.urandom(12)
# ct = aesgcm.encrypt(nonce, data, aad)
# print(ct)
# dcr = aesgcm.decrypt(nonce, ct, aad)
# print(dcr)




# from Crypto.PublicKey import RSA
# from Crypto import Random
# import binascii
# from base64 import b64encode
# from base64 import b64decode


    
# key= b"aLc9vPtusfQPeoy7"
# nonce = os.urandom(16)

# plaintext = b"Charizard was designed by Atsuko Nishida for the first generation of Pocket Monsters games Red and Green, which were localized outside Japan as Pokemon Red and Blue. Charizard was designed before Charmander, the latter being actually based on the former. Originally called lizardon in Japanese, Nintendo decided to give the various Pokemon species clever and descriptive names related to their appearance or features when translating the game for western audiences as a means to make the characters more relatable to American children. As a result, they were renamed Charizard, a portmanteau of the words charcoal or char and lizard."
# cipher = AES.new(key, AES.MODE_GCM,nonce=nonce)
# # cipher.update(header)
# ct_bytes , tag = cipher.encrypt_and_digest(plaintext)

# cipher = AES.new(key, AES.MODE_GCM,nonce=nonce)
# # cipher.update(header)
# pt = cipher.decrypt_and_verify(ct_bytes,tag)
# print("The message was: ", pt)




# from base64 import b64encode, b64decode
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad

# key = os.urandom(16)
# cipher = AES.new(key, AES.MODE_CBC)
# ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
# # iv = b64encode(cipher.iv).decode('utf-8')
# # ct = b64encode(ct_bytes).decode('utf-8')

# print(ct_bytes)



# try:
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     pt = unpad(cipher.decrypt(ct), AES.block_size)
#     print("The message was: ", pt)
# except (ValueError, KeyError):
#     print("Incorrect decryption")


# from Crypto.Signature import pkcs1_15
# from Crypto.Hash import SHA3_256
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
# private_key = RSA.generate(2048)
# public_key = private_key.public_key()
# message = b'To be signed'
# h = SHA3_256.new(message)
# signature = pkcs1_15.new(private_key).sign(h)
# print("....")
# print(signature)
# h = SHA3_256.new(b"abcd")
# pkcs1_15.new(public_key).verify(h, signature)
# print("The signature is valid.")

# cipher = PKCS1_OAEP.new(public_key)
# ciphertext = cipher.encrypt(message)
# print(ciphertext)

# cipher = PKCS1_OAEP.new(private_key)
# plaintext = cipher.decrypt(ciphertext)
# print(plaintext)

# key = os.urandom(16)
# from Crypto.Hash import HMAC, SHA3_256
# h = HMAC.new(key, digestmod=SHA3_256)
# message = b"suraj is good boy..."
# res = h.update(message).hexdigest()
# h = HMAC.new(key, digestmod=SHA3_256)
# h.update(message)
# print("good..")
# try:
#     h.hexverify(res)
#     print("message is good...")
# except ValueError:
#     print("The message or the key is wrong")








class ExecuteCrypto(object): # Do not change this
    def generate_keys(self):
        """Generate keys"""

        # Write your script here

        symmetric_key = os.urandom(16)

        private_key_sender_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key_sender_rsa = private_key_sender_rsa.public_key()

        private_key_receiver_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key_receiver_rsa = private_key_receiver_rsa.public_key()

        private_key_sender_ecc = SigningKey.generate(curve=NIST384p)
        public_key_sender_ecc = private_key_sender_ecc.verifying_key

        print("Symmetric Key") # Do not change this
        print(symmetric_key) # Do not change this

        print("Sender's RSA Public Key") # Do not change this
        print(public_key_sender_rsa) # Do not change this
        print("Sender's RSA Private Key") # Do not change this
        print(private_key_sender_rsa) # Do not change this

        print("Receiver's RSA Public Key") # Do not change this
        print(public_key_receiver_rsa) # Do not change this
        print("Receiver's RSA Private Key") # Do not change this
        print(private_key_receiver_rsa) # Do not change this

        print("Sender's ECC Public Key") # Do not change this
        print(public_key_sender_ecc) # Do not change this
        print("Sender's ECC Private Key") # Do not change this
        print(private_key_sender_ecc) # Do not change this

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this


    def generate_nonces(self):
        """Generate nonces"""

        # Write your script here

        nonce_aes_cbc = os.urandom(16)

        nonce_aes_ctr = os.urandom(16)

        nonce_encrypt_rsa = os.urandom(256)

        nonce_aes_cmac = os.urandom(16)

        nonce_hmac = os.urandom(32)

        nonce_tag_rsa = os.urandom(32)

        nonce_ecdsa = os.urandom(16)

        nonce_aes_gcm = os.urandom(16)

        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("NOnce for RSA-2048") # Do not change this
        print(nonce_encrypt_rsa) # Do not change this
        print("Nonce for AES-128-CMAC") # Do not change this
        print(nonce_aes_cmac) # Do not change this
        print("Nonce for SHA3-256-HMAC") # Do not change this
        print(nonce_hmac) # Do not change this
        print("Nonce for RSA-2048-SHA3-256") # Do not change this
        print(nonce_tag_rsa) # Do not change this
        print("Nonce for ECDSA") # Do not change this
        print(nonce_ecdsa) # Do not change this
        print("Nonce for AES-128-GCM") # Do not change this
        print(nonce_aes_gcm) # Do not change this

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm # Do not change this



    def encrypt(self, algo, key, plaintext, nonce): # Do not change this
        """Encrypt the given plaintext"""
        
        # Write your script here
        if algo == 'AES-128-CBC-ENC': # Do not change this
            plaintext = bytes(str(plaintext), 'utf8')
            cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            plaintext = pad(plaintext, AES.block_size)
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()


        elif algo == 'AES-128-CTR-ENC': # Do not change this
            plaintext = bytes(str(plaintext), 'utf8')
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            plaintext = pad(plaintext, AES.block_size)
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()


        elif algo == 'RSA-2048-ENC': # Do not change this
            ciphertext = key.encrypt(plaintext, padding2.PKCS1v15())
            

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        return ciphertext # Do not change this


    def decrypt(self, algo, key, ciphertext, nonce): # Do not change this
        """Decrypt the given ciphertext"""
        # Write your script here

        if algo=='AES-128-CBC-DEC': # Do not change this
            cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext =  unpad(plaintext, AES.block_size)
            plaintext = plaintext.decode("utf8")
            

        elif algo == 'AES-128-CTR-DEC': # Do not change this
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = unpad(plaintext, AES.block_size)
            plaintext = plaintext.decode("utf8")


        elif algo == 'RSA-2048-DEC': # Do not change this
            plaintext = key.decrypt(ciphertext, padding2.PKCS1v15())
            

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this
        

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        return plaintext # Do not change this


    def generate_auth_tag(self, algo, key, plaintext, nonce): # Do not change this
        """Generate the authenticate tag for the given plaintext"""

        plaintext = bytes(str(plaintext), 'utf8')

        # Write your script here

        if algo =='AES-128-CMAC-GEN': # Do not change this
            c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
            c.update(plaintext)
            auth_tag = c.finalize()
            

        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(plaintext)
            auth_tag = h.finalize()
            

        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            auth_tag = key.sign(plaintext, padding2.PSS(mgf=padding2.MGF1(hashes.SHA256()), salt_length=padding2.PSS.MAX_LENGTH), hashes.SHA256())


        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
            auth_tag = key.sign(plaintext)


        else:
            raise Exception("Unexpected algorithm") # Do not change this


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        return auth_tag # Do not change this


    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): # Do not change this
        """Verify the authenticate tag for the given plaintext"""

        plaintext = bytes(str(plaintext), 'utf8')

        # Write your script here

        if algo =='AES-128-CMAC-VRF': # Do not change this
            c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
            c.update(plaintext)
            check_tag = c.verify(auth_tag)


        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(plaintext)
            check_tag = h.verify(auth_tag)


        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            check_tag = key.verify(auth_tag, plaintext, padding2.PSS(mgf=padding2.MGF1(hashes.SHA256()), salt_length=padding2.PSS.MAX_LENGTH), hashes.SHA256())  


        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            auth_tag_valid = key.verify(auth_tag, plaintext)
            if(auth_tag_valid == True):
                check_tag = None

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        if(check_tag == None):
            auth_tag_valid = True
        else:
            auth_tag_valid = False

        # # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this
        return auth_tag_valid # Do not change this


    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
        """Encrypt and generate the authentication tag for the given plaintext"""

        plaintext = bytes(str(plaintext), 'utf8')

        # Write your script here

        if algo == 'AES-128-GCM-GEN': # Do not change this
            cipher = AES.new(key_encrypt, AES.MODE_GCM, nonce=nonce)
            ciphertext , auth_tag = cipher.encrypt_and_digest(plaintext)

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key_encrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_generate_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return ciphertext, auth_tag # Do not change this



    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
        """Decrypt and verify the authentication tag for the given plaintext"""

        # Write your script here

        if algo == 'AES-128-GCM-VRF': # Do not change this
            cipher = AES.new(key_decrypt, AES.MODE_GCM, nonce=nonce)
            pt = cipher.decrypt_and_verify(ciphertext, auth_tag)

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        plaintext = pt
        auth_tag_valid = True
        # Write your script here

        plaintext = plaintext.decode('utf8')

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key_decrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_verify_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return plaintext, auth_tag_valid # Do not change this

if __name__ == '__main__': # Do not change this
    ExecuteCrypto() # Do not change this




# ans = ExecuteCrypto()
# key = os.urandom(16)
# # key_auth = AESGCM.generate_key(128)
# # nonce = os.urandom(12)

# private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# public_key = private_key.public_key()

# iv = os.urandom(256)
# plaintext = b"suraj is very very clever boy..."
# # plaintext = key
# enc = ans.encrypt("RSA-2048-ENC", public_key, plaintext, iv)
# print("This is my generated ciphertext :  \n")
# print(enc)

# dcr = ans.decrypt("RSA-2048-DEC", private_key, enc, iv)
# print("This is my generated plaintext :  \n")
# print(dcr)

# ciphertext, auth_ag = ans.encrypt_generate_auth("AES-128-GCM-GEN", key_auth, key, plaintext, nonce)
