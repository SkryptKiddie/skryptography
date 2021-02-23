import base64, os, string, random, calendar, hashlib # basic cryptography tool by SkryptKiddie
from datetime import datetime # uses the fernet key protocol
from random import randint
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

txt_mode = "utf-8" # specify what character encoding to use

class ct: # colour text
    ENDC = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    BOLD = '\033[1m'
    SUCCESS = "[\033[92m√\033[0m] "
    ERROR = "[\033[91m!\033[0m] "
    NOTE = "[\033[93m#\033[0m] "

class keyOperations: # crypto key operations
    @staticmethod # sourced from https://github.com/bopace/generate-primes
    def isPrime(num, testCount):
        if num == 1:
            return False
        if testCount >= num:
            testCount = num - 1
        for val in range(testCount):
            val = randint(1, num - 1)
            if pow(val, num-1, num) != 1:
                return False
        return True

    @staticmethod
    def generateBigPrime(n):
        foundPrime = False
        while not foundPrime:
            p = randint(2**(n-1), 2**n)
            if keyOp.isPrime(p, 1000): # make sure the number can be divided by itself and 1
                return int(p) # return prime number

    @staticmethod
    def keyGenerate(): # key generation
        keyPwd = input("Key password: ")
        if keyPwd is None: # if user doesn't enter a password, generate a random string and use that
            letters = string.ascii_letters 
            resultStr = ''.join(random.choice(letters) for i in range(16))
            keyPwd = str(resultStr).encode(txt_mode) # encode the password into the selected encoding method
            keyPwd = str(keyPwd).encode(txt_mode) # generate a random string as the password if nothing is entered
            print("No password specified, using {}".format(keyPwd)) # tell the user what the password is 
        keyPwd = str(keyPwd).encode(txt_mode)
        print(ct.NOTE + "Generating a large prime number...")
        try:
            keyPrime = str(keyOp.generateBigPrime(128))
            print(ct.SUCCESS + "Generated a prime!")
            print(keyPrime)
            pass
        except: # unable to get a prime number, so we'll use 1024 as a key entropy
            print(ct.ERROR + "Error while generating a prime number! Failover to 1024")
            keyPrime = int(1024)
            pass
        print(ct.NOTE + "Generating new key...")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=(str(keyPrime).encode(txt_mode)),
            iterations=100000,
            backend=default_backend())
        try:
            newKey = base64.urlsafe_b64encode(kdf.derive(keyPwd)) # generate a PSK
            keyHash = hashlib.md5(str(newKey).encode(txt_mode)) # generate key md5
            print(ct.SUCCESS + "Generated key!")
            print("\n---START FERNET KEY---\n" + str(newKey)[2:-1] + "\n---END FERNET KEY---\n") # print the new key
            print(ct.NOTE + "MD5: " + keyHash.hexdigest()) # print the key hash
        except:
            print(ct.ERROR + "An unexpected error occured while generating a key.")
            exit()

    @staticmethod
    def keyExport(keyName, time, keyData): # export key to a file for cold storage
        keyFileName = str(keyName + ".key")
        keyData = str(keyData)
        validateKey = keyData
        if keyOp.keyValidate(validateKey, verbose=2) == True: # make sure the key is valid
            keyName = str(keyName).encode(txt_mode)
            br = str(":").encode(txt_mode)
            ts = str(int(time)).encode(txt_mode)
            keyData = str(keyData).encode(txt_mode)
            with open(keyFileName, "wb") as expKey:
                expKey.write(keyName + br + ts + br + keyData) # format = key nickname:export time:crypto key
            print(ct.SUCCESS + "Exported key successfully! {}".format(str(keyFileName)))
            exit()
        else:
            print(ct.ERROR + "Key validation failed! Unable to save.")
            exit()

    @staticmethod
    def keyValidate(validateKey, verbose): # key validation
        try: # make sure the key is actually valid
            key = Fernet(str(validateKey))
        except:
            print(ct.ERROR + "Invalid key")
            exit()
        letters = string.ascii_letters # generate a test string to validate the key
        resultStr = ''.join(random.choice(letters) for i in range(16))
        test_var = str(resultStr).encode(txt_mode)
        if verbose == 1: # normal key test
            print(ct.BOLD + "Key test")
            print("Test string: " + str(test_var)[2:-1])
            print(ct.NOTE + "Starting test.")
            try: # try to encrypt the test string
                print(ct.NOTE + "Encrypting...")
                test_var_enc = key.encrypt(test_var) # encrypt the string
                print(ct.SUCCESS + "Encrypted!")
                try: # if that worked, try to decrypt the test string
                    print(ct.NOTE + "Decrypting...")
                    test_var_final = key.decrypt(test_var_enc) # decrypt the string
                    print(ct.SUCCESS + "Decrypted")
                    if str(test_var) == str(test_var_final): # make sure the values both match at the end
                        print(ct.SUCCESS + "Key validation completed successfully!")
                        return True
                    else:
                        print(ct.ERROR + "Key validation failed! Value mismatch.")
                        return False
                except: # if we couldn't decrypt, error here
                    print(ct.ERROR + "Key validation failed!")
                    print(ct.ERROR + "Key {} failed decryption test".format(validateKey))
                    return False
            except: # if we couldn't encrypt, error here
                print(ct.ERROR + "Key validation failed!")
                print(ct.ERROR + "Key {} failed encryption test".format(validateKey))
                return False

        if verbose == 2: # quiet key test
            print(ct.NOTE + "Verifying key...")
            try: # try to encrypt the test string
                test_var_enc = key.encrypt(test_var) # encrypt the string
                try: # if that worked, try to decrypt the test string
                    test_var_final = key.decrypt(test_var_enc) # decrypt the string
                    if str(test_var) == str(test_var_final): # make sure the values both match at the end
                        print(ct.SUCCESS + "Valid key!", end="\r")
                        return True
                    else:
                        print(ct.ERROR + "Invalid key! Value mismatch.", end="\r") # if the start and finish string don't match, return this error
                        return False
                except: # if we couldn't decrypt, error here
                    print(ct.ERROR + "Key validation failed!", end="\r")
                    return False
            except: # if we couldn't encrypt, error here
                print(ct.ERROR + "Key validation failed!", end="\r")
                return False

    @staticmethod
    def encTimestamp(decKey, input):
        key = Fernet(str(decKey))
        ts = str(input).encode(txt_mode) 
        encrypted_data = str(input).encode(txt_mode)
        ts = key.extract_timestamp(encrypted_data) # get timestamp from file
        return str(datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"))

class cryptography: # cryptographic operations
    @staticmethod
    def encryptText(encKey, encMessage): # encrypt text
        validateKey = encKey
        if keyOp.keyValidate(validateKey, verbose=2) == True: # make sure the key is valid
            key = Fernet(encKey)
            try: # try to encrypt the message
                encryptedMessage = key.encrypt(str(encMessage).encode(txt_mode))
                return str(encryptedMessage)[2:-1]
            except: # return an error if we can't
                print(ct.ERROR + "An error occured while trying to encrypt.")
        else:
            print(ct.ERROR + "Key validation failed! Unable to encrypt.")
            exit()

    @staticmethod
    def decryptText(decKey, decMessage):
        validateKey = decKey
        if keyOp.keyValidate(validateKey, verbose=2) == True: # make sure the key is valid
            key = Fernet(str(decKey))
            encrypted_data = (str(decMessage).encode(txt_mode))
            try: # try to decrypt the message
                decrypted_message = key.decrypt(encrypted_data)
                return str(decrypted_message)[2:-1]
            except: # return an error if we can't
                print(ct.ERROR + "An error occured while trying to decrypt.")
        else:
            print(ct.ERROR + "Key validation failed! Unable to decrypt.")
            exit()

    @staticmethod
    def encryptFile(encKey, encFile):
        validateKey = encKey
        if keyOp.keyValidate(validateKey, verbose=2) == True: # make sure the key is valid
            key = Fernet(encKey) # load the key
            try: # try to open the file and encrypt
                with open(encFile, "rb") as file:
                    fileData = file.read()
                    encryptedData = key.encrypt(fileData)
                    with open(encFile, "wb") as file:
                        file.write(encryptedData)
                        print(ct.SUCCESS + "Successfully encrypted {}".format(encFile))
            except:
                print(ct.ERROR + "An error occured while trying to encrypt.")

        else:
            print(ct.ERROR + "Key validation failed! Unable to encrypt file.")
            exit()

    @staticmethod
    def decryptFile(decKey, decFile):
        validateKey = decKey
        if keyOp.keyValidate(validateKey, verbose=2) == True: # make sure the key is valid
            key = Fernet(str(decKey))
            try:
                with open(decFile, "rb") as file:
                    encrypted_data = file.read()
                    decrypted_data = key.decrypt(encrypted_data) # decrypt the file
                    with open(decFile, "wb") as fileData:
                        fileData.write(decrypted_data) # write the decrypted data back into the file
                    print(ct.SUCCESS + "Successfully decrypted {}".format(decFile))
            except:
                print(ct.ERROR + "An error occured while trying to decrypt.")
        else:
            print(ct.ERROR + "Key validation failed! Unable to decrypt file.")
            exit()

keyOp = keyOperations()
crypto = cryptography()

def runtime():
    try:
        print("""
        -- cryptography --
        (e)ncrypt message   (E)encrypt file
        (d)ecrypt message   (D)ecrypt file
        -- key managment --
        (g)enerate key    (v)alidate key
        e(x)port key
        """)
        opt = input("")
        if opt[:1] == "e": # encrypt message
            print(ct.BOLD + "Encrypt message" + ct.ENDC)
            encKey = input("Key: ")
            encMessage = input("Message: ")
            print("Output: " + str(crypto.encryptText(encKey, encMessage))) # calls the crypto.encryptText function

        if opt[:1] == "d": # decrypt message
            print(ct.BOLD + "Decrypt message" + ct.ENDC)
            decKey = input("Key: ")
            decMessage = input("Encrypted hash: ")
            print("Output: " + str(crypto.decryptText(decKey, decMessage))) # calls the crypto.decryptText function
            print("Encryption timestamp: " + keyOp.encTimestamp(decKey, input=decMessage)) # call the keyOperations.encTimestamp function

        if opt[:1] == "E": # encrypt file
            print(ct.BOLD + "Encrypt file" + ct.ENDC)
            print("Current directory: " + str(os.getcwd()))
            encFile = input("Filename: ")
            encKey = input("Key: ")
            crypto.encryptFile(encKey, encFile) # calls the crypto.encryptFile function
            
        if opt[:1] == "D": # decrypt file
            print(ct.BOLD + "Decrypt file" + ct.ENDC)
            print("Current directory: " + str(os.getcwd()))
            decFile = input("Filename: ")
            decKey = input("Key: ")
            print(crypto.decryptFile(decKey, decFile)) # calls the crypto.decryptFile function

        if opt[:1] == "g": # generate key
            print(ct.BOLD + "Key generator" + ct.ENDC)
            keyOp.keyGenerate() # call the key generator function

        if opt[:1] == "x": # export key
            print(ct.BOLD + "Export key" + ct.ENDC)
            keyName = input("Enter a nickname for the key: ")
            keyData = input("Paste the key: ")
            d = datetime.utcnow()
            time = calendar.timegm(d.utctimetuple()) # timestamp of export
            print(str(keyOp.keyExport(keyName, time, keyData)))

        if opt[:1] == "v": # validate key
            print(ct.BOLD + "Key validation" + ct.ENDC)
            validateKey = input("Paste key here: ")
            keyOperations.keyValidate(validateKey, verbose=1) # call the keyOperations.keyValidate function

    except KeyboardInterrupt:
        print(ct.NOTE + "Exiting...")
        exit()

default_backend()
runtime()