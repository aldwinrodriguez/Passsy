import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass 
from cryptography.fernet import InvalidToken

import sys
import ast

def makeKey(arg1, arg2):
    p1 = arg1 
    password = p1.encode() 
    salt = arg2.encode() 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) 
    return key

def encrpyt(keyw, cpassw):
    passw = getpass('Social Password: ')

    message = passw.encode()
    f = Fernet(keyw)

    encrypted = f.encrypt(message)
    keys= {}

    fileEncryptionPassword = getpass('File Password: ')
    firstpart, secondpart = fileEncryptionPassword[:len(fileEncryptionPassword)//2], fileEncryptionPassword[len(fileEncryptionPassword)//2:]
    encryptionKey = makeKey(firstpart, secondpart)
    
    try:
        data = list(filter(None, decFile(encryptionKey).split(',')))
        for element in data:
            key, val = element.split(' : ')
            keys[key.lower()] = val

        to_look_for = cpassw
        if to_look_for not in keys:
            text = cpassw.lower() + ' : ' + encrypted.decode() + "\n"
            data.append(text)
            data = ''.join(data)
            encFile(encryptionKey, data.encode())
            print("Saved.")
        else:
            return print("Data already exists.")
    except:
        print('Encrypting Failed.')

def encrpytOverride(keyw, cpassw):
    passw = getpass('Social Password: ')
    message = passw.encode()
    f = Fernet(keyw)

    encrypted = f.encrypt(message)
    keys= {}

    fileEncryptionPassword = getpass('File Password: ')
    firstpart, secondpart = fileEncryptionPassword[:len(fileEncryptionPassword)//2], fileEncryptionPassword[len(fileEncryptionPassword)//2:]
    encryptionKey = makeKey(firstpart, secondpart)

    try:
        data = list(filter(None, decFile(encryptionKey).split(',')))
    
    except:
        print('\nOverriding Failed.')

    else:
        for element in data:
            key, val = element.split(' : ')
            keys[key.lower()] = val

        to_look_for = cpassw
        if to_look_for not in keys:
            return print("Account doesn't exist.")
        else:
            keys[to_look_for] = encrypted.decode() + "\n"
            data = convertToString(keys)
            data = ''.join(data)
            encFile(encryptionKey, data.encode())
            print('Overrided.')
    

def convertToString(obj):
    data = []
    for key in obj:
        toAppend = key + " : " + obj[key]
        data.append(toAppend) 
    return data


def encFile(encryptionPassword, data):
    try:
        key = encryptionPassword # Use one of the methods to get a key (it must be the same when decrypting)
        output_file = './enc/file.encrypted'

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        with open(output_file, 'wb') as f:
            f.write(encrypted)

    except InvalidToken:
        print('Encrypting File Failed : Incorrect Password.')
    
    except FileNotFoundError as e:
        print('File not found. Create file first.')

def decFile(encryptionPassword):
    try:
        key = encryptionPassword # Use one of the methods to get a key (it must be the same as used in encrypting)
        input_file = './enc/file.encrypted'

        with open(input_file, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.decrypt(data)
        result = encrypted.decode().replace('\n', '\n,')

    except InvalidToken:
        return print('Decrypting File Failed : Incorrect Password.')
    
    except FileNotFoundError:
        raise FileNotFoundError('File not found. Create file first.')

    else:
        return result

def decrypt(wkey, seckey):
    try:
        wval = ''
        fileEncryptionPassword = getpass('File Password: ')
        firstpart, secondpart = fileEncryptionPassword[:len(fileEncryptionPassword)//2], fileEncryptionPassword[len(fileEncryptionPassword)//2:]
        encryptionKey = makeKey(firstpart, secondpart)

        data = list(filter(None, decFile(encryptionKey).split(',')))
        for element in data:
            key, val = element.split(' : ')
            if key == seckey:
                wval = val
                break

        encrypted = wval.encode()
        f = Fernet(wkey)
        decrypted = f.decrypt(encrypted)

        print(decrypted.decode())
    except FileNotFoundError as e:
        print(e)
    except InvalidToken:
        print('Decrypting Failed : Incorrect Password.')
    except:
        print('Decryption Failed.')

def makeNewFile():
    fileEncryptionPassword = getpass('File Password: ')
    firstpart, secondpart = fileEncryptionPassword[:len(fileEncryptionPassword)//2], fileEncryptionPassword[len(fileEncryptionPassword)//2:]
    encryptionKey = makeKey(firstpart, secondpart)

    try:
        key = encryptionKey
        output_file = './enc/file.encrypted'

        fernet = Fernet(key)
        encrypted = fernet.encrypt(''.encode())

        with open(output_file, 'wb') as f:
            f.write(encrypted)
    except FileNotFoundError:
        print("No directory: Create a Folder named 'enc'")


if __name__ == "__main__":
    command = getpass('Command ? ')
    
    if command == 'ovr':
        social = getpass('Account ? ')
        salt = getpass('Password: ')
        key = makeKey(social, salt)
        encrpytOverride(key, social)
    elif command == 'enc':
        social = getpass('Account ? ')
        salt = getpass('Password: ')
        key = makeKey(social, salt)
        encrpyt(key, social)
    elif command == 'dec':
        social = getpass('Account ? ')
        salt = getpass('Password: ')
        key = makeKey(social, salt)
        decrypt(key, social)
    elif command == 'file':
        makeNewFile()
    else:
        print('Command not found.')