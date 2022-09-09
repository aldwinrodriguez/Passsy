import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
from cryptography.fernet import InvalidToken

import sys
import ast
import os


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


def encrpyt(keyw, cpassw, social):
    passw = getpass('Account Password: ')

    message = passw.encode()
    f = Fernet(keyw)

    encrypted = f.encrypt(message)
    keys = {}

    fileEncryptionPassword = getpass('File Password: ')
    firstpart, secondpart = fileEncryptionPassword[:len(
        fileEncryptionPassword)//2], fileEncryptionPassword[len(fileEncryptionPassword)//2:]
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

            output_file = './enc/accounts.txt'
            with open(output_file, 'a') as f:
                f.write(social + "\n")

            print("\nSaved.")
        else:
            return print("\nData already exists.")
    except:
        print('\nEncrypting Failed.')


def encrpytOverride(keyw, cpassw):
    passw = getpass('Account Password: ')
    message = passw.encode()
    f = Fernet(keyw)

    encrypted = f.encrypt(message)
    keys = {}

    fileEncryptionPassword = getpass('File Password: ')
    firstpart, secondpart = fileEncryptionPassword[:len(
        fileEncryptionPassword)//2], fileEncryptionPassword[len(fileEncryptionPassword)//2:]
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
            return print("\nAccount doesn't exist.")
        else:
            keys[to_look_for] = encrypted.decode() + "\n"
            data = convertToString(keys)
            data = ''.join(data)
            encFile(encryptionKey, data.encode())
            print('\nSuccess\Overrided.')


def convertToString(obj):
    data = []
    for key in obj:
        toAppend = key + " : " + obj[key]
        data.append(toAppend)
    return data


def encFile(encryptionPassword, data):
    try:
        # Use one of the methods to get a key (it must be the same when decrypting)
        key = encryptionPassword
        output_file = './enc/file.encrypted'

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        with open(output_file, 'wb') as f:
            f.write(encrypted)

    except InvalidToken:
        print('\nEncrypting File Failed : Incorrect Password.')

    except FileNotFoundError as e:
        print('\nFile not found. Create file first.')


def decFile(encryptionPassword):
    try:
        # Use one of the methods to get a key (it must be the same as used in encrypting)
        key = encryptionPassword
        input_file = './enc/file.encrypted'

        with open(input_file, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.decrypt(data)
        result = encrypted.decode().replace('\n', '\n,')

    except InvalidToken:
        return print('\nDecrypting File Failed : Incorrect Password.')

    except FileNotFoundError:
        raise FileNotFoundError('\nFile not found. Create file first.')

    else:
        return result


def decrypt(wkey, seckey):
    try:
        wval = ''
        fileEncryptionPassword = getpass('File Password: ')
        firstpart, secondpart = fileEncryptionPassword[:len(
            fileEncryptionPassword)//2], fileEncryptionPassword[len(fileEncryptionPassword)//2:]
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

        print("\nYour password is: " + decrypted.decode())
    except FileNotFoundError as e:
        print("\n" + e)
    except InvalidToken:
        print('\nDecrypting Failed : Incorrect Password.')
    except:
        print('\nDecryption Failed.')


def makeNewFile():
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, r'enc')
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)
    fileEncryptionPassword = getpass('File Password: ')
    firstpart, secondpart = fileEncryptionPassword[:len(
        fileEncryptionPassword)//2], fileEncryptionPassword[len(fileEncryptionPassword)//2:]
    encryptionKey = makeKey(firstpart, secondpart)

    try:
        key = encryptionKey
        output_file = './enc/file.encrypted'

        fernet = Fernet(key)
        encrypted = fernet.encrypt(''.encode())

        with open(output_file, 'wb') as f:
            f.write(encrypted)
    except FileNotFoundError:
        print("\nFolder not found: Create a Folder named 'enc'")


if __name__ == "__main__":
    command = input(
        # 'Command ? \n\nwrite:\nenc to Encode\novr to Override\ndec to Decypher\nsee to see all Accounts\n\n--> ')
        'Command ? \n\nwrite:\nfile to initiate this project (THIS IS IMPORTANT!! BEFORE YOU CAN USE THE APP !!)\nenc to Encode\novr to Override\ndec to Decypher\nsee to see all Accounts\n\n---> ')

    if command == 'ovr':
        social = input('\nFor what Account ? ')
        salt = input('Salt/Security/Favorite word: ')
        key = makeKey(social, salt)
        encrpytOverride(key, social)
    elif command == 'enc':
        social = input('\nFor what Account ? ')
        salt = input('Salt/Security/Favorite word: ')
        key = makeKey(social, salt)
        encrpyt(key, social, social)
    elif command == 'dec':
        social = input('\nFor what Account ? ')
        salt = input('Salt/Security/Favorite word: ')
        key = makeKey(social, salt)
        decrypt(key, social)
    elif command == 'file':
        makeNewFile()
    elif command == 'see':
        f = open("./enc/accounts.txt", "r")
        print("\nYour accounts are:\n" + f.read())
    else:
        print('\nCommand not found.')
