import ibe
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.bitstring import Bytes,py3
from charm.core.math.integer import integer
from charm.toolbox.bitstring import Bytes,py3
import math
import pandas as pd
import csv
import os
import json
import ast
import shutil
from datetime import datetime
import time
import random
from Crypto.Cipher import AES
from statistics import mean , stdev
import pickle

group = PairingGroup('MNT224', secparam=1024)
obj = ibe.IBE_BonehFranklin(group)

def prYellow(skk): return ("\033[93m {}\033[00m" .format(skk))
def prGreen(skk): return ("\033[92m {}\033[00m" .format(skk))
def prRed(skk): return("\033[91m {}\033[00m" .format(skk))
def prCyan(skk): return ("\033[96m {}\033[00m" .format(skk))

def IP2OS(number, xLen=None):
    '''
    :Parameters:
      - ``number``: is a normal integer, not modular
      - ``xLen``: is the intended length of the resulting octet string

    Converts an integer into a byte string'''

    ba = bytearray()
    x = 0
    if type(number) == integer:
        x = int(number)
    elif type(number) == int:
        x = number
    elif not py3 and type(number) == long:
        x = number

    if xLen == None:
        xLen = int(math.ceil(math.log(x, 2) / 8.0))

    for i in range(xLen):
        ba.append(x % 256)
        x = x >> 8
    ba.reverse()
    return Bytes(ba)


def OS2IP(bytestr, element=False):
    '''
    :Return: A python ``int`` if element is False. An ``integer.Element`` if element is True

    Converts a byte string to an integer
    '''
    val = 0
    for i in range(len(bytestr)):
        byt = bytestr[len(bytestr) - 1 - i]
        if not py3: byt = ord(byt)
        val += byt << (8 * i)


    if element:
        return integer(val)
    else:
        return val

def load_user (username):
    user = pd.read_csv('users.csv')
    user = user.loc[user['username'] == username]
    return user['username'].values[0], user['private_key'].values[0]

def write_to_csv (list):
    with open('./req.csv', "a",encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(list)
def send_SK_request (username,session_key):
    mpk = load_mpk()

    ey_session_key = obj.encrypt(mpk,'CA',str(session_key).encode())


    u = objectToBytes(ey_session_key["U"], group)
    v = IP2OS(ey_session_key["V"])
    w = IP2OS(ey_session_key["W"])
    a = {"username":username, "U": u, "V":v, "W": w}

    with open(os.path.join("/home/ubuntu/IBE_GUI/requests/",username+".txt"), 'w') as data:
        data.write(str(a))

    users = open('requests.csv','a')
    users.write("{}\n".format(username))
    users.close()

def load_sk(username):
    secret_read = open(os.path.join("/home/ubuntu/IBE_GUI/shared_sk/",username+".txt"))
    secret_sesion_key = secret_read.read()
    secret_read.close()


    file_in = open(os.path.join("/home/ubuntu/IBE_GUI/encrypted_sk/",username+".bin"), "rb")
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]


    cipher = AES.new(secret_sesion_key.encode(), AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt(ciphertext)

    with open(os.path.join("/home/ubuntu/IBE_GUI/sk/",username+".txt"), "w") as file:
        file.write(str(plaintext))

def load_sk_d(username):
    sk_r = open('/home/ubuntu/IBE_GUI/sk/' + username + '.txt')
    sk = sk_r.read()
    sk_r.close()
    return sk

def load_mpk ():
    mpk_read = open("mpk.txt", "r")
    mpk = mpk_read.read()
    mpk_read.close()
    mpk = bytesToObject(mpk, group)
    return mpk

def check_messages (username):
    # reading the data from the file
    with open(os.path.join("/home/ubuntu/IBE_GUI/encrypted_message/",username+".txt")) as f:
        e = f.read()
    ey = ast.literal_eval(e)
    i = 0
    while i < 3:
        i += 1
        suspected = ey['original']
        print ("\nWe have detected a similar account: "+prYellow(suspected)+
           ". Please verify whether this is your account by uploading the similar account ("+prYellow(suspected)+") private key")
        print("\nIf it is not your account please enter 'n'.")
        sk = input()
        if sk == 'n':
            report(username,suspected, 'n')
            return print('\n\nYour response is sent to the '+ prYellow("Central Authority"))
        try:
            sk = str(sk[2:-1])
            sk = bytesToObject(sk, group)
            u = bytesToObject(ey["U"], group)
            v = OS2IP(ey["V"])
            v = integer(v)
            w = OS2IP(ey["W"])
            w = integer(w)
            dy = {'U': u, 'V': v, 'W': w}
            decrypt(username,ey['original'],sk,dy)
            break
        except:
            os.system('clear')
            print("Please try again....", i)
            continue
    else:
        os.system('clear')
        print(prRed("\nThe authentication is not successful."))
        print(prRed("Please contact the "+prYellow("Central Authority")+"."))
        report(username,ey['original'],0)

def report(username_a,username_b,st):
    now = datetime.now()
    timestamp = now.strftime("%d/%m/%Y %H:%M:%S")
    r = [username_a,username_b, st,timestamp]
    auth_sat_encrypt(r)

def auth_sat_encrypt (response):
    mpk = load_mpk()
    s = time.process_time()
    encrypt_sat = obj.encrypt(mpk, 'CA', str(response[2]).encode())
    e = time.process_time()
    d = e - s
    print("Time for Enrcption auth is : ", d)
    u_sat = objectToBytes(encrypt_sat["U"], group)
    v_sat = IP2OS(encrypt_sat["V"])
    w_sat = IP2OS(encrypt_sat["W"])
    auth_reports = []
    ey = [response[0], response[1], response[3], u_sat, v_sat,  w_sat]
    report_filename = 'reports3.dat'

    if os.path.exists(report_filename):
        with open(report_filename, 'rb') as rfp:
            auth_reports = pickle.load(rfp)

    auth_reports.append(ey)
    with open(report_filename, 'wb') as wfp:
        pickle.dump(auth_reports, wfp)


def decrypt (user_a,user_b,sk,e):
    mpk = load_mpk()

    dy = obj.decrypt(mpk,sk,e)

    #print("The dycerpted message is:", dy.decode())
    print(prGreen("The authentication is successful."))
    report(user_a,user_b, 1)
    os.remove(os.path.join("/home/ubuntu/IBE_GUI/encrypted_message/",user_a+".txt"))

def login ():
    print ("Log in to .....")
    userlist = pd.read_csv("users.csv")
    while True:
        user = str(input("Username: "))
        passw = str(input("Password: "))
        try:
            userobj = userlist[userlist['username'] == user].astype(str).values.tolist()
            if (userobj[0][0] == user) & (userobj[0][1] == passw):
                if userobj[0][3] == "1":
                    return user
                else:
                    os.system('clear')
                    print("Your account is deactivated. Please contact the "+prYellow("Central Authority")+".")
                    continue
                    #exit()
            else:
                print("Wrong username or password....")
        except IndexError:
            os.system('clear')
            print("Wrong username or password....")
            continue

def main():
    #os.system('clear')
    username = login()
    os.system('clear')
    print ('Welcome '+ prGreen(username) +',\n')
    if os.path.isfile('/home/ubuntu/IBE_GUI/encrypted_sk/'+username+'.bin') == False:
        N = random.randint(10000000000000, 10000000000000000)
        with open(os.path.join("/home/ubuntu/IBE_GUI/shared_sk/",username+".txt"), "w") as file:
            file.write(str(N))
        send_SK_request(username,N)
        print("You don't have a private key. A private key request is sent to the " + prYellow("Central Authority") + ".")
        print("Please login later...")
        exit()
    else:
        if os.path.isfile('/home/ubuntu/IBE_GUI/sk/'+username+'.txt') == False:
            load_sk(username)

        sk = load_sk_d(username)
        #sk = str(sk[2:-1])
        #print(sk)
        #sk = bytesToObject(sk, group)
        print("Public key: ", username)
        print("Private key: ", sk)#['id'])

    if os.path.isfile('/home/ubuntu/IBE_GUI/encrypted_message/' + username + '.txt') == True:
        check_messages(username)
    else:
        print(prCyan("Your account is authenticated.....\n"))
if __name__ == "__main__":
    main()