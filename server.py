import ibe
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.core.math.integer import integer
from charm.toolbox.bitstring import Bytes,py3
import math
import pandas as pd
import secrets
import string
import random
import csv
from datetime import datetime
import os
import json
import time
from dateutil.parser import parse
import ast
from Crypto.Cipher import AES
from statistics import mean , stdev
import pickle

group = PairingGroup('MNT224', secparam=1024)
obj = ibe.IBE_BonehFranklin(group)


def prYellow(skk): return ("\033[93m {}\033[00m" .format(skk))
def prGreen(skk): return ("\033[92m {}\033[00m" .format(skk))
def prRed(skk): return("\033[91m {}\033[00m" .format(skk))
def prLightPurple(skk): return ("\033[94m {}\033[00m" .format(skk))
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

    # These lines convert val into a binary string of 1's and 0's
    # bstr = bin(val)[2:]   #cut out the 0b header
    # val = int(bstr, 2)
    # return val
    if element:
        return integer(val)
    else:
        return val

def write_to_csv (list):
    with open('./messages.csv', "a",encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(list)

#Generate PUBLIC AND PRIVATE KEY FOR CA
def m_pk_sk ():
    (master_public_key, master_secret_key) = obj.setup()
    master_public_key = objectToBytes(master_public_key, group)
    master_secret_key = objectToBytes(master_secret_key, group)
    with open(os.path.join("/home/ubuntu/IBE_GUI/mpk.txt"), "w") as file:
        file.write(str(master_public_key))
    with open(os.path.join("/home/ubuntu/IBE_GUI/msk.txt"), "w") as file:
        file.write(str(master_secret_key))

#LOAD MASTER SECRET KEY
def load_msk ():
    msk_read = open("msk.txt", "r")
    msk = msk_read.read()
    msk_read.close()
    msk = bytesToObject(msk, group)
    return msk

#LOAD MASTER PUBLIC KEY
def load_mpk ():
    mpk_read = open("mpk.txt", "r")
    mpk = mpk_read.read()
    mpk_read.close()
    mpk = bytesToObject(mpk, group)
    return mpk

def load_sk():
    sk_r = open('/home/ubuntu/IBE_GUI/sk/CA.txt')
    sk = sk_r.read()
    sk_r.close()
    return sk
#EXTRACT PRIVATE KEY FOR USERS
def extract_private_key (ey):

    mpk = load_mpk()
    sk = load_sk()
    sk = str(sk[2:-1])
    sk = bytesToObject(sk, group)
    u = bytesToObject(ey["U"], group)
    v = OS2IP(ey["V"])
    v = integer(v)
    w = OS2IP(ey["W"])
    w = integer(w)
    dy = {'U': u, 'V': v, 'W': w}
    c = obj.decrypt(mpk,sk,dy)

    with open(os.path.join("/home/ubuntu/IBE_GUI/server_shared_sk/",ey["username"]+".txt"), "w") as file:
        file.write(str(c.decode()))
    msk = load_msk()

    private_key = obj.extract(msk, ey["username"])
    private_key = objectToBytes(private_key, group)

    key = c
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)

    file_out = open(os.path.join("/home/ubuntu/IBE_GUI/encrypted_sk/",ey["username"]+".bin"), "wb")
    [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    file_out.close()

    print('\nSK is created FOR ' + ey["username"] + ' \n')


def check_reports():
    os.system('clear')
    report_filename = 'reports3.dat'
    reports = []
    with open(report_filename, 'rb') as rfp:
        reports = pickle.load(rfp)

    if not reports:
        print( '\n\nThere is no authentication reports..\n\n\n')
        main()
    else:
        mpk = load_mpk()
        sk = load_sk()
        sk = str(sk[2:-1])
        sk = bytesToObject(sk, group)
        print('*************************')
        print("\nHere is the list of the authentication results....\n ")

        for i in range(len(reports)):
            u_sat = reports[i][3]
            v_sat = reports[i][4]
            w_sat = reports[i][5]
            u = bytesToObject(u_sat, group)
            v = OS2IP(v_sat)
            v = integer(v)
            w = OS2IP(w_sat)
            w = integer(w)
            dy = {'U': u, 'V': v, 'W': w}
            c = obj.decrypt(mpk, sk, dy).decode()
            if c == '0':
                a = prRed('0')
            elif c == '1':
                a = prGreen('1')
            else:
                a = prYellow('n')

            print(reports[i][0],',', reports[i][1],a)
        print('')
        print("auth_sat: " + prRed("0 - the authentication is not successful."))
        print("auth_sat: " + prGreen("1 - the authentication is successful."))
        print("auth_sat: " + prYellow("n - the similar account is not their account.\n"))
        print('')
        print('*************************')
        print('')
        print('')
        print('')
        main()

def check_sk_requests ():
    users = pd.read_csv('requests.csv')
    if users.empty == True:
        print( '\nThere is no SK requests..\n')
        main()
    else:
        username = users['username'].values
        for i in range(len(username)):
            if os.path.isfile('/home/ubuntu/IBE_GUI/sk/' + username[i] + '.txt') == True:
                continue
            with open(os.path.join("/home/ubuntu/IBE_GUI/requests/", username[i] + ".txt")) as f:
                e = f.read()
            ey = ast.literal_eval(e)
            extract_private_key(ey)
        users = users.iloc[0:0]
        users.to_csv('requests.csv', index=False)
        main()

def send_encrypted(account_pair):
    users = pd.read_csv('users.csv',parse_dates=['registration_date'])
    a = users.loc[users.username == account_pair.values[0][0]]
    b = users.loc[users.username == account_pair.values[0][1]]
    a_date = a['registration_date'].values[0]
    b_date = b['registration_date'].values[0]
    original = 0
    suspected = 0
    if a_date < b_date:
        original = a['username'].values[0]
        suspected = b['username'].values[0]
        print(prGreen(original) + " is older than " + prRed(suspected))
    elif b_date < a_date:
        original = b['username'].values[0]
        suspected = a['username'].values[0]
        print(prGreen(original) + " is older than " + prRed(suspected))

    N = random.randint(10,50)
    message = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                  for i in range(N))
    now = datetime.now()
    timestamp = now.strftime("%d/%m/%Y %H:%M:%S")
    mpk = load_mpk()

    encrypt_message = obj.encrypt(mpk, original, message.encode())

    u = objectToBytes(encrypt_message["U"], group)
    v = IP2OS(encrypt_message["V"])
    w = IP2OS(encrypt_message["W"])
    ey = {"original": original,"suspected": suspected, "timestamp": timestamp, "message": message,
          "U": u, "V": v, "W": w}

    with open(os.path.join("/home/ubuntu/IBE_GUI/encrypted_message/",suspected+".txt"), 'w') as data:
        data.write(str(ey))

    print("\nEncrypted message is sent to " + prRed(suspected) + " using " + prGreen(original)+"'s public key\n")

def similar_account():
    account = pd.read_csv('similar_account.csv')
    return account

def ibe ():
    while True:
        try:
            sim_user = similar_account()
            print("\n")
            print(sim_user)
            print("\nThere are " + prGreen(str(len(sim_user))) + " not authenticated similar account pair....\n ")
            print("\nPlease choose an account pair to authenticated.." ,
                  "or "+prGreen("-1")+ " for main menu")
            inupt = int(input())
            if inupt == -1:
                main()
                break
            else:
                send_encrypted(sim_user.iloc[[inupt]])
                break
        except TypeError:
            print(prRed("Wrong Choose....."))
            continue

def notification (m):
    if m == 0:
        users = pd.read_csv('requests.csv')
        if users.empty == True:
            return 0
        else:
            return len(users['username'].values)
    if m == 1:
        sim_user = similar_account()
        return len(sim_user)
    if m == 2:
        reports = pd.read_csv('reports.csv')
        username = reports['account_A'].values
        auth_sat = reports['auth_sat'].values
        count_f = 0
        count_uf = 0
        count_un = 0
        for i in range(len(username)):
            if auth_sat[i] == '0':
                count_f += 1
            elif auth_sat[i] == '1':
                count_uf += 1
            elif auth_sat[i] == 'n':
                count_un += 1
        return count_f, count_uf, count_un


def main():
    print ("Welcome to the "+prYellow("Central Authority")+"\n")
    if os.path.isfile('/home/ubuntu/IBE_GUI/msk.txt') == False:
        m_pk_sk()
        print("PUBLIC KEY AND PRIVATE KEY ARE GENERATED.......")
    if os.path.isfile('/home/ubuntu/IBE_GUI/sk/CA.txt') == False:
        extract_private_key('CA')
    while True:
        try:
            print("Please choose from the drop down main menu")
            print("0 - Private Key Request - "+ prRed(notification(0)) + " new private key request " )
            print("1 - Cryptography-Based Authentication - " + prRed(notification(1)) + " not authenticated similar user pair. ")
            a,b,c = notification(2)
            print("2 - Authentication List - " + prRed(a) + "," + prGreen(b) + " failed, passed authentication and" + prYellow(c) + "  the similar account is not their account" )
            print ("3 - Exit")
            chose = int(input ())
            if chose == 0 :
                check_sk_requests()
                break
            elif chose == 1:
                ibe()
                break
            if chose == 2:
                check_reports()
                break
            elif chose == 3:
                exit()
            else:
                print(prRed("Wrong Choose....."))
                continue
        except ValueError:
            print(prRed("Wrong Choose....."))
            continue

if __name__ == "__main__":
    main()