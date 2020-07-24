from __future__ import print_function
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.util import toHexString
import time
import os, sys


class TracerAndSELECTInterpreter(CardConnectionObserver):
    """This observer will interprer SELECT and GET RESPONSE bytes
    and replace them with a human readable string."""

    def update(self, cardconnection, ccevent):

        if 'connect' == ccevent.type:
            print('connecting to ' + cardconnection.getReader())

        elif 'disconnect' == ccevent.type:
            print('disconnecting from ' + cardconnection.getReader())

        elif 'command' == ccevent.type:
            str = toHexString(ccevent.args[0])
            str = str.replace("A0 A4 00 00 02", "SELECT")
            str = str.replace("A0 C0 00 00", "GET RESPONSE")
            print('>', str)

        elif 'response' == ccevent.type:
            if [] == ccevent.args[0]:
                print('<  []', "%-2X %-2X" % tuple(ccevent.args[-2:]))
            else:
                print('<',
                      toHexString(ccevent.args[0]),
                      "%-2X %-2X" % tuple(ccevent.args[-2:]))


# define the apdus used in this script
GET_RESPONSE        = [0XA0, 0XC0, 00, 00]
SELECT              = [0x00, 0xA4, 0x04, 0x00, 0x07]
AID                 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
GEN_KEY_PAIR        = [0x00, 0x41, 0x02, 0x00]
GET_PRIVATE_KEY     = [0x00, 0x44, 0x00, 0x00]
GET_PUBLIC_KEY      = [0x00, 0x45, 0x00, 0x00]
STORE_PRIVATE_KEY   = [0x00, 0x46, 0x02, 0x00]
STORE_PUBLIC_KEY    = [0x00, 0x47, 0x02, 0x00]
SIGN                = [0x00, 0x48, 0x00, 0x00]
PLAIN_TEXT          = [0x01]
VERIFY              = [0x00, 0x49]
SIGN_NTIMES         = [0x00, 0x4A, 0x00, 0x00]
GEN_KEY_PAIR_NTIMES = [0x00, 0x4C, 0x00, 0x00]

log_path = os.getcwd() + r'\results'
args = sys.argv

def write_time(log_name, time):
    print('elapsed_time:{0}'.format(time))
 
    os.makedirs(log_path, exist_ok=True)
    path = log_path + '\\' + log_name
    
    with open(path, mode='a') as f:
        f.write(str(time) + '\n')

def select_applet():
    print('Selecting Applet')
    apdu = SELECT + AID
    response, sw1, sw2 = cardservice.connection.transmit(apdu)

def gen_key_pair():
    print('GEN_KEY_PAIR')
    apdu = GEN_KEY_PAIR
    response, sw1, sw2 = cardservice.connection.transmit(apdu)

    print(hex(sw1))
    if sw1 != 0x90:
        sys.exit()

def gen_key_pair_ntimes():
    print('GEN_KEY_PAIR_NTIMES')
    apdu = GEN_KEY_PAIR_NTIMES

    start_time = time.time()
    response, sw1, sw2 = cardservice.connection.transmit(apdu)
    elapsed_time = time.time() - start_time

    print(hex(sw1))
    if sw1 == 0x90:
        print('OK')
        print
        write_time(log_name, elapsed_time)
    else:
        print('NG')

def get_private_key():
   print('GET_PRIVATE_KEY')
   apdu = GET_PRIVATE_KEY
   response, sw1, sw2 = cardservice.connection.transmit(apdu)
   private_key = list(map(lambda x: int(x), response))
   return private_key

def get_public_key():
   print('GET_PUBLIC_KEY')
   apdu = GET_PUBLIC_KEY
   response, sw1, sw2 = cardservice.connection.transmit(apdu)
   public_key = list(map(lambda x: int(x), response))
   return public_key

def store_private_key(private_key):
    print('STORE_PRIVATE_KEY')
    private_key.insert(0, len(private_key))
    apdu = STORE_PRIVATE_KEY + private_key
    print(apdu)
    response, sw1, sw2 = cardservice.connection.transmit(apdu)

def store_public_key(public_key):
    print('STORE_PUBLIC_KEY')
    public_key.insert(0, len(public_key))
    apdu = STORE_PUBLIC_KEY + public_key
    response, sw1, sw2 = cardservice.connection.transmit(apdu)

def sign_args(input):
    print('SIGN')
    if input != None:
        plain = [input]
        plain.insert(0, len(plain))
    else:
        plain = PLAIN_TEXT
        plain.insert(0, len(PLAIN_TEXT))
    apdu = SIGN + plain 
    
    response, sw1, sw2 = cardservice.connection.transmit(apdu)
    if sw1 != 0x90:
        sys.exit()

    signed = list(map(lambda x: int(x), response))
    return signed

def sign_ntimes(log_name):
    print('SIGN_NTIMES')
    plain = PLAIN_TEXT
    plain.insert(0, len(PLAIN_TEXT))
    apdu = SIGN + plain 
    
    start_time = time.time()
    response, sw1, sw2 = cardservice.connection.transmit(apdu)
    elapsed_time = time.time() - start_time
    
    print(hex(sw1))
    if sw1 == 0x90:
        print('OK')
        write_time(log_name, elapsed_time)
    else:
        print('NG')

def verify(signed):
    print('VERIFY')
    apdu = VERIFY
    apdu.append(len(signed))
    apdu.append(0)
    apdu.append(len(signed)+1)
    apdu.extend(signed)
    apdu.extend(PLAIN_TEXT)
    response, sw1, sw2 = cardservice.connection.transmit(apdu)
    
    if response[0] == 1:
        print('VERIFY - TRUE')
    else:
        print('VERIFY - FALSE')


# we request any type and wait for 10s for card insertion
cardtype = AnyCardType()
cardrequest = CardRequest(timeout=10, cardType=cardtype)
cardservice = cardrequest.waitforcard()

# create an instance of our observer and attach to the connection
observer = TracerAndSELECTInterpreter()
cardservice.connection.addObserver(observer)

# connect and send APDUs
# the observer will trace on the console
cardservice.connection.connect()

# Selecting Applet
select_applet()

# Generate Key Pair
if args[1] == '01' or args[1] == '03':
    gen_key_pair()
elif args[1] == '02' and args[2] == '01':
    ##GEN_KEY_PAIR(02-01)
    log_name = '02-01.txt'
    start_time = time.time()
    for i in range(10):
        gen_key_pair()
    elapsed_time = time.time() - start_time

    write_time(log_name, elapsed_time)
    sys.exit()
elif args[1] == '02' and args[2] == '02':
    ##GEN_KEY_PAIR_NTIMES(02-02)
    log_name = '02-02.txt'
    gen_key_pair_ntimes()
    sys.exit()

# Get Private Key
private_key = get_private_key()

# Get Public Key
public_key = get_public_key()

# Store PrivateKey and PrivateKeyLen to tempBuffer
#/send 00460200(PrivateKey)
store_private_key(private_key)

# Store PublicKey and PublicKeyLen to tempBuffer
#/send 00470200
store_public_key(public_key)

#Sign
if args[1] == '01':
    signed = sign_args()
elif args[1] == '03' and args[2] == '01':
    #SIGN(03-01)
    log_name = '03-01.txt'
    start_time = time.time()
    for i in range(10):
        ret = sign_args(i)
        print(ret)
    elapsed_time = time.time() - start_time

    write_time(log_name, elapsed_time)
    sys.exit()
elif args[1] == '03' and args[2] == '02':
    log_name = '03-02.txt'
    sign_ntimes(log_name)
    sys.exit()


#Verify
if args[1] == '01':
    verify(signed)