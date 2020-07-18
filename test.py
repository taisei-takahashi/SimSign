from __future__ import print_function
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.util import toHexString
import time


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
GET_RESPONSE = [0XA0, 0XC0, 00, 00]
SELECT = [0x00, 0xA4, 0x04, 0x00, 0x07]
AID = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
GEN_KEY_PAIR = [0x00, 0x41, 0x02, 0x00]
GET_PRIVATE_KEY = [0x00, 0x44, 0x00, 0x00]
GET_PUBLIC_KEY = [0x00, 0x45, 0x00, 0x00]
STORE_PRIVATE_KEY = [0x00, 0x46, 0x02, 0x00]
STORE_PUBLIC_KEY = [0x00, 0x47, 0x02, 0x00]
SIGN = [0x00, 0x48, 0x00, 0x00]
PLAIN_TEXT = [0x01]
VERIFY = [0x00, 0x49]
SIGN_NTIMES = [0x00, 0x4A, 0x00, 0x00]

def sign_args(input):
    plain = [input]
    plain.insert(0, len(PLAIN_TEXT))
    apdu = SIGN + plain 
    
    response, sw1, sw2 = cardservice.connection.transmit(apdu)
    signed = list(map(lambda x: int(x), response))
    return signed

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
print('Selecting Applet')
apdu = SELECT + AID
response, sw1, sw2 = cardservice.connection.transmit(apdu)

print('GEN_KEY_PAIR')
apdu = GEN_KEY_PAIR
response, sw1, sw2 = cardservice.connection.transmit(apdu)

print('GET_PRIVATE_KEY')
apdu = GET_PRIVATE_KEY
response, sw1, sw2 = cardservice.connection.transmit(apdu)
#private_key = list(map(lambda x: int(hex(x), 16), response))
private_key = list(map(lambda x: int(x), response))
print(private_key)

print('GET_PUBLIC_KEY')
apdu = GET_PUBLIC_KEY
response, sw1, sw2 = cardservice.connection.transmit(apdu)
#public_key = list(map(lambda x: int(hex(x), 16), response))
public_key = list(map(lambda x: int(x), response))


# Store PrivateKey and PrivateKeyLen to tempBuffer
#/send 00460200(PrivateKey)
print('STORE_PRIVATE_KEY')
private_key.insert(0, len(private_key))
apdu = STORE_PRIVATE_KEY + private_key
print(apdu)
response, sw1, sw2 = cardservice.connection.transmit(apdu)

# Store PublicKey and PublicKeyLen to tempBuffer
#/send 00470200
print('STORE_PUBLIC_KEY')
public_key.insert(0, len(public_key))
apdu = STORE_PUBLIC_KEY + public_key
response, sw1, sw2 = cardservice.connection.transmit(apdu)

#Sign
print('SIGN')
#PLAIN_TEXT.insert(0, len(PLAIN_TEXT))
#apdu = SIGN + PLAIN_TEXT
#response, sw1, sw2 = cardservice.connection.transmit(apdu)
#signed = list(map(lambda x: int(x), response))

#sign_start_time = time.time()
#for i in range(100):
#    ret = sign_args(i)
#    print(ret)
#sign_elapsed_time = time.time() - sign_start_time
#print('elapsed_time:{0}'.format(sign_elapsed_time))

sign_start_time = time.time()
PLAIN_TEXT.insert(0, len(PLAIN_TEXT))
apdu = SIGN_NTIMES + PLAIN_TEXT
response, sw1, sw2 = cardservice.connection.transmit(apdu)
sign_elapsed_time = time.time() - sign_start_time
print('elapsed_time:{0}'.format(sign_elapsed_time))

#Verify
#print('VERIFY')
#apdu = VERIFY
#apdu.append(len(signed))
#apdu.append(0)
#apdu.append(len(signed)+1)
#apdu.extend(signed)
#apdu.extend(PLAIN_TEXT)
#response, sw1, sw2 = cardservice.connection.transmit(apdu)

#if response[0] == 1:
#    print('VERIFY - TRUE')
#else:
#    print('VERIFY - FALSE')
