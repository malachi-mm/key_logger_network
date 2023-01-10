import base64

from scapy.all import raw
from scapy.all import bytes_hex
from scapy.packet import Raw
from scapy.sendrecv import sniff

def rev(s: str):
    x = ''
    for i in s:
        a = ord(i)-60
        x += chr(a)
    return x


def f(packet):
    if (packet[0].haslayer(Raw)):
        try:
            a = ((packet[0][Raw].load)[::-1]).decode()
            #print(a)
            a = rev(a)
            # print("2#  " + a)
            if a[:3] == 'kkk':
                # print(a.decode())
                print(a[3:])
        except:
            pass


while True:
    sniff(prn=f)
    #print(bytes_hex(packet[0]))
