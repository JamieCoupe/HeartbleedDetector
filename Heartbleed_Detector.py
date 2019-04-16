"""This script is designed to intercept SSL
packets coming into the device and to warn
the user if the Heartbleed bug is being exploited.This script is for educational use only and is
property of Jamie Coupe"""

# Import scapy and scapy ssl-tls layers
from scapy.all import *
from scapy.layers.scapy_ssl_tls.ssl_tls import *
import smtplib
import getpass

# Set up global variables
device_name = " "
interface = " "
msg = " "
passwd = " "
target = " "
usrname = " "


# Function to set up config variables
def set_up():

    # Collecting global variable
    global device_name
    global interface
    global msg
    global passwd
    global target
    global usrname

    # User input
    """device_name = raw_input("Please enter the name of this device")
    interface = raw_input("Please enter the name of the interface you wish to monitor : ")
    msg = device_name + ": " + raw_input("Please enter the alert message to send: ")
    passwd = raw_input('Password: ')
    target = raw_input("Please enter the address you want alerts to be sent to")
    usrname = raw_input("Please enter your gmail email here (without domain): ") + "@gmail.com"
    """
    # Static values for testing
    device_name = "heartbleed vulnerable VM"
    interface = "eth0"
    msg = "This is a heartbleed alert. Your " + device_name + " device is possibly being targeted"
    passwd = "heartbleed"
    target = "jamie.coupe.jc@gmail.com"
    usrname = "heartbleed.python@gmail.com"

    return 0


# Function to check if message is a heartbeat message
def is_heartbeat(p):
    if p[SSL][TLSRecord].content_type == 24:
        return True

    else:
        return False


# Function to get length of heartbeat message
def get_actual_length(p):

    length = p[SSL][TLSRecord].length
    return length


# Function to get actual length of heartbeat message
def get_length(p):

    # Set data field to data value
    raw_hex = [p[2][SSL][TLSRecord]]
    data = str(raw_hex)
    processed_data = data[92:94] + data[96:98]
    return int("0x" + processed_data, 0)


# Function for checking fields
def field_comparison(p):

    if is_heartbeat(p):

        if get_length(p) != get_actual_length(p):

            # Print output to the console
            print "The defined length is : " + str(get_length(p))
            print "The actual length is : " + str(get_actual_length(p))
            print "This packet is possibly malicious"

            # Send email alert to the user
            send_alert(usrname, passwd, target, msg)

            return 1

        else:
            return 0


# Function to send email alert
def send_alert(uname, password, send_to, message):

    # Set up and log into server
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(uname, password)

    # Send email alert
    server.sendmail(uname, send_to, message)
    server.quit()

    # debugging printing variables
#   print usrname
#   print passwd
#   print target
#   print msg
#   print interface


# To print single function
def print_heartbeat(p):
    print "<<Heartbeat Request>>"
    print get_length(pkt[2])
    print get_actual_length(pkt[2])


# Run set up function
set_up()

# Intercept Network Traffic
pkt = sniff(iface="eth0", lfilter=lambda x: x.haslayer(TLSRecord), stop_filter=field_comparison)

# If Malicious packet > Drop/reset connection
