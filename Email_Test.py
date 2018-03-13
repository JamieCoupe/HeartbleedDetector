"""A simple script set up to test emailsending functionality withing python"""

# import the required libs
import smtplib
import getpass

euname = raw_input("Please enter your gmail email here (without domain): ") + "@gmail.com"
epass = getpass.getpass('Password: ')
target = raw_input("Please enter the address you want alerts to be sent to")
msg = "This is a heartbleed alert, one of your devices maybe being exploited by heartbleed"


server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login(euname, epass)



server.sendmail(euname, target, msg)
server.quit()