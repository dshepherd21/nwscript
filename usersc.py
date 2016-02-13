import ldap
import os
import sys
import time
from datetime import date
import datetime
import ldif
import socket
import ldap.modlist as modlist
from xml.dom import minidom
from optparse import OptionParser
import pyad
from pyad import aduser

def username(dn):
	temp=dn.split(".")
	name=temp[0].replace("cn=","")
	return name

def findusersc(ldapsrv,base_dn,user,passw):
	#print base_dn
	#print ldapsrv
	l=ldap.initialize(ldapsrv)
	try:
		#l.start_tls_s()
		l.bind_s(user, passw)
	except ldap.INVALID_CREDENTIALS:
		print "Your username or password is incorrect."
		sys.exit()
	except ldap.LDAPError, e:
		print e.message['info']
		if type(e.message) == dict and e.message.has_key('desc'):
			print e.message['desc']

		else:
			sys.exit()
	except ldap.NO_SUCH_OBJECT:
		print "Object Not Found"
		sys.exit()
	attrs = ['cn','objectClass','loginScript']
	filter='(&(objectclass=user)(loginScript=*))'
	objlist=l.search_s( base_dn,ldap.SCOPE_SUBTREE,filter,attrs)
	return(objlist)
	
parser = OptionParser()
parser.add_option("-u","--user",help="LDAP User")
parser.add_option("-p","--password",help="LDAP Password")
parser.add_option("-d","--dn",help="BaseDN")
parser.add_option("-s","--server",help="ldap://Server Name:389")

(options, args) = parser.parse_args()

required=["user","password","dn","server"]

for m in required:
	if not options.__dict__[m]:
		print m
		print "Mandatory option is missing\n"
		parser.print_help()
		sys.exit(-1)



user=options.user
pw=options.password
basedn=options.dn
server=options.server
scripts=findusersc(server,basedn,user,pw)
if len(scripts)==0:
	print "No Login Scripts to Import"
print scripts
ad1user=os.environ["USERNAME"]
for line in scripts:
	cn=line[1]["cn"][0]
	print cn
	scr=line[1]["loginScript"][0]
	#user = aduser.ADUser.from_cn(cn)
	try:
		adu=aduser.ADUser.from_cn(cn)
		homedir=adu.get_attribute("homeDirectory")
		homedrive=adu.get_attribute("homeDrive")
		print homedir[0]
		if homedir[0]:
			if os.path.exists(homedir[0]):
				print "Copy Files to Path"
				print scr
				lscript=open(homedir[0]+"\\userlogin.scr","w")
				lscript.write(scr)
				lscript.close()
			else:
				print "No Home Folder for User exists in AD"
				continue
	except:
		print "User Error"
		continue
	sys.exit()
