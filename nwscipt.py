import xml
import ldap
import os
import sys
import time
from datetime import date
import datetime
import ldif
import ldap.modlist as modlist
from xml.dom import minidom
from optparse import OptionParser
import pyad
from pyad import aduser
import win32wnet
import win32netcon
from IPy import IP
import socket
import _winreg
import win32api
#pyad.pyad_setdefaults(ldap_server="192.168.10.51")
from Crypto.Cipher import DES


def sub(line):
	for temp in option:
		if temp in line:
			line=line.replace(temp,option[temp])
	return(line)
	
def optsetup(temp=[]):
	"""Populate Options for Macros"""
	for line in temp.iterkeys():
		
		if line=="%home_directory":
			temp[line]=os.environ['HOMESHARE']
		if line=="%cn" or line=="%login_name":
			temp[line]=os.environ['USERNAME']
		if line=="%file_server":
			temp[line]=os.environ['LOGONSERVER']
		if line=="%os":
			temp[line]=os.environ['OS']
		if line=="%language":
			temp[line]=os.environ['LANGUAGE']
		if line=="%network_address":
			temp[line]=socket.gethostbyname(socket.gethostname())
		
			
	return(temp)
	

def errorlog(name,line):
	details="ERROR: "+name+" error in line "+str(line)+"\n"
	errors.write(details)
	print details
	return
	
def scriptproc(cmds):
	status=0
	ifproc=0
	"""Core Login Script Processing Function"""
	ifprocess=0
	count=1
	for temp in cmds:
		#print temp
		temp=temp.lower()
		if "write" in temp:
			try:
				temp1=temp.split("\"")
				temp1=temp1[1]
				temp1=sub(temp1)
				print temp1
			except:
				errorlog("Write Command Invalid",count)
			
		if "set" in temp or "dos set" in temp:
			print "\n"
			try:
				pts=temp.split(" ")
				params=pts[-1].split("=")
			except:
				# print "ERROR in line "+count
				errorlog("set failed",count)
				print "\n"
	
			print "STATUS: Setting Env Variable "+params[0]+" to "+params[1]
			try:
				os.system("setx "+params[0]+" "+params[1])
			except:
				errorlog("Client does not have setx.exe installed",count)
			print "\n"
			continue
	
		if "exit" == temp:
			print "STATUS: Login Script Finished"
			return
		
		for line in excluded_commands:
			if line in temp:
				print "\n"
				print "STATUS: Command Dropped "+temp+" In Line "+str(count)
				print "\n"
				continue
		
		if "if \"%" in temp.lower():
			ifmarker=1
			try:
				temp1=temp.split(" ")
				#print temp1
				vals=temp1[1].split("=")
				vals[1]=vals[1].replace("\"","")
				vals[0]=vals[0].replace("\"","")
				vals[0]=vals[0].replace("%","")
			
				envvar=vals[0]
			except:
				#print "ERROR: Command error in line "+count
				errorlog("Command error in if command",count)
				continue
			try:
				val1=os.environ.get(envvar)
				#print val1
			except:
				errorlog("Env Variable Not Found",count)
				status=1
				continue
			ifprocess=1
			if val1==vals[1]:
				status=0
				print "STATUS: Start IF Process. Env Variable Check Passed"
				
			
	
		if "if member of".lower() in temp.lower():
			#print "if member of found"h
			ifmarker=1
			try:
				temp1=temp.split("\"")
				name=groupname(temp1[1])
			except:
				errorlog("IF Failed",count)
				continue
			print "\n"
			print "STATUS Group found is "+name
			
			if "." in name:
				ldapgroup=ldappath(temp1[1])
				name=checkad(ldapgroup)
				print "Matched AD Group is "+name	
		
				usermember=aduser.get_attribute("memberOf")
				status=adgrp(usermember,name)
				ifprocess=1
				if status==0:
					print "STATUS: START IF statenent. User is member of group so drives mapped.."
					print
			else:
				print "STATUS: Group Not Found in AD"
				status=1
				ifprocess=1
				print "\n"
				
		if ifprocess==1 and status<>0 and "map" in temp.lower():
			print "STATUS: Failed if check command not executed line "+str(count)
			continue		
		
		if ifprocess==1 and status==0 and "map" in temp.lower():
			temp=temp.lower().replace("map root","map")
			try:
				mapbits=temp.lower().split(" ")
				print mapbits[1]
				drive,path=checkpath(mapbits[1])
				print drive,path
				if path.lower()=="%home_directory":
					path=homedir[0]
				status=drvmap(drive,path)
			except:
				errorlog("Drive Map Failed Inside IF",count)
				continue
			
		if ifprocess==0 and "map" in temp.lower():
			
			temp=temp.lower().replace("map root","map")
			try:
				mapbits=temp.lower().split(" ")
			
				drive,path=checkpath(mapbits[1])
				print drive,path
				#if path.lower()=="%home_directory":
					#path=homedir[0]
				path=sub(path)
				status=drvmap(drive,path)
				#sys.exit()
			except:
				errorlog("Drive Map Failed Outside IF",count)
		
		if "end".lower() in temp.lower():
			ifprocess=0
			status=0
			print "STATUS: ENDIF Statement"
			print "\n"
	
		if "include" in temp.lower():
			ndap=temp.split(" ")[1]
			ldapobj=ldappath(ndap)
			ldapobj=ldapobj.replace("cn=,","")
			print "\n"
			print "STATUS: Running Include from " +ldapobj
			status=inc("ldaps://"+edir[0],"include "+ldapobj,edir[1],edir[2])
			print "\n"
		if "#" == temp[0:1]:
			print "STATUS: Running external script"
			cmdline=temp[1:].replace("\n","")
			stat=os.system(cmdline)
			if stat<>0:
				errorlog("Script Returned an Error State",count)
				#print "ERROR: Script returned an Error State"
		count=count+1
			

	print "\n"
	print "Script Processing Finished"
	print "\n"

	return

def userlscript():
	"""Running the Users Login Script as a File in the AD Home Directory userslogin.scr"""
	
	if homedir=="" or homedrive=="":
		print "STATUS: No Home Folder or Home Drive Letter Set"
	lscr=homedrive[0]+"\\userlogin.scr"
	if os.path.isfile(lscr):
		print
		print "STATUS: Running User Login Script"
		print 
		loc=open(lscr,"r").read()
		loc=loc.replace("\r","")
		lscriptrans3(loc)
		return(0)
	else:
		print
		print "STATUS: No User Login Script Found"
		print 
		return(1)
	

def pad(key):
	if len(key)>8:
		padl=16
	else:
		padl=8
	key=key+" "*(padl-len(key))
	#print key,":"
	#print len(key)
	return(key)

def encrypt(pw,key1):
	print pw,key1
	print key1
	obj=DES.new(key1,DES.MODE_ECB)
	ciph=obj.encrypt(pw)
	return (ciph)

def decrypt(pw,key):
	obj=DES.new(key,DES.MODE_ECB)
	pw=obj.decrypt(pw)
	pw=pw.replace(" ","")
	return(pw)


def listdrives():
	drives = win32api.GetLogicalDriveStrings()
	drives = drives.split('\000')[:-1]
	print drives
	return drives
	

def chunc(pth):
	"""Convert from Old Style to UNC Path in Login Script"""
	pth1=pth.split("/")
	server=pth1[0]
	vol=pth1[1].split(":")
	ptemp=""
	for temp in vol:
		ptemp=ptemp+"\\"+temp
	unc="\\\\"+server+ptemp
	unc=unc[0:-2]
	return unc

def edirconf(ldapsrvr,basedn,user,pw):
	"""Read from edir O config info """
	try:
		confitems=findos(ldapsrvr,basedn,user,pw)
	except:
		print "ERROR: No NSS Config Data"
		sys.exit(-1)
	
	for temp in confitems:
		volume=temp[1]["nssADvols"]
		groups=temp[1]["nssADgrps"]

	return groups,volume

def dnslookup(address):
	"""Lookup DNS Name from IP Address"""
	try:
		temp=socket.gethostbyaddr(address)
		return(temp[0])
	except:
		print "ERROR: No DNS Name Found"
		return("error")
		
def checkip(address):
	"""Check format of IP Address"""
	try:
		IP(address)
		return 0
	except:
		return -1

def checkpath(unc):
	"""Check UNC Path"""
	temp=unc.split(":=")
	return(temp[0],temp[1])

def mapDrive(drive, networkPath, user, password, force=0):
    if (os.path.exists(drive)):
        print "STATUS: "+drive, "Drive in use, trying to unmap..."
        if force:
            try:
                win32wnet.WNetCancelConnection2(drive, 1, 1)
                print "STATUS: "+drive, "successfully unmapped..."
            except:
                print "STATUS: "+drive, "Unmap failed, This might not be a network drive..."
                return -1
        else:
            print "STATUS: Non-forcing call. Will not unmap..."
            return -1
    else:
        print "STATUS: "+drive, ": drive is free..."
    if (os.path.exists(networkPath)):
        print "STATUS: "+networkPath, " is found..."
        print "STATUS: Trying to map ", networkPath, " on to ", drive, " ....."
        try: 
			win32wnet.WNetAddConnection2(win32netcon.RESOURCETYPE_DISK, drive, networkPath, None, user, password)
        except:
			print "ERROR: Mapping error"
			return -1
        print "STATUS: Mapping successful"
        return 0
    else:
        print "ERROR: Network path unreachable..."
        return -1


def ldappath(path):
	""" Split and create an ldap path for object named with CN"""
	parts=path.split(".")
	# print len(parts)
	# print parts
	i=len(parts)
	# print i
	i=i-1
	newpath=""
	first="cn="+parts[0]+","
	last="o="+parts[i]
	for c in range(1,i):
		# print c
		newpath=newpath+"ou="+parts[c]+","
		# print newpath
	finalpath=first+newpath+last
	#print finalpath
	return(finalpath)

def checkad(groupname):
	x=0
	grp=xmlparse(nurm)
	for line in grp:
		#print line
		#print "---"
		if line[0]==groupname:
			x=1
			return line[1]
	if x==1:
		print "No Matching Edir Group Found"
		return("EDIR-NEEDS REPLACING-"+groupname)
			

def ndap(ldap):
	""" Convert LDAP Path to NDAP"""
	temp=ldap.split(",")
	newpath=""
	for lines in temp:
		lines=lines.replace("cn=","")
		lines=lines.replace("ou=","")
		lines=lines.replace("o=","")
		newpath=newpath+"."+lines
	return(newpath)
		
		
	
def search(xml,tag,offset=0):
	"""Search XML Fragment for named tag"""
	xmltemp=xml.getElementsByTagName(tag)[offset]
	xmlval=xmltemp.childNodes[0].data
	return xmlval
	
def xmlparse(fname):
	"""Parse XML File Created by Norm"""
	grplist=[]
	fname=fname[0]
	
	#print "xml parse called"
	#xmldoc = minidom.parse(fname)
	xmldoc=minidom.parseString(fname)
	ftype=search(xmldoc,"type")
	#filetype=xmldoc.getElementsByTagName('type')[0]
	#ftype=filetype.childNodes[0].data
	if ftype <> "group2group":
		print "ERROR: Wrong Type of NURM File"
	itemlist = xmldoc.getElementsByTagName('userPair')
	for temp in itemlist:
		
		src=search(temp,"dn")
		tar=search(temp,"sAMAccountName",1)
		#print src,tar
	 	#print ndap(src)
		
		#print "Edir Group is "+src+" AD Group is "+tar
		temp=[src,tar]
		grplist.append(temp)
		
	
	return grplist
	



def ldapreplace(ldapsrv,user,passw,dn,attr,value):
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
            print e
        sys.exit()
    mod_attrs=[( ldap.MOD_REPLACE, attr,value)]
    try:
    	status=l.modify_s(dn,mod_attrs)
    except ldap.TYPE_OR_VALUE_EXISTS:
        print "Value Already set against group "
    except ldap.INVALID_DN_SYNTAX:
        print "Invalid DN !!"
    l.unbind()
    # print status
    return


def ldapcr(srv,user,passw,name,dn,attrs,naming):
        print "-"*70
        l=ldap.initialize(srv)
        try:
		l.bind_s(user, passw)
	except ldap.INVALID_CREDENTIALS:
		print "Your username or password is incorrect."
		sys.exit()
	except ldap.LDAPError, e:
		if type(e.message) == dict and e.message.has_key('desc'):
			print e.message['desc']
		else:
			print e
			sys.exit()
	try:
		print name,dn,naming
		value = l.compare_s(dn,naming,name[0])
		print value
		if value==1:
			print "Object Already Exists"
			objectpresent="yes"
	except ldap.NO_SUCH_OBJECT:
		print "Object not Found So create new object"
		print "Before Add Record ***"
		try:
			ld=modlist.addModlist(attrs)
			print ld,dn
			l.add_s(str(dn),ld)
		except:
			print "ERROR In Create"
	status=0
	return(status)

def findos(ldapsrv,base_dn,user,passw):
	
	ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
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
	attrs = ['O','objectclass','nssADgrps','nssADvols']
	filter='(objectclass=nssADconf)'
	grplist=l.search_s( base_dn,ldap.SCOPE_SUBTREE,filter,attrs)
	return(grplist)




def findusers(ldapsrv,base_dn,user,passw):
	print ldapsrv
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
	attrs = ['CN','loginTime']
	filter='(objectclass=inetOrgPerson)'
	attrs = ['cn','objectClass','sn','description','fullName','givenName','groupMembership','ou','ndsHomeDirectory']
	grplist=l.search_s( base_dn,ldap.SCOPE_SUBTREE,filter,attrs)
	return(grplist)
	
def namedgroups(ldapsrv,base_dn,grpname,user,passw):
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

     attrs = ['cn','objectClass','ACL']
     filter=('(&(objectclass=groupOfNames)(cn='+grpname+'))')
     grplist=l.search_s( base_dn,ldap.SCOPE_SUBTREE,filter,attrs)
     return(grplist)	
	
def findgroups(ldapsrv,base_dn,user,passw):
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

     attrs = ['cn','objectClass','ACL']
     filter=('(objectclass=groupOfNames)')
     grplist=l.search_s( base_dn,ldap.SCOPE_SUBTREE,filter,attrs)
     return(grplist)	


def findous(ldapsrv,base_dn,user,passw):
	#print base_dn
	#print ldapsrv
	ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
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
	attrs = ['ou','objectClass','description','loginScript']
	filter='(&(objectclass=*)(loginScript=*))'
	objlist=l.search_s( base_dn,ldap.SCOPE_SUBTREE,filter,attrs)
	return(objlist)

def dotted(dn):
	newtemp=[]
	dntemp=dn.split(",")
	#print dntemp
	for line in dntemp:
		#print line[0:3]
		#print line[0:2]
		if line[0:3]=="ou=":
			newtemp.append(line.replace("ou=","."))
		if line[0:2]=="o=":
			newtemp.append(line.replace("o=","."))
	#print newtemp
	newdn="".join(newtemp)
	newdn=newdn[1:]
	return (newdn)
	
def makeunc(path,dns):
	print "Source Path: "+path
	if ":" not in path and "\\" in path:
		print "No leading \ but unc"
		print "Old Path: "+path
		srv=path.split("\\")
		srv1=srv[0]
		pth=srv[1]
		path="\\\\"+srv1+"."+dns+"\\"+pth
		print "Mew Path: "+path
		return(path)
	if path[0:2]=="\\\\":
		print "UNC Path Found"
		return(path)
	if "/" in path:
		temp=path.split("/")
		#print len(temp)
		srv=temp[0]
		path=temp[1].split(":")
		
		unc1="\\\\"+srv+"."+dns+"\\"+path[0]+"\\"+path[1]
	if "\\" in path:
		temp=path.split("\\")
		# print len(temp)
		srv=temp[0]
		path=temp[1].split(":")
		#print temp
		sys.exit()
		unc1="\\\\"+srv+"."+dns+"\\"+path[0]+"\\"+path[1]
		print unc1
	return(unc1)

def groupname(dn):
	#print "dn: "+dn
	if "." not in dn:
		print "Just Group Name Passed"
		return(dn)
	temp2=dn.split(".")
	cn=temp2[0]
	cn=cn.replace("cn=","")
	cn=cn.replace("CN=","")
	cn=cn.replace(".","")
	return(cn)

def checkad(groupname):
	x=0
	grp=xmlparse(nurm)
	for line in grp:
		#print line
		#print "---"
		if line[0]==groupname:
			x=1
			return line[1]
	if x==1:
		print "No Matching Edir Group Found"
		return(groupname)
			
def adgrp(grps,name):
	"""Check AD Group Membership"""
	for temp in grps:
		#print temp
		#print "cn="+name
		if "cn="+name.lower() in temp.lower():
			print "User is a member of "+name
			status=0
			return(status)
	status=1
	print "STATUS: User is not a member of Group"
	return(status)


def connect():
	"""Establish Current logged in Name of User"""
	user=os.environ["USERNAME"]
	domain=os.environ["USERDOMAIN"]
	domain=pad(domain)
	
	
	user1=getusername()
	if user1=="error":
		print "STATUS: short user is correct"
	else:
		user=user1
	#print "user "+user
		
	adhandle=aduser.ADUser.from_cn(user)
	#print adhandle	
	#print adhandle.adsPath
	print "STATUS: Connected as User "+user
	ad1=aduser.ADUser.from_cn("proxy ldap")
	edir=ad1.Description.split(" ")
	#print edir
	return edir,adhandle


def drvmap(drive,path):
	"""Drive Mapping Helper Function"""
	print "\n"
	print "Mapping Drive "+drive+": to "+path
	print "==========================================="
	if "/" in path:
		path=chunc(path)
	
	found=0
	
	path1=path
	path1=path1.replace("."+suffix,"")
	#print path1
		
	

	if "\\" in path:
		server1=path.split("\\")
		server=server1[2]
		servertemp=server
		status=checkip(server)
		
		if status==0:
			print "Change IP Address to DNS Name"
			dns=dnslookup(server)
			#dns="oes-2015.ds.com"
			server=dns
			path1="\\\\"+dns+"\\"+server1[-1]
			drvpath=path.replace("\\\\"+servertemp+"\\","")
			
			
			
		if status==-1:
			print "Sever Name Not IP Address"
			if "." not in server:
				server=server+"."+suffix
			
			drvpath=path.replace("\\\\"+servertemp+"\\","")
			
		#print drive
		#print server
		
		
		for temp in volumes:
			path2=path1.replace("."+suffix,"")
			if temp in path2:
				found=1
	
		if found==0:
			print "\n"
			print "STATUS: NSSAD Volume Not Found"
			print "STATUS: "+path1+" Not found as configured for NSSAD"
			print "===================================================="
			print "\n"
			found=0
			return -1
		print
		mapDrive(drive+":", "\\\\"+server+"\\"+drvpath, None, None,force=1)
		print
		return 0
	elif "/" in path:
		print "Old Path conversion"
		print "Path is "+path
		unc=chunc(path)
		mapDrive(drive+":", unc,None,None,force=1)
		print 
		return 0

def getusername():
	try:
		explorer = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI")
		value, type = _winreg.QueryValueEx(explorer, "LastLoggedOnDisplayName")
	except:
		value="error"
	return value
	
	

def getLocalDomainSuffix():
	"""Gets local machines DNS Suffix"""
	explorer = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,r"SYSTEM\CurrentControlSet\Services\TCPIP\Parameters")
	value, type = _winreg.QueryValueEx(explorer, "NV Domain")
	#print value,type
	return value
	
def inc(psrv,cmd,user,pw):
	#print psrv
	ldapsrv=psrv
	"""Code for dealing with login script includes"""
	cmds=cmd.split(" ")
	#print cmds
	if cmds[0].lower()<>"include":
		print "include not found"
		return -1
	#print cmds[1]
	#print ldapsrv,cmd[1],user,pw
	lscript=findous(ldapsrv,cmds[1],user,pw)
	
	if len(lscript)==0:
		errorlog("Include File Not Found in EDIR",count)
		return -1
	for temp in lscript:
		scr=temp[1]["loginScript"][0]
	if len(scr)<>0:
		print "STATUS: Include Script being executed"
		print "\n"
		lscriptrans1(scr)
	 
def lscriptrans(script1):
	status=0
	ifprocess=0
	cmds=script1.split("\r\n")
	scriptproc(cmds)
	userlscript()
	print "\n"
	print "STATUS:Login Script Processing Finished"
	print "\n"

	return





def lscriptrans1(lscript):
	"""Function to process login script includes"""
	ifprocess=0
	cmds=lscript.split("\r\n")
	scriptproc(cmds)
	print "\n"
	print "STATUS: Include Login Script Processing Finished"
	print "\n"
	return

def lscriptrans3(script1):
	"""Processing of user login script"""
	ifprocess=0
	cmds=script1.split("\n")
	
	#cmds=scr.split("\r\n")
	scriptproc(cmds)		

	print "\n"
	print "STATUS: User Login Script Processing Finished"
	print "\n"

	return




excluded_commands=["map display","map errors","map ins","no_default"]

parser = OptionParser()

parser.add_option("-d","--dn",help="Edir Login Script")
parser.add_option("-n","--nurm",help="NURM XML Group File Path")
parser.add_option("-c","--conf",help="Config in EDIR")



(options, args) = parser.parse_args()


required=["dn","conf"]

for m in required:
	if not options.__dict__[m]:
		#print m
		print "Mandatory option is missing\n"
		parser.print_help()
		sys.exit(-1)


option={"%cn":"",
"%language":"",
"%login_name":"",
"%os":"",
"%file_server":"",
"%network_address":"",
"%home_directory":"",}

option=optsetup(option)

status=0
nurm=options.nurm
dn=options.dn
suffix=getLocalDomainSuffix()
edir,aduser=connect()
conf=options.conf
logloc=os.getenv("TEMP")+"\\lscript.log"


#confitems=findos("ldap://"+edir[0]+":389",conf,edir[1],edir[2])
nurm,volumes=edirconf("ldaps://"+edir[0],conf,edir[1],edir[2])
if len(nurm)==0 or len(volumes)==0:
	errorlog("No Configuration Information in EDIR",0)
	#print "ERROR: No Configuration Information in EDIR"
	sys.exit(-1)


os.system("cls")
ver="0.5"
print "LOGON SCRIPT PROCESSOR\t"+ver
print "\n"
print "LDAP Server is \t\t"+edir[0]+":636"
print "User Proxy is \t\t"+edir[1]
print "AD DNS Suffix \t\t"+suffix
print "EDIR CONF \t\t"+conf
print "AD User is \t\t"+os.getenv("USERNAME")
print "Log File location \t"+logloc

errors=open(logloc,"w")
grp=xmlparse(nurm)

print "\n"
homedir=aduser.get_attribute("homeDirectory")
homedrive=aduser.get_attribute("homeDrive")

lscript=findous("ldaps://"+edir[0],dn,edir[1],edir[2])
l=len(lscript)
if l==0:
	errorlog("No Login Script Found in EDIR",0)
	sys.exit()
ifprocess=0
print "STATUS: Processing Novell Login Script"
print
for temp in lscript:
	scr=temp[1]["loginScript"][0]

lscriptrans(scr)

sys.exit()
		
		







