# nwscript
Login Script Translation on the fly from Edir to AD

Introduction
=============

This code is designed for OES2015SP1 and to allow AD clients with no novell software to run where possible the existing novell login scripts. This should be considered aplha code at this stage.

This code is written in Annaconda Python 2.7 and is compiled using pyinstaller to make the exe.

Installation
==============
An LDIF file is provided to add to an existing tree and is called nssad.ldif.

So the first step for the installation is the addition of the schema file to edir. This is an AUX class to be added ot an Organisation object at the top of the tree. This object has two attributes in called ...

nssadgrps
nssadvols

The nssad.ldif needs to be added to the schema of the edirectory tree. This can be done through both ConsoleOne and iManager. Within iManager select eDirectory Maintenance and then "Import Convert Export Wizard". Using this tool the ldif file can be added to the schema. Once added the "Organisation" needs to be extended using the "Schema", "Object Extensions" option. Using the "add" option look for the nssADconf. Once added the "O" class will gain 2 extra attributes:

nssadgrps
nssadvols

nssadvols holds a list of nssad volumes in the form of unc paths such as \\server.x.x.x\volume. This is a multi valued object.
nssadgrps holds an xml export od the group mappings between AD and EDIR. This was created and exported from the NURM utility and the resulting file is pasted in to this attribute.

From the AD side a user called "proxy ldap" needs to be created. The password that is set is not relavant. The description of this field needs to hold the following info:

1) Edir Server DNS Names such as "oes.ds.com".This would be changed to match you ldap server running on OES.

2) User Name to act to act as proxy for the edir ldap server. Since the password is not currently secured this user needs to have limited rights to edir. So only read rights to the CN and the Login Script property through the tree.

3)Password for that user.

So the description for that user needs to show the following "oes.ds.com cn=ldapproxy,o=home password" with the fields being changed to match your enviroment.

Usage
=======

nwscipt.exe is requried to e copied to (Assume domain is "ds.com) \\ds.com\netlogon\nwscipt.exe on a DC in the domain. This DC wil then replicate this file round the domain. Within this location there needs to be a login script that this utility ican be appended to. This utility can be executed by :

nwscipt.exe -d ou=xx,o=xx -c o=xx

The -d parameter refers to the DN in ldap of the object that holds the login script.
The -c parameter refers to the config object aux class that is assigned to the o of the tree.
the -v parameter (optional) allows verbose output and giex extra debugging information.

User Login Scripts
==================
Provided is an import routine that will take out the users edir personal login script and export it as a .scr file to the users home directory in AD.

Logging
=======

A log file is created in the temp directory.

Limitations
============
1) Will not support changing search drives. Makes no sense to replicate.
2) Will support includes to directory objects not includes to files
3) Will not currently support the use of volume objects in MAP commands as edir DNs (will work in future).
4) No support for Fire Phasers :-(
5) Some enviroment variables will now work such as %os, %home_directory.
6) Personal login scripts will work. Use the usersc.py file to export the users existing login scripts to a script file (.scr) that will be copied in to each AD users home folder. A users home folder needs to be set for this to work. The .scr file is then a text file that can edited and have exta lines added by any text editor.

