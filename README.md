# nwscript
Login Script Translation on the fly from Edir to AD

Introduction
=============

This code is designed for OES2015 and to allow AD clients with no novell software to run where possible the existing novell login scripts. This should be considered aplha code at this stage.

This code is written in Annaconda Python 2.7 and is compiled using pyinstaller to make the exe.

Installation
==============

So the first step for the installation is the addition of the schema file to edir. This is an AUX class to be added ot an O object at the top of the tree. This object has two attributes in called ...

nssadgrps
assadvols

nssadvols holds a list of nssad volumes in the form of unc paths such as \\server.x.x.x\volume. This is a multi valued object.
nssadgrps holds an xml export od the group mappings between AD and EDIR. This was created and exported from the NURM utility and the resulting file is pasted in to this attribute.

From the AD side a user called "ldap proxy" needs to be created. The password that is set is not relavant. The description of this field needs to hold the following info:

1) Edir Server DNS Names such as "oes.ds.com"

2) User Name to act to act as proxy for the edir ldap server. Since the password is not currently secured this user needs to have limited rights to edir. So only read rights to the CN and the Login Script property through the tree.

3)Password for that user.

So the description for that user needs to show the following "oes.ds.com cn=ldapproxy,o=home password" with the fields being changed to match your enviroment.

Usaage
=======

nwscipt.exe is requried to e copied to (Assume domain is "ds.com) \\ds.com\netlogon\nwscipt.exe on a DC in the domain. This DC wil then replicate this file round the domain. Within this location there needs to be a login script that this utility ican be appended to. This utility can be executed by :

nwscipt.exe -d ou=xx,o=xx -c o=xx

The -d parameter refers to the DN in ldap of the object that holds the login script.
The -c parameter refers to the config object aux class that is assigned to the o of the tree.

Limitations
============
1) Will not support changing search drives. Makes no sense to replicate.
2) Will support includes to directory objects not includes to filess

