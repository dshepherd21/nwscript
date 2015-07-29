# nwscript
Login Script Translation on the fly from Edir to AD

So the first step for the installation is the addition of the schema file. This is an AUX class to be added ot an O object at the top of the tree. This object has two attributes in called ...

nssadgrps
assadvols

nssadvols holds a list of nssad volumes in the form of unc paths such as \\server.x.x.x\volume. This is a multi valued object.
nssadgrps holds an xml export od the group mappings between AD and EDIR. This was created and exported from the NURM utility and the resulting file is pasted in to this attribute.

Under 

nwscipt.exe is requried to e copied to (Assume domain is "ds.com) \\ds.com\netlogon\nwscipt.exe on a DC in the domain. This DC wil then replicate this file round the domain. Within this location there needs to be a login script that this utility ican be appended to. This utility can be executed by :

nwscipt.exe -d ou=xx,o=xx -c o=xx

The first 

