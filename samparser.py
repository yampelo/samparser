#Ok this one is a bit more diffuclt. ALL the data in here is in Binary data which means we need to unpack all of it.
#The SAM file is structed like this
#0000123F
	#F - Contains binary data
	#V - Contains binary data
#0000234F
	#F - Contains binary data
	#V - Contains binary data

#The things that start with 000000 Correlate with each user on the computer while the F and V contain different data
#F contains type of account, and various account settings
#V contains username, fullname, comment, password hashes and more
#We have to individually parse both the F and V for every user.
f_values = {} 	#Used to temp store F Data before we get V Value data

#ACB Flags which tell us if the account is disabled/etc
acb_flags = {0x0001 : "Account Disabled",
		0x0002 : "Home directory required",
		0x0004 : "Password not required",
		0x0008 : "Temporary duplicate account",
		0x0010 : "Normal user account",
		0x0020 : "MNS logon user account",
		0x0040 : "Interdomain trust account",
		0x0080 : "Workstation trust account",
		0x0100 : "Server trust account",
		0x0200 : "Password does not expire",
		0x0400 : "Account auto locked"}

#Account Types
types = {0xbc : "Default Admin User",
	0xd4 : "Custom Limited Acct",
	0xb0 : "Default Guest Acct"}
usersRoot = self.sam.open("SAM\\Domains\\Account\\Users")
for x in usersRoot.subkeys():
	#We Use this to get the account name and timestamp
	if x.name() == "Names":
		for a in x.subkeys():
			self.out['users'][a.name()]['Account Information']['Account Created Date'] = a.timestamp().strftime('%d %B %Y - %H:%M:%S')
	else:
		for a in x.values():
			#F comes before V, and since we're using usernames, F will store in a temporary dict
			#F Comes in binary data aswell
			#For unpacking this is the formatting
				# x = padded null bytes (\00x)
				# L = Unsigned long (32bit) in little-endian
				# H = Unsigned short (16bit) in little-endian
			#Bytes 8-15 Last Login Date
			#Bytes 24-31 Date password was last reset
			#Bytes 32-39 Account expiration date
			#Bytes 40-47 Last failed login attempt
			if a.name() == "F":
				b = struct.unpack('<xxxxxxxxLLxxxxxxxxLLxxxxxxxxLLLxxxxHxxxxxxHHxxxxxxxxxxxx', a.value())
				f_values[b[6]] = [] #Create a List and sort by RID

				f_values[b[6]].append(self.getTime(b[0],b[1])) 	#Last Login Date
				f_values[b[6]].append(self.getTime(b[2],b[3]))	#This is password reset date
				f_values[b[6]].append(self.getTime(b[4],b[5]))	#PWD Fail Date maybe?
				flags = []
				for flag in acb_flags:							#Compare the two hex values and check if one goes in another using & logic gate
					if bool(flag & b[7]):
						flags.append(acb_flags[flag])
				f_values[b[6]].append(flags)
				f_values[b[6]].append(b[8])						#Failed Login Count
				f_values[b[6]].append(b[9])						#Login Count

			#Parsing the "V" Value
			#the first 4 bytes of each entry refer to the location of the entry relative to offset
			#the second 4 bytes refer to the entry length, rounded up to the nearest multiple of 4
			#for example the 4 bytes from 0x0c -> 0x10 contains the offset+0xcc(4) where the username is
			if a.name() == "V":
				data = a.value()

				#Unpacking The values, refrence here http://www.beginningtoseethelight.org/ntsecurity/index.htm
				account_type = struct.unpack("<L", data[4:8])[0]		#Only one i use which is not a "pointer"
				username_ofst = struct.unpack("<L", data[12:16])[0]
				username_lngth = struct.unpack("<L", data[16:20])[0]
				fullname_ofst = struct.unpack("<L", data[24:28])[0]
				fullname_lngth = struct.unpack("<L", data[28:32])[0]
				comment_ofst = struct.unpack("<L", data[36:40])[0]
				comment_lngth = struct.unpack("<L", data[40:44])[0]
				driveletter_ofst = struct.unpack("<L", data[84:88])[0]
				driveletter_lngth = struct.unpack("<L", data[88:92])[0]
				logonscript_ofst = struct.unpack("<L", data[96:100])[0]
				logonscript_lngth = struct.unpack("<L", data[100:104])[0]						
				profilepath_ofst = struct.unpack("<L", data[108:112])[0]
				profilepath_lngth = struct.unpack("<L", data[112:116])[0]
				workstations_ofst = struct.unpack("<L", data[120:124])[0]
				workstations_lngth = struct.unpack("<L", data[124:128])[0]
				# lmpwhash_ofset = struct.unpack("<L", data[156:160])[0]		LM Password Hash - Can't print this on web
				# lmpwhash_lngth = struct.unpack("<L", data[160:164])[0]
				# ntpwhash_ofset = struct.unpack("<L", data[168:172])[0]		NT Password Hash - Can't print on web
				# ntpwhash_lngth = struct.unpack("<L", data[172:176])[0]

				username = data[(username_ofst+0xCC):(username_ofst+0xCC + username_lngth)].replace('\x00','')

				self.out['users'][username] = OrderedDict()
				self.out['users'][username]['Account Information'] = OrderedDict()		# SO MANY DICTIONARIES?

				self.out['users'][username]['Account Information']['Full Name'] = data[(fullname_ofst+0xCC):(fullname_ofst+0xCC + fullname_lngth)]
				self.out['users'][username]['Account Information']['Comment'] = data[(comment_ofst+0xCC):(comment_ofst+0xCC + comment_lngth)]
				for acctype in types:
					if account_type == int(acctype):
						self.out['users'][username]['Account Information']['Account Type'] = types[acctype]
				self.out['users'][username]['Account Information']['RID'] = str(int(x.name().strip("0000"), 16)) #Since im converting hex to int, you need to tell python it's in base 16
				self.out['users'][username]['Account Information']['Drive Letter'] = data[(driveletter_ofst+0xCC):(driveletter_ofst+0xCC + driveletter_lngth)]
				self.out['users'][username]['Account Information']['Profile Path'] = data[(profilepath_ofst+0xCC):(profilepath_ofst+0xCC + profilepath_lngth)]
				self.out['users'][username]['Account Information']['Logon Script'] = data[(logonscript_ofst+0xCC):(logonscript_ofst+0xCC + logonscript_lngth)]
				self.out['users'][username]['Account Information']['Workstations'] = data[(workstations_ofst+0xCC):(workstations_ofst+0xCC + workstations_lngth)]
				# self.out['users'][username]['Account Information']['LM Password Hash'] = data[(lmpwhash_ofset+0xCC):(lmpwhash_ofset+0xCC + lmpwhash_lngth)]	!- Cant Print -!
				# self.out['users'][username]['Account Information']['NT Password Hash'] = data[(ntpwhash_ofset+0xCC):(ntpwhash_ofset+0xCC + ntpwhash_lngth)]	!- Cant Print -!

				continue
#Now we combine the two!
for RID in f_values:
	for user in self.out['users']:
		if self.out['users'][user]['Account Information']['RID'] == str(RID):
			self.out['users'][user]['Account Information']['Last Login Date'] = f_values[RID][0]
			self.out['users'][user]['Account Information']['Password Reset Date'] = f_values[RID][1]
			self.out['users'][user]['Account Information']['Password Fail Date'] = f_values[RID][2]
			self.out['users'][user]['Account Information']['Account Flags'] = ""			#Gotta do this for the next step
			for flag in f_values[RID][3]:
				self.out['users'][user]['Account Information']['Account Flags'] += (flag + " | ")
			self.out['users'][user]['Account Information']['Failed Login Count'] = f_values[RID][4]
			self.out['users'][user]['Account Information']['Login Count'] = f_values[RID][5]
			break