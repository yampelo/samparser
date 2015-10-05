# samparser
A python script used to parse the SAM registry hive. 

10/5/2015 update:
	Can now parse groups as well

Depends on python-registry
```
pip install python-registry
```

Input is a sam registry hive.

```
python samparse.py <hive>
```

Sample output (Tested on the SAM hive from http://digitalcorpora.org/corpora/scenarios/m57-jean)

```
----- Administrator -----
Comment : Built-in account for administering the computer/domain
Account Type : Default Admin User
RID : 500
Account Created Date : 13 May 2008 - 22:20:14
Last Login Date : 21 July 2008 - 01:22:18
Password Reset Date : 13 May 2008 - 22:23:39
Password Fail Date : Never
Account Flags : Password does not expire | Normal user account |
Failed Login Count : 0
Login Count : 24


----- Guest -----
Comment : Built-in account for guest access to the computer/domain
Account Type : Default Guest Acct
RID : 501
Account Created Date : 13 May 2008 - 22:20:14
Last Login Date : Never
Password Reset Date : Never
Password Fail Date : Never
Account Flags : Password does not expire | Account Disabled | Password not required | Normal user account |
Failed Login Count : 0
Login Count : 0


----- HelpAssistant -----
Full Name : Remote Desktop Help Assistant Account
Comment : Account for Providing Remote Assistance
Account Type : Custom Limited Acct
RID : 1000
Account Created Date : 13 May 2008 - 21:24:45
Last Login Date : Never
Password Reset Date : 13 May 2008 - 21:24:45
Password Fail Date : Never
Account Flags : Password does not expire | Account Disabled | Normal user account |
Failed Login Count : 0
Login Count : 0


----- SUPPORT_388945a0 -----
Full Name : CN=Microsoft Corporation,L=Redmond,S=Washington,C=US
Comment : This is a vendor's account for the Help and Support Service
Account Type : Custom Limited Acct
RID : 1002
Account Created Date : 13 May 2008 - 21:25:56
Last Login Date : Never
Password Reset Date : 13 May 2008 - 21:25:56
Password Fail Date : Never
Account Flags : Password does not expire | Account Disabled | Normal user account |
Failed Login Count : 0
Login Count : 0


----- Kim -----
Full Name : Kim
Account Type : Default Admin User
RID : 1003
Account Created Date : 14 May 2008 - 05:32:56
Last Login Date : Never
Password Reset Date : Never
Password Fail Date : Never
Account Flags : Password does not expire | Normal user account |
Failed Login Count : 0
Login Count : 0


----- Jean -----
Full Name : Jean
Account Type : Default Admin User
RID : 1004
Account Created Date : 14 May 2008 - 05:33:08
Last Login Date : 20 July 2008 - 00:00:41
Password Reset Date : Never
Password Fail Date : Never
Account Flags : Password does not expire | Normal user account |
Failed Login Count : 0
Login Count : 80


----- Addison -----
Full Name : Addison
Account Type : Default Admin User
RID : 1005
Account Created Date : 14 May 2008 - 05:34:03
Last Login Date : Never
Password Reset Date : Never
Password Fail Date : Never
Account Flags : Password does not expire | Normal user account |
Failed Login Count : 0
Login Count : 0


----- Abijah -----
Full Name : Abijah
Account Type : Default Admin User
RID : 1006
Account Created Date : 14 May 2008 - 05:34:43
Last Login Date : Never
Password Reset Date : Never
Password Fail Date : Never
Account Flags : Password does not expire | Normal user account |
Failed Login Count : 0
Login Count : 0


----- Devon -----
Full Name : Devon
Account Type : Default Admin User
RID : 1007
Account Created Date : 14 May 2008 - 05:34:54
Last Login Date : 12 July 2008 - 03:02:47
Password Reset Date : Never
Password Fail Date : Never
Account Flags : Password does not expire | Normal user account |
Failed Login Count : 0
Login Count : 4


----- Sacha -----
Full Name : Sacha
Account Type : Default Admin User
RID : 63
Account Created Date : 14 May 2008 - 05:35:35


----- Administrators -----
Group Description : Administrators have complete and unrestricted access to the computer/domain
Last Write : 2008-05-14 05:35:35.281248
User Count : 7
Memebers : S-1-5-21-484763869-796845957-839522115-500
S-1-5-21-484763869-796845957-839522115-1003
S-1-5-21-484763869-796845957-839522115-1004
S-1-5-21-484763869-796845957-839522115-1005
S-1-5-21-484763869-796845957-839522115-1006
S-1-5-21-484763869-796845957-839522115-1007
S-1-5-21-484763869-796845957-839522115-1008



----- Users -----
Group Description : Users are prevented from making accidental or intentional system-wide changes.  Thus, Users can run certified applications, but not most legacy applications
Last Write : 2008-05-14 05:35:35.265625
User Count : 8
Memebers : S-1-5-4
S-1-5-11
S-1-5-21-484763869-796845957-839522115-1003
S-1-5-21-484763869-796845957-839522115-1004
S-1-5-21-484763869-796845957-839522115-1005
S-1-5-21-484763869-796845957-839522115-1006
S-1-5-21-484763869-796845957-839522115-1007
S-1-5-21-484763869-796845957-839522115-1008



----- Guests -----
Group Description : Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
Last Write : 2008-05-13 22:20:14.812498
User Count : 1
Memebers : S-1-5-21-484763869-796845957-839522115-501



----- Power Users -----
Group Description : Power Users possess most administrative powers with some restrictions.  Thus, Power Users can run legacy applications in addition to certified applications
Last Write : 2008-05-13 22:20:14.812498
User Count : 0
Memebers : No users in this group


----- Backup Operators -----
Group Description : Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
Last Write : 2008-05-13 22:20:14.812498
User Count : 0
Memebers : No users in this group


----- Replicator -----
Group Description : Supports file replication in a domain
Last Write : 2008-05-13 22:20:14.812498
User Count : 0
Memebers : No users in this group


----- Remote Desktop Users -----
Group Description : Members in this group are granted the right to logon remotely
Last Write : 2008-05-13 22:20:14.828125
User Count : 0
Memebers : No users in this group


----- Network Configuration Operators -----
Group Description : Members in this group can have some administrative privileges to manage configuration of networking features
Last Write : 2008-05-13 22:20:14.828125
User Count : 0
Memebers : No users in this group


```
