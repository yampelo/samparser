# samparser
A python script used to parse the SAM registry hive. 

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


----- Sacha -----
Full Name : Sacha
Account Type : Default Admin User
RID : 63
Account Created Date : 14 May 2008 - 05:35:35
```
