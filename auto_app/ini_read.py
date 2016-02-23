#-*- encoding: utf-8 -*-
#废弃
import ConfigParser
import string, os, sys
cf = ConfigParser.ConfigParser()
cf.read("../conf/conf.ini")
# 返回所有的section
s = cf.sections()
print 'section:', s

o = cf.options("zabbix_db")
print 'options:', o

v = cf.items("zabbix_db")
print 'db:', v

# print '-'*60
# #可以按照类型读取出来
# db_host = cf.get("db", "db_host")
# db_port = cf.getint("db", "db_port")
# db_user = cf.get("db", "db_user")
# db_pass = cf.get("db", "db_pass")



# print "db_host:", db_host
# print "db_port:", db_port
# print "db_user:", db_user
# print "db_pass:", db_pass




# threads = cf.getint("concurrent", "thread")
# processors = cf.getint("concurrent", "processor")

# print "thread:", threads
# print "processor:", processors



# cf.set("db", "db_pass", "chenmeng")
# cf.write(open("conf.ini", "w"))

# print '-'*60
## 可#以按照类型读取出来
# db_host = cf.get("db", "db_host")
# db_port = cf.getint("db", "db_port")
# db_user = cf.get("db", "db_user")
# db_pass = cf.get("db", "db_pass")



# print "db_host:", db_host
# print "db_port:", db_port
# print "db_user:", db_user
# print "db_pass:", db_pass