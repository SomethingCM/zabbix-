#-*- coding:utf-8 -*-
"""
 Mysql Python

"""

import MySQLdb
#import pygal
import os
import time
#from pygal.style import CleanStyle

Myhost = "ip"
Myuser = "auto"
Mypasswd = "auto"
Myport = 3306
Mydb = "zabbix"
# MonHost="172.16.8.150"
# MonPort="%Gi1/0/23"
#aa = ""
def search_zabbix1(MonHost,MonPort):
	try:
		conn = MySQLdb.connect(host=Myhost,user=Myuser,passwd=Mypasswd,db=Mydb,port=Myport)
		cur = conn.cursor()
#		global aa
		cur.execute("select * from hosts where host='%s'" % (MonHost)) 
		numrows = int(cur.rowcount)
#		print numrows
		hostinfo = cur.fetchall()
		listhost = []
		listhost[:] = [list(i) for i in hostinfo]
		Zhostid = listhost[0][0]
		# print Zhostid,MonHost
		cur.execute("select * from items where hostid='%s' and name like '%s'" % (Zhostid,MonPort))
		iteminfo = cur.fetchall()
		listitem = list(iteminfo)
		listiteminfo = []
		listiteminfo[:] = [list(i) for i in listitem]

		itemid1 = listiteminfo[0][0]
		itemid2 = listiteminfo[1][0]
		cur.execute("select * from history_uint where itemid='%s' order by clock desc limit 30" % (itemid1))
		info1 = cur.fetchall()
		data1 = []
		data1[:] = [list(i) for i in info1]

		datalist1 = []
		datalist1[:] = [i[1:3] for i in data1]


		cur.execute("select * from history_uint where itemid='%s' order by clock desc limit 30" % (itemid2))
		info2 = cur.fetchall()
		data2 = []
		data2[:] = [list(i) for i in info2]
		datalist2 = []
		datalist2[:] = [i[1:3] for i in data2]
		
		for i in datalist2:
			if "172.16.8.200" in MonHost:
				i[0] = str(time.strftime("%H:%M", time.localtime(i[0])))
				i[1] = i[1]
			else:
				i[0] = str(time.strftime("%H:%M", time.localtime(i[0])))
				i[1] = i[1]/1024/1024

		for i in datalist1:
			if "172.16.8.200" in MonHost:
				i[0] = str(time.strftime("%H:%M", time.localtime(i[0])))
				i[1] = i[1]
			else:
				i[0] = str(time.strftime("%H:%M", time.localtime(i[0])))
				i[1] = i[1]/1024/1024
			

		data = []
		datalist2.reverse()
		datalist1.reverse()
		data.append(datalist2)
		data.append(datalist1)
		

		cur.close()
		conn.close()
		

		return data
		
	except MySQLdb.Error,e:
		print "Error %d:%s" % (e.args[0],e.args[1])
		
