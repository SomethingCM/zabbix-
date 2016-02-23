#!/usr/bin/python
#coding:utf-8
import json
import urllib2
from urllib2 import URLError
import ConfigParser #读取配置文件调用的函数
import string, os, sys




class ZabbixTools:
    def __init__(self):
                                                                       
        # self.address = 'http://ip/zabbix/api_jsonrpc.php'
        # self.username = "Admin"
        # self.password = "admin"
        self.cf = ConfigParser.ConfigParser()
        self.cf.read("conf/conf.ini")#读取配置文件
        self.address = self.cf.get("zabbix_api", "url")
        self.username = self.cf.get("zabbix_api", "user")
        self.password = self.cf.get("zabbix_api", "password")                                                                    
        self.url = '%s/api_jsonrpc.php' % self.address
        self.header = {"Content-Type":"application/json"}
                                                                       
                                                                       
                                                                       
    def user_login(self):
        data = json.dumps({
                           "jsonrpc": "2.0",
                           "method": "user.login",
                           "params": {
                                      "user": self.username,
                                      "password": self.password
                                      },
                           "id": 0
                           })
                                                                       
        request = urllib2.Request(self.url, data)
        for key in self.header:
            request.add_header(key, self.header[key])
                                                                   
        try:
            result = urllib2.urlopen(request)
        except URLError as e:
            print "Auth Failed, please Check your name and password:", e.code
        else:
            response = json.loads(result.read())
            result.close()
            #print response['result']
            self.authID = response['result']
            return self.authID
    #获取报警信息                                                                       
    def trigger_get(self):
        data = json.dumps({
                           "jsonrpc":"2.0",
                           "method":"trigger.get",
                           "params": {
                                      "output": [
                                                "triggerid",
                                                "description",
                                                "priority",
												"lastchange"
                                                ],
                                      "filter": {
                                                 "value": 1
                                                 },
                                      "expandData":"hostname",
                                      "sortfield": "lastchange",
                                      "sortorder": "DESC"
                                    },
                           "auth": self.user_login(),
                           "id":2              
        })
                                                                       
        request = urllib2.Request(self.url, data)
        for key in self.header:
            request.add_header(key, self.header[key])
                                                                       
        try:
            result = urllib2.urlopen(request)
        except URLError as e:
            print "Error as ", e
        else:
            response = json.loads(result.read())
            result.close()
            issues = response['result']
            # content = ''
            # if issues:
                # for line in issues:
                    #print line
                    # content = content + "%s:%s\r\n" % (line['host'],line['description'])
            # print issues
            # return issues[:10]
            return issues[:50]
                                                                           
# if __name__ == "__main__":
    # t = ZabbixTools()
    # print t.trigger_get()
    # for i in  t.trigger_get():
		# print i
