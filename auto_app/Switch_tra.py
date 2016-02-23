#!/usr/bin/env python
#coding:utf-8
import json
import urllib2
from urllib2 import URLError
import sys,re,traceback
import threading, time
from db_connector import *
from auto_app import models
class Zabbix(object):
	def __init__(self):
		# based url and required header
		self.url = "http://192.168.45.237/zabbix/api_jsonrpc.php"
		self.header = {"Content-Type":"application/json"}
		self.keys = self.login()

	def login(self):
		# auth user and password
		data = json.dumps(
		{
		   "jsonrpc": "2.0",
		   "method": "user.login",
		   "params": {
		   "user": "Admin",
		   "password": "jd07_gm09"
		},
		"id": 0
		})
		# create request object
		request = urllib2.Request(self.url,data)
		for key in self.header:
			request.add_header(key,self.header[key])
		# auth and get authid
		try:
			result = urllib2.urlopen(request)
		except URLError as e:
			print "Auth Failed, Please Check Your Name AndPassword:",e.code
		else:
			response = json.loads(result.read())
			result.close()
			return response['result']
			
	def group_get(self):
		
		data = json.dumps(
		{
		   "jsonrpc":"2.0",
		   "method":"hostgroup.get",
		   "params":{
			   "output":["groupid","name"],
		   },
		   "auth":self.keys,
		   "id":1,
		})

		request = urllib2.Request(self.url,data)
		for key in self.header:
			request.add_header(key,self.header[key])
			# get host list
		try:
			result = urllib2.urlopen(request)
		except URLError as e:
			if hasattr(e, 'reason'):
				print 'We failed to reach a server.'
				print 'Reason:', e.reason
			elif hasattr(e, 'code'):
				print 'The server could not fulfill the request.'
				print 'Error code: ', e.code
		else:
			response = json.loads(result.read())
			result.close()
			# print "Number Of Hosts: ", len(response['result'])
			#print response
			for group in response['result']:
				# print group
				if group['name']=='Switch':
					return group['groupid']
				# print "Group ID:",group['groupid'],"\tGroupName:",group['name']
			# print response['result']
			# return response['result']

	def host_get(self):
		hostinfo = []
		groupinfo = self.group_get()
		# for group in groupinfo:
		data = json.dumps(
			{
			   "jsonrpc":"2.0",
			   "method":"host.get",
			   "params":{
				   "output":["hostid","name",'host'],
				   "groupids":groupinfo,
				   # "groupids":group['groupid'],
			   },
			   "auth":self.keys,
			   "id":1,
			})
			# create request object
		request = urllib2.Request(self.url,data)
		for key in self.header:
			request.add_header(key,self.header[key])
		# get host list
		
		try:
			result = urllib2.urlopen(request)
		except URLError as e:
			if hasattr(e, 'reason'):
				print 'We failed to reach a server.'
				print 'Reason: ', e.reason
			elif hasattr(e, 'code'):
				print 'The server could not fulfill the request.'
				print 'Error code: ', e.code
		else:
			response = json.loads(result.read())
			result.close()
			# print "Number Of Hosts: ", len(response['result'])
			for host in response['result']:
				# print "Host ID:",host['hostid'],"HostName:",host['name']
				hostinfo.append([host['hostid'],host['host']])
		
			# for line in  hostinfo:
				# print line[0],line[1],line[2],'\n'
		# print response['result']
		return hostinfo
			
			
			
	def item_info(self):
		iteminfo = []
		hostinfo = self.host_get()
		# print hostinfo
		for item in hostinfo:
			data = json.dumps(
			{
			   "jsonrpc":"2.0",
			   "method":"item.get",
			   "params":{
				   "output":["itemids","key_"],
				   "hostids":item[0],
			   },
			   "auth":self.keys,
			   "id":1,
			})
			# create request object
			request = urllib2.Request(self.url,data)
			for key in self.header:
				request.add_header(key,self.header[key])
			# get host list
			try:
				result = urllib2.urlopen(request)
			except URLError as e:
				if hasattr(e, 'reason'):
					print 'We failed to reach a server.'
					print 'Reason: ', e.reason
				elif hasattr(e, 'code'):
					print 'The server could not fulfill the request.'
					print 'Error code: ', e.code
			else:
				response = json.loads(result.read())
				result.close()
				# print "Number Of Hosts: ", len(response['result'])
				for host in response['result']:
					# print host['itemid'],host['key_']
					p = re.compile(r'if(\w+)Octets*')
					if p.match(host['key_']):
						# print "Host ID:",item[0],"HostName:",item[1],"itemid",host['itemid'],"key_",host['key_']
						iteminfo.append([item[0],item[1],host['itemid'],host['key_']])
					
		return iteminfo
		# with open('item1.txt','r+') as f:
			# for line in iteminfo:
				# f.write(json.dumps(line))
				# f.write('\n')
		# print len(iteminfo)
		# item_key = ["system.cpu.load[percpu,avg5]","vm.memory.size[available]","vfs.fs.size[/,free]"]
	def traffic_get(self,item):
		info = {}
		# l.acquire()
		# for ks,vs in v.items():
		time_e = time.time()
		time_s = time_e - 800
		data = json.dumps(
		{
		   "jsonrpc":"2.0",
		   "method":"history.get",
		   "params":{
			   "output":"extend",
			   "time_from":time_s,
				"time_till":time_e,
			   "history":3,
			   "itemids":item[2],
			   "limit":1
		   },
		   "auth":self.keys,
		   "id":2,
		})
		request = urllib2.Request(self.url,data)
		for key in self.header:
			request.add_header(key,self.header[key])
			# get host list				
		try:
			result = urllib2.urlopen(request)
		except URLError as e:
			# continue
			if hasattr(e, 'reason'):
				print 'We failed to reach a server.'
				print 'Reason: ', e.reason
			elif hasattr(e, 'code'):
				print 'The server could not fulfill the request.'
				print 'Error code: ', e.code
		else:
			if result:
				try:
					response = json.loads(result.read())
				except:
					response = {}
					# print traceback.format_exc()
				# print response['result']
			result.close()
		
		# if response:
			# print response
		try:
			if response:
				if "result" in response.keys():
					if response["result"]:
						# print response["result"]
						val = float(int(float(response['result'][0]['value'].encode('utf-8'))/1048576))
						if val>5:
							models.Port_traffic.objects.create(
									hostname = item[1],
									key = item[3],
									time_c = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(int(response['result'][0]['clock']))),
									times = int(response['result'][0]['clock']),
									values = val
							)
		except Exception,e:
			print traceback.format_exc()
		# l.release()
	def prot_traffic(self):
		iteminfo = self.item_info()
		threads = []
	# l = threading.Lock()
		for item in iteminfo:
			t = threading.Thread(target=self.traffic_get, args=(item,))
			# t = threading.Thread(target=f5_vip1, args=(l,k,v,vip_list))
			threads.append(t)
		for i,t in zip(range(len(threads)),threads):
			t.start()
			if i % 30 == 0:
				time.sleep(0.5)
		for t in threads:
			t.join()
if __name__=='__main__':
	a=Zabbix()
	# a.group_get()
	# a.host_get()
	# a.item_info()
	a.prot_traffic()