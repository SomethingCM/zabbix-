#!/usr/bin/env python
#coding:utf-8
import json
import urllib2
from urllib2 import URLError
import ConfigParser
import string, os, sys
cf = ConfigParser.ConfigParser()
cf.read("conf/conf.ini")
import threading, time

class Zabbix(object):
	def __init__(self):
		# based url and required header
		# self.url = "http://ip/zabbix/api_jsonrpc.php"
		self.url = cf.get("zabbix_api", "url")
		self.header = {"Content-Type":"application/json"}
		self.vip_list = []
#api登陆获取token
	def login(self):
		# auth user and password
		data = json.dumps(
		{
		   "jsonrpc": "2.0",
		   "method": "user.login",
		   "params": {
		   # "user": "Admin",
		   "user": cf.get("zabbix_api", "user"),
		   # "password": "admin"
		   "password": cf.get("zabbix_api", "password")
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
			if response['result']:
				return response['result']
#获取组信息		
	def group_get(self):
		
		data = json.dumps(
		{
		   "jsonrpc":"2.0",
		   "method":"hostgroup.get",
		   "params":{
			   "output":["groupid","name"],
		   },
		   "auth":self.login(),
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
			# for group in response['result']:
				# print "Group ID:",group['groupid'],"\tGroupName:",group['name']
			# print response['result']
			return response['result']
#获取主机信息
	def host_get(self):
		hostinfo = []
		groupinfo = self.group_get()
		for group in groupinfo:
			data = json.dumps(
			{
			   "jsonrpc":"2.0",
			   "method":"host.get",
			   "params":{
				   "output":["hostid","name",'host'],
				   "groupids":group['groupid'],
			   },
			   "auth":self.login(),
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
					hostinfo.append([group['name'],host['hostid'],host['host']])
			
			# for line in  hostinfo:
				# print line[0],line[1],line[2],'\n'
		# print response['result']
		return hostinfo
			
			
#获取主机item监控项			
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
				   "hostids":item[1],
			   },
			   "auth":self.login(),
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
					#print "Host ID:",host['hostid'],"HostName:",host['name']
					iteminfo.append([item[0],item[2],host['itemid'],host['key_']])
					
		# return iteminfo
		with open('item1.txt','r+') as f:
			for line in iteminfo:
				f.write(json.dumps(line))
				f.write('\n')
		print len(iteminfo)
		# item_key = ["system.cpu.load[percpu,avg5]","vm.memory.size[available]","vfs.fs.size[/,free]"]
	#获取f5的监控信息
	def f5(self):
		info = []
		f5_dic = {}
		item_id = ['62780','62781','62782','62788','62783','62785','34462','34411']
		keys = ['CPU','CPU1','CPU2','serverconnects','memorytotal','memoryused','ifInOctets2.1','ifOutOctets2.1']
		time_e = time.time()
		time_s = time_e - 300
		for id,k in zip(item_id,keys):
			data = json.dumps(
			{
			   "jsonrpc":"2.0",
			   "method":"history.get",
			   "params":{
				   "output":"extend",
				   "time_from":time_s,
				   "time_till":time_e,
				   "history":3,
				   "itemids":id,
				   "sortorder":"ASC",
				   "limit":1
			   },
			   "auth":self.login(),
			   "id":10,
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
				for host in response['result']:
					# print host
					# print k,host['value'].encode('utf-8')
					f5_dic[k] = float(host['value'].encode('utf-8'))
					# print "Host ID:",host['hostid'],"HostName:",host['name']
				
		info.append('F5')
		info.append('%.2f' % ((f5_dic["CPU"]-f5_dic["CPU1"]+f5_dic["CPU2"])/f5_dic["CPU"]*100))#
		info.append('%.2f' % (f5_dic["memoryused"]/f5_dic["memorytotal"]*100))
		info.append('%.2f' % (f5_dic["ifInOctets2.1"]/1048576))
		info.append('%.2f' % (f5_dic["ifOutOctets2.1"]/1048576))
		info.append(f5_dic["serverconnects"])
		# print info
		return info
		# print info
		# print f5_dic

#获取慧敏的流量信息
	def huiming(self):
		info = []
		huiming_dic = {}
		item_id = ['52560','52588']
		keys = ['ifInOctets2.24','ifOutOctets2.24']
		time_e = time.time()
		time_s = time_e - 300
		for id,k in zip(item_id,keys):
			data = json.dumps(
			{
			   "jsonrpc":"2.0",
			   "method":"history.get",
			   "params":{
				   "output":"extend",
				   "time_from":time_s,
				   "time_till":time_e,
				   "history":3,
				   "itemids":id,
				   "sortorder":"ASC",
				   "limit":1
			   },
			   "auth":self.login(),
			   "id":10,
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
				for host in response['result']:
					# print host
					# print k,host['value'].encode('utf-8')
					huiming_dic[k] = float(host['value'].encode('utf-8'))
					# print "Host ID:",host['hostid'],"HostName:",host['name']
				
		info.append('慧敏')
		info.append(0)
		info.append(0)
		info.append('%.2f' % (huiming_dic["ifInOctets2.24"]/1048576))
		info.append('%.2f' % (huiming_dic["ifOutOctets2.24"]/1048576))
		info.append(0)
		# print info
		return info



		
# VIPBK = {'BI_vip':{'In':'61620','Out':'61800'},'activityb2b_vip':{'In':'61746','Out':'61926'},'alarmorg_vip':{'In':'61702','Out':'61882'},'anyipforward':{'In':'61703','Out':'61883'},'ask_vip':{'In':'61624','Out':'61804'},'bbs_jsp_vip':{'In':'61688','Out':'61868'},'bjmrtg_vip':{'In':'61668','Out':'61848'},'care_vip':{'In':'61634','Out':'61814'},'cem_vip':{'In':'61625','Out':'61805'},'chat_vip':{'In':'61635','Out':'61815'},'cmall_vip':{'In':'61647','Out':'61827'},'cms_info_vip':{'In':'61704','Out':'61884'},'cmstest_vip':{'In':'61689','Out':'61869'},'cognos_vip':{'In':'61669','Out':'61849'},'comment_vip':{'In':'61690','Out':'61870'},'cookiesorg_vip':{'In':'61733','Out':'61913'},'credit_ftp_vip':{'In':'61734','Out':'61914'},'crm53_vip':{'In':'61648','Out':'61828'},'daikuanorder_vip':{'In':'61760','Out':'61940'},'db_monitor_vip':{'In':'61735','Out':'61915'},'detailb2b_vip':{'In':'61718','Out':'61898'},'dsp_new_vip':{'In':'61691','Out':'61871'},'dxcrm_vip':{'In':'61649','Out':'61829'},'edmcobar8066_vip':{'In':'61761','Out':'61941'},'edmcobar9066_vip':{'In':'61762','Out':'61942'},'edmorg_vip':{'In':'61670','Out':'61850'},'edoc_vip':{'In':'61636','Out':'61816'},'ehetong_vip':{'In':'61692','Out':'61872'},'ehr_vip':{'In':'61626','Out':'61806'},'espinc_vip':{'In':'61671','Out':'61851'},'fhftp_vip':{'In':'61650','Out':'61830'},'flow_vip':{'In':'61637','Out':'61817'},'ganglia_vip':{'In':'61693','Out':'61873'},'hcmta2_vip':{'In':'61672','Out':'61852'},'hcpad_80_vip':{'In':'61705','Out':'61885'},'hcpad_vip':{'In':'61651','Out':'61831'},'hcpadnew_80_vip':{'In':'61747','Out':'61927'},'hcproxy2_110_vip':{'In':'61763','Out':'61943'},'hcproxy2_143_vip':{'In':'61764','Out':'61944'},'hcproxy2_80_vip':{'In':'61748','Out':'61928'},'hcproxy2_993_vip':{'In':'61765','Out':'61945'},'hcproxy2_995_vip':{'In':'61766','Out':'61946'},'hetongcrm_vip':{'In':'61719','Out':'61899'},'hetongpdf_vip':{'In':'61720','Out':'61900'},'hfbzhifu_vip':{'In':'61706','Out':'61886'},'homeinc_vip':{'In':'61694','Out':'61874'},'hotso8080_vip':{'In':'61721','Out':'61901'},'hotso_vip':{'In':'61652','Out':'61832'},'hr_vip':{'In':'61621','Out':'61801'},'huifubao_gateway':{'In':'61767','Out':'61947'},'huifubao_gateway80_vip':{'In':'61797','Out':'61977'},'hycrm_vip':{'In':'61653','Out':'61833'},'im_9000_vip':{'In':'61695','Out':'61875'},'im_file_vip':{'In':'61696','Out':'61876'},'im_hcact_vip':{'In':'61707','Out':'61887'},'im_manage_vip':{'In':'61722','Out':'61902'},'im_online2_vip':{'In':'61736','Out':'61916'},'im_sms_vip':{'In':'61673','Out':'61853'},'im_ws_80_vip':{'In':'61708','Out':'61888'},'im_ws_vip':{'In':'61654','Out':'61834'},'imchat_vip':{'In':'61674','Out':'61854'},'imchatroom_vip':{'In':'61737','Out':'61917'},'imgb2b_vip':{'In':'61675','Out':'61855'},'imgup_vip':{'In':'61655','Out':'61835'},'imlogin_443_vip':{'In':'61749','Out':'61929'},'imlogin_5222_vip':{'In':'61768','Out':'61948'},'imlogin_80_vip':{'In':'61738','Out':'61918'},'imonline_web_vip':{'In':'61769','Out':'61949'},'imp2pold443_vip':{'In':'61750','Out':'61930'},'imp2pold80_vip':{'In':'61739','Out':'61919'},'imyz2_vip':{'In':'61656','Out':'61836'},'imyz_vip':{'In':'61638','Out':'61818'},'info_delivery_vip':{'In':'61774','Out':'61954'},'info_pubnew_vip':{'In':'61751','Out':'61931'},'info_upload_80_vip':{'In':'61783','Out':'61963'},'infoweb3':{'In':'61639','Out':'61819'},'infoweb4_vip':{'In':'61709','Out':'61889'},'jdcrm_vip':{'In':'61657','Out':'61837'},'log2_vip_34.243':{'In':'61752','Out':'61932'},'log2_vip_34.243_3306':{'In':'61790','Out':'61970'},'log2_vip_34.243_55535':{'In':'61794','Out':'61974'},'log4_vip':{'In':'61640','Out':'61820'},'log5_vip':{'In':'61641','Out':'61821'},'logb2b_vip':{'In':'61676','Out':'61856'},'logorg_vip':{'In':'61677','Out':'61857'},'logorg_vip_34.64_81':{'In':'61787','Out':'61967'},'mail_hc360_rec_vip':{'In':'61784','Out':'61964'},'mail_hc360_send_1_vip':{'In':'61795','Out':'61975'},'mail_hc360_send_2_vip':{'In':'61796','Out':'61976'},'mail_hcmailbox1_vip':{'In':'61788','Out':'61968'},'manage-im_vip':{'In':'61723','Out':'61903'},'manageb2b_vip':{'In':'61724','Out':'61904'},'managecredit_ftp_vip':{'In':'61791','Out':'61971'},'managecredit_vip':{'In':'61770','Out':'61950'},'managevms_vip':{'In':'61725','Out':'61905'},'markettrends_vip':{'In':'61771','Out':'61951'},'miniportal_vip':{'In':'61740','Out':'61920'},'mis2_vip':{'In':'61642','Out':'61822'},'mis_vip':{'In':'61627','Out':'61807'},'mjcrm_vip':{'In':'61658','Out':'61838'},'mjdown_vip':{'In':'61678','Out':'61858'},'mmtclient_ftp_vip':{'In':'61775','Out':'61955'},'mmtclient_vip':{'In':'61726','Out':'61906'},'mobile_info_vip':{'In':'61753','Out':'61933'},'mweb_vip':{'In':'61643','Out':'61823'},'myb2b2_vip':{'In':'61679','Out':'61859'},'myb2b_vip':{'In':'61659','Out':'61839'},'mycredit_vip':{'In':'61710','Out':'61890'},'nagios_vip':{'In':'61680','Out':'61860'},'newbbs_vip':{'In':'61681','Out':'61861'},'ngniximg00-14_vip':{'In':'61776','Out':'61956'},'ngniximg15-29_vip':{'In':'61777','Out':'61957'},'ngniximg_b2b_vip':{'In':'61772','Out':'61952'},'ngniximg_info_vip':{'In':'61778','Out':'61958'},'nps_vip':{'In':'61628','Out':'61808'},'openapi_vip':{'In':'61697','Out':'61877'},'opencrm_web_vip':{'In':'61754','Out':'61934'},'order_b2b_vip':{'In':'61727','Out':'61907'},'order_pub_vip':{'In':'61728','Out':'61908'},'partercredit8080_vip':{'In':'61792','Out':'61972'},'partnercredit_vip':{'In':'61779','Out':'61959'},'pay_dingdan_443':{'In':'61755','Out':'61935'},'pay_logs':{'In':'61644','Out':'61824'},'pay_logs_80':{'In':'61698','Out':'61878'},'pay_mmt_gateway':{'In':'61756','Out':'61936'},'pay_styles_vip':{'In':'61741','Out':'61921'},'pay_vip':{'In':'61629','Out':'61809'},'phone_vip':{'In':'61660','Out':'61840'},'press_org_8080_vip':{'In':'61785','Out':'61965'},'press_org_ftp_vip':{'In':'61780','Out':'61960'},'press_org_vip':{'In':'61729','Out':'61909'},'qdcrm_vip':{'In':'61661','Out':'61841'},'qdcrm_web_vip':{'In':'61730','Out':'61910'},'qiye_manage_vip':{'In':'61757','Out':'61937'},'qiye_web_vip':{'In':'61711','Out':'61891'},'renwu_vip':{'In':'61662','Out':'61842'},'renwumgr_vip':{'In':'61712','Out':'61892'},'reporter9300_vip':{'In':'61773','Out':'61953'},'reporter_vip':{'In':'61713','Out':'61893'},'rili':{'In':'61618','Out':'61798'},'rilimanager_vip':{'In':'61758','Out':'61938'},'score_vip':{'In':'61663','Out':'61843'},'sdclog_vip':{'In':'61682','Out':'61862'},'search2_vip':{'In':'61699','Out':'61879'},'search_lvci_3360_vip':{'In':'61793','Out':'61973'},'search_new_vip':{'In':'61742','Out':'61922'},'search_vip':{'In':'61683','Out':'61863'},'searchlvci_vip':{'In':'61743','Out':'61923'},'sell_vip':{'In':'61645','Out':'61825'},'sem_vip':{'In':'61630','Out':'61810'},'serviceorg_vip':{'In':'61744','Out':'61924'},'sessiondata_org_vip':{'In':'61789','Out':'61969'},'shehui_vip':{'In':'61684','Out':'61864'},'shopdns_vip':{'In':'61700','Out':'61880'},'sousuo_dsp_vip':{'In':'61745','Out':'61925'},'sso_https_vip':{'In':'61731','Out':'61911'},'sso_vip':{'In':'61631','Out':'61811'},'survy_vip':{'In':'61664','Out':'61844'},'syslog_smtplog_vip':{'In':'61786','Out':'61966'},'test':{'In':'61619','Out':'61799'},'test8082':{'In':'61646','Out':'61826'},'timesten17003_vip':{'In':'61781','Out':'61961'},'timesten17005_vip':{'In':'61782','Out':'61962'},'trademobile_vip':{'In':'61759','Out':'61939'},'tuan_ftp_vip':{'In':'61714','Out':'61894'},'tuan_new_vip':{'In':'61715','Out':'61895'},'uidorg_vip':{'In':'61685','Out':'61865'},'un_vip':{'In':'61622','Out':'61802'},'vmsim_vip':{'In':'61665','Out':'61845'},'vmsinfo1_vip':{'In':'61716','Out':'61896'},'vmsinfo_vip':{'In':'61701','Out':'61881'},'weixin_vip':{'In':'61686','Out':'61866'},'weshop_vip':{'In':'61687','Out':'61867'},'wlgateway_vip':{'In':'61732','Out':'61912'},'ws_vip':{'In':'61623','Out':'61803'},'wtd_vip':{'In':'61632','Out':'61812'},'wuliu_vip':{'In':'61666','Out':'61846'},'www1_bak_vip':{'In':'61717','Out':'61897'},'www_vip':{'In':'61633','Out':'61813'},'wwwim_vip':{'In':'61667','Out':'61847'}}
#获取f5 vip的流量信息
	def f5_vip(self):
		VIP = {'BI_vip':{'In':'61620','Out':'61800'},'activityb2b_vip':{'In':'61746','Out':'61926'},'alarmorg_vip':{'In':'61702','Out':'61882'},'anyipforward':{'In':'61703','Out':'61883'},'ask_vip':{'In':'61624','Out':'61804'},'bbs_jsp_vip':{'In':'61688','Out':'61868'},'bjmrtg_vip':{'In':'61668','Out':'61848'},'care_vip':{'In':'61634','Out':'61814'},'cem_vip':{'In':'61625','Out':'61805'},'chat_vip':{'In':'61635','Out':'61815'},'cmall_vip':{'In':'61647','Out':'61827'},'cms_info_vip':{'In':'61704','Out':'61884'},'cmstest_vip':{'In':'61689','Out':'61869'},'cognos_vip':{'In':'61669','Out':'61849'},'comment_vip':{'In':'61690','Out':'61870'},'cookiesorg_vip':{'In':'61733','Out':'61913'},'credit_ftp_vip':{'In':'61734','Out':'61914'},'crm53_vip':{'In':'61648','Out':'61828'},'daikuanorder_vip':{'In':'61760','Out':'61940'},'db_monitor_vip':{'In':'61735','Out':'61915'},'detailb2b_vip':{'In':'61718','Out':'61898'},'dsp_new_vip':{'In':'61691','Out':'61871'},'dxcrm_vip':{'In':'61649','Out':'61829'},'edmcobar8066_vip':{'In':'61761','Out':'61941'},'edmcobar9066_vip':{'In':'61762','Out':'61942'},'edmorg_vip':{'In':'61670','Out':'61850'},'edoc_vip':{'In':'61636','Out':'61816'},'ehetong_vip':{'In':'61692','Out':'61872'},'ehr_vip':{'In':'61626','Out':'61806'},'espinc_vip':{'In':'61671','Out':'61851'},'fhftp_vip':{'In':'61650','Out':'61830'},'flow_vip':{'In':'61637','Out':'61817'},'ganglia_vip':{'In':'61693','Out':'61873'},'hcmta2_vip':{'In':'61672','Out':'61852'},'hcpad_80_vip':{'In':'61705','Out':'61885'},'hcpad_vip':{'In':'61651','Out':'61831'},'hcpadnew_80_vip':{'In':'61747','Out':'61927'},'hcproxy2_110_vip':{'In':'61763','Out':'61943'},'hcproxy2_143_vip':{'In':'61764','Out':'61944'},'hcproxy2_80_vip':{'In':'61748','Out':'61928'},'hcproxy2_993_vip':{'In':'61765','Out':'61945'},'hcproxy2_995_vip':{'In':'61766','Out':'61946'},'hetongcrm_vip':{'In':'61719','Out':'61899'},'hetongpdf_vip':{'In':'61720','Out':'61900'},'hfbzhifu_vip':{'In':'61706','Out':'61886'},'homeinc_vip':{'In':'61694','Out':'61874'},'hotso8080_vip':{'In':'61721','Out':'61901'},'hotso_vip':{'In':'61652','Out':'61832'},'hr_vip':{'In':'61621','Out':'61801'},'huifubao_gateway':{'In':'61767','Out':'61947'},'huifubao_gateway80_vip':{'In':'61797','Out':'61977'},'hycrm_vip':{'In':'61653','Out':'61833'},'im_9000_vip':{'In':'61695','Out':'61875'},'im_file_vip':{'In':'61696','Out':'61876'},'im_hcact_vip':{'In':'61707','Out':'61887'},'im_manage_vip':{'In':'61722','Out':'61902'},'im_online2_vip':{'In':'61736','Out':'61916'},'im_sms_vip':{'In':'61673','Out':'61853'},'im_ws_80_vip':{'In':'61708','Out':'61888'},'im_ws_vip':{'In':'61654','Out':'61834'},'imchat_vip':{'In':'61674','Out':'61854'},'imchatroom_vip':{'In':'61737','Out':'61917'},'imgb2b_vip':{'In':'61675','Out':'61855'},'imgup_vip':{'In':'61655','Out':'61835'},'imlogin_443_vip':{'In':'61749','Out':'61929'},'imlogin_5222_vip':{'In':'61768','Out':'61948'},'imlogin_80_vip':{'In':'61738','Out':'61918'},'imonline_web_vip':{'In':'61769','Out':'61949'},'imp2pold443_vip':{'In':'61750','Out':'61930'},'imp2pold80_vip':{'In':'61739','Out':'61919'},'imyz2_vip':{'In':'61656','Out':'61836'},'imyz_vip':{'In':'61638','Out':'61818'},'info_delivery_vip':{'In':'61774','Out':'61954'},'info_pubnew_vip':{'In':'61751','Out':'61931'},'info_upload_80_vip':{'In':'61783','Out':'61963'},'infoweb3':{'In':'61639','Out':'61819'},'infoweb4_vip':{'In':'61709','Out':'61889'},'jdcrm_vip':{'In':'61657','Out':'61837'},'log2_vip_34.243':{'In':'61752','Out':'61932'},'log2_vip_34.243_3306':{'In':'61790','Out':'61970'},'log2_vip_34.243_55535':{'In':'61794','Out':'61974'},'log4_vip':{'In':'61640','Out':'61820'},'log5_vip':{'In':'61641','Out':'61821'},'logb2b_vip':{'In':'61676','Out':'61856'},'logorg_vip':{'In':'61677','Out':'61857'},'logorg_vip_34.64_81':{'In':'61787','Out':'61967'},'mail_hc360_rec_vip':{'In':'61784','Out':'61964'},'mail_hc360_send_1_vip':{'In':'61795','Out':'61975'},'mail_hc360_send_2_vip':{'In':'61796','Out':'61976'},'mail_hcmailbox1_vip':{'In':'61788','Out':'61968'},'manage-im_vip':{'In':'61723','Out':'61903'},'manageb2b_vip':{'In':'61724','Out':'61904'},'managecredit_ftp_vip':{'In':'61791','Out':'61971'},'managecredit_vip':{'In':'61770','Out':'61950'},'managevms_vip':{'In':'61725','Out':'61905'},'markettrends_vip':{'In':'61771','Out':'61951'},'miniportal_vip':{'In':'61740','Out':'61920'},'mis2_vip':{'In':'61642','Out':'61822'},'mis_vip':{'In':'61627','Out':'61807'},'mjcrm_vip':{'In':'61658','Out':'61838'},'mjdown_vip':{'In':'61678','Out':'61858'},'mmtclient_ftp_vip':{'In':'61775','Out':'61955'},'mmtclient_vip':{'In':'61726','Out':'61906'},'mobile_info_vip':{'In':'61753','Out':'61933'},'mweb_vip':{'In':'61643','Out':'61823'},'myb2b2_vip':{'In':'61679','Out':'61859'},'myb2b_vip':{'In':'61659','Out':'61839'},'mycredit_vip':{'In':'61710','Out':'61890'},'nagios_vip':{'In':'61680','Out':'61860'},'newbbs_vip':{'In':'61681','Out':'61861'},'ngniximg00-14_vip':{'In':'61776','Out':'61956'},'ngniximg15-29_vip':{'In':'61777','Out':'61957'},'ngniximg_b2b_vip':{'In':'61772','Out':'61952'},'ngniximg_info_vip':{'In':'61778','Out':'61958'},'nps_vip':{'In':'61628','Out':'61808'},'openapi_vip':{'In':'61697','Out':'61877'},'opencrm_web_vip':{'In':'61754','Out':'61934'},'order_b2b_vip':{'In':'61727','Out':'61907'},'order_pub_vip':{'In':'61728','Out':'61908'},'partercredit8080_vip':{'In':'61792','Out':'61972'},'partnercredit_vip':{'In':'61779','Out':'61959'},'pay_dingdan_443':{'In':'61755','Out':'61935'},'pay_logs':{'In':'61644','Out':'61824'},'pay_logs_80':{'In':'61698','Out':'61878'},'pay_mmt_gateway':{'In':'61756','Out':'61936'},'pay_styles_vip':{'In':'61741','Out':'61921'},'pay_vip':{'In':'61629','Out':'61809'},'phone_vip':{'In':'61660','Out':'61840'},'press_org_8080_vip':{'In':'61785','Out':'61965'},'press_org_ftp_vip':{'In':'61780','Out':'61960'},'press_org_vip':{'In':'61729','Out':'61909'},'qdcrm_vip':{'In':'61661','Out':'61841'},'qdcrm_web_vip':{'In':'61730','Out':'61910'},'qiye_manage_vip':{'In':'61757','Out':'61937'},'qiye_web_vip':{'In':'61711','Out':'61891'},'renwu_vip':{'In':'61662','Out':'61842'},'renwumgr_vip':{'In':'61712','Out':'61892'},'reporter9300_vip':{'In':'61773','Out':'61953'},'reporter_vip':{'In':'61713','Out':'61893'},'rili':{'In':'61618','Out':'61798'},'rilimanager_vip':{'In':'61758','Out':'61938'},'score_vip':{'In':'61663','Out':'61843'},'sdclog_vip':{'In':'61682','Out':'61862'},'search2_vip':{'In':'61699','Out':'61879'},'search_lvci_3360_vip':{'In':'61793','Out':'61973'},'search_new_vip':{'In':'61742','Out':'61922'},'search_vip':{'In':'61683','Out':'61863'},'searchlvci_vip':{'In':'61743','Out':'61923'},'sell_vip':{'In':'61645','Out':'61825'},'sem_vip':{'In':'61630','Out':'61810'},'serviceorg_vip':{'In':'61744','Out':'61924'},'sessiondata_org_vip':{'In':'61789','Out':'61969'},'shehui_vip':{'In':'61684','Out':'61864'},'shopdns_vip':{'In':'61700','Out':'61880'},'sousuo_dsp_vip':{'In':'61745','Out':'61925'},'sso_https_vip':{'In':'61731','Out':'61911'},'sso_vip':{'In':'61631','Out':'61811'},'survy_vip':{'In':'61664','Out':'61844'},'syslog_smtplog_vip':{'In':'61786','Out':'61966'},'test':{'In':'61619','Out':'61799'},'test8082':{'In':'61646','Out':'61826'},'timesten17003_vip':{'In':'61781','Out':'61961'},'timesten17005_vip':{'In':'61782','Out':'61962'},'trademobile_vip':{'In':'61759','Out':'61939'},'tuan_ftp_vip':{'In':'61714','Out':'61894'},'tuan_new_vip':{'In':'61715','Out':'61895'},'uidorg_vip':{'In':'61685','Out':'61865'},'un_vip':{'In':'61622','Out':'61802'},'vmsim_vip':{'In':'61665','Out':'61845'},'vmsinfo1_vip':{'In':'61716','Out':'61896'},'vmsinfo_vip':{'In':'61701','Out':'61881'},'weixin_vip':{'In':'61686','Out':'61866'},'weshop_vip':{'In':'61687','Out':'61867'},'wlgateway_vip':{'In':'61732','Out':'61912'},'ws_vip':{'In':'61623','Out':'61803'},'wtd_vip':{'In':'61632','Out':'61812'},'wuliu_vip':{'In':'61666','Out':'61846'},'www1_bak_vip':{'In':'61717','Out':'61897'},'www_vip':{'In':'61633','Out':'61813'},'wwwim_vip':{'In':'61667','Out':'61847'}}
		vip_info = []
		ioin = 0
		ioout = 0
		for k,v in VIP.items():
			# print k
			info = {}

			for ks,vs in v.items():
				time_e = time.time()
				time_s = time_e - 500
				data = json.dumps(
				{
				   "jsonrpc":"2.0",
				   "method":"history.get",
				   "params":{
					   "output":"extend",
					   	"time_from":time_s,
						"time_till":time_e,
					   "history":3,
					   "itemids":vs,
					   "limit":1
				   },
				   "auth":self.login(),
				   "id":10,
				})
				request = urllib2.Request(self.url,data)
				for key in self.header:
					request.add_header(key,self.header[key])
					# get host list				
				try:
					result = urllib2.urlopen(request)
				except URLError as e:
					continue
					if hasattr(e, 'reason'):
						print 'We failed to reach a server.'
						print 'Reason: ', e.reason
					elif hasattr(e, 'code'):
						print 'The server could not fulfill the request.'
						print 'Error code: ', e.code	
				else:
					response = json.loads(result.read())
					# print response['result']
					result.close()
					tag = True
					# print response['result']
					if response['result']:
						for host in response['result']:
							info[ks] = ('%.2f' % (float(host['value'].encode('utf-8'))/1048576))
							# print info
						# print k,host['value'].encode('utf-8')
						# f5_dic[k] = float(host['value'].encode('utf-8'))	
					else:
						tag = False
			if tag:
				# print k,info['In'],info['Out']
				ioin = ioin + float(info['In'])
				ioout = ioout + float(info['Out'])
				vip_info.append([k,info['In'],info['Out']])
		vip_info.append(['TOTLE',('%.2f' % (float(ioin))),('%.2f' % (float(ioout)))])
		# print vip_info
		return vip_info
'''
	def f5_vip1(self,l,k,v):
		l.acquire()
		info = {}
		for ks,vs in v.items():
			
			data = json.dumps(
			{
			   "jsonrpc":"2.0",
			   "method":"history.get",
			   "params":{
				   "output":"extend",
				   "history":3,
				   "itemids":vs,
				   "limit":1
			   },
			   "auth":self.login(),
			   "id":2,
			})
			request = urllib2.Request(self.url,data)
			for key in self.header:
				request.add_header(key,self.header[key])
				# get host list				
			try:
				result = urllib2.urlopen(request)
			except URLError as e:
				continue
				if hasattr(e, 'reason'):
					print 'We failed to reach a server.'
					print 'Reason: ', e.reason
				elif hasattr(e, 'code'):
					print 'The server could not fulfill the request.'
					print 'Error code: ', e.code	
			else:
				response = json.loads(result.read())
				# print response['result']
				result.close()
				tag = True
				if response['result']:
					for host in response['result']:
						info[ks] = ('%.2f' % (float(host['value'].encode('utf-8'))/1048576))
					# print k,info
					# print k,host['value'].encode('utf-8')
					# f5_dic[k] = float(host['value'].encode('utf-8'))	
				else:
					tag = False
			if tag:
				self.vip_list.append([k,info['In'],info['Out']])
		# return self.vip_list
		l.release()

	def vip_demo(self):
		VIP = {'anyipforward':{'In':"44960",'Out':"45141"},'ask_vip':{'In':"44881",'Out':"45062"},'bbs_jsp_vip':{'In':"44943",'Out':"45124"},'care_vip':{'In':"44890",'Out':"45071"},'chat_vip':{'In':"44891",'Out':"45072"},'cognos_vip':{'In':"44922",'Out':"45103"},'comment_vip':{'In':"44945",'Out':"45126"},'cookiesorg_vip':{'In':"44988",'Out':"45169",},'detailb2b_vip':{'In':"44975",'Out':"45156"},'edmcobar8066_vip':{'In':"45016",'Out':"45197"},'edmorg_vip':{'In':"44924",'Out':"45105"},'ehetong_vip':{'In':"44948",'Out':"45129"},'ehr_vip':{'In':"44883",'Out':"45064"},'espinc_vip':{'In':"44925",'Out':"45106"},'hcmta2_vip':{'In':"44927",'Out':"45108"},'hcproxy2_110_vip':{'In':"45018",'Out':"45199"},'hcproxy2_143_vip':{'In':"45019",'Out':"45200"},'hcproxy2_80_vip':{'In':"45004",'Out':"45185"},'hcproxy2_993_vip':{'In':"45020",'Out':"45201"},'hcproxy2_995_vip':{'In':"45021",'Out':"45202"},'hetongcrm_vip':{'In':"44976",'Out':"45157"},'hr_vip':{'In':"44878",'Out':"45059"},'huifubao_gateway80_vip':{'In':"45056",'Out':"45237"},'hycrm_vip':{'In':"44906",'Out':"45087"},'im_file_vip':{'In':"44953",'Out':"45134"},'im_manage_vip':{'In':"44978",'Out':"45159"},'im_online2_vip':{'In':"44991",'Out':"45172"},'im_ws_vip':{'In':"44907",'Out':"45088"},'imchat_vip':{'In':"44930",'Out':"45111"},'imgup_vip':{'In':"44908",'Out':"45089"},'imlogin_5222_vip':{'In':"45023",'Out':"45204"},'imonline_web_vip':{'In':"45024",'Out':"45205"},'imyz2_vip':{'In':"44909",'Out':"45090"},'info_delivery_vip':{'In':"45029",'Out':"45210"},'info_pubnew_vip':{'In':"45007",'Out':"45188"},'info_upload_80_vip':{'In':"45039",'Out':"45220"},'logb2b_vip':{'In':"44933",'Out':"45114"},'logorg_vip':{'In':"44934",'Out':"45115"},'mail_hc360_send_1_vip':{'In':"45054",'Out':"45235"},'mail_hc360_send_2_vip':{'In':"45055",'Out':"45236"},'log2_vip_34.243_3306':{'In':"45049",'Out':"45230"},'manageb2b_vip':{'In':"44980",'Out':"45161"},'managevms_vip':{'In':"44981",'Out':"45162"},'miniportal_vip':{'In':"44995",'Out':"45176"},'mjcrm_vip':{'In':"44910",'Out':"45091"},'mweb_vip':{'In':"44895",'Out':"45076"},'myb2b_vip':{'In':"44911",'Out':"45092"},'mycredit_vip':{'In':"44966",'Out':"45147"},'newbbs_vip':{'In':"44938",'Out':"45119"},'ngniximg00-14_vip':{'In':"45032",'Out':"45213"},'ngniximg15-29_vip':{'In':"45033",'Out':"45214"},'ngniximg_b2b_vip':{'In':"45027",'Out':"45208"},'opencrm_web_vip':{'In':"45010",'Out':"45191"},'order_b2b_vip':{'In':"44983",'Out':"45164"},'pay_styles_vip':{'In':"44996",'Out':"45177"},'pay_vip':{'In':"44885",'Out':"45066"},'phone_vip':{'In':"44912",'Out':"45093"},'qdcrm_web_vip':{'In':"44986",'Out':"45167"},'qiye_web_vip':{'In':"44967",'Out':"45148"},'renwu_vip':{'In':"44914",'Out':"45095"},'sdclog_vip':{'In':"44939",'Out':"45120"},'search_lvci_3360_vip':{'In':"45052",'Out':"45233"},'search_new_vip':{'In':"44997",'Out':"45178"},'sell_vip':{'In':"44898",'Out':"45079"},'sessiondata_org_vip':{'In':"45048",'Out':"45229"},'shopdns_vip':{'In':"44957",'Out':"45138"},'sso_https_vip':{'In':"44987",'Out':"45168"},'sso_vip':{'In':"44887",'Out':"45068"},'survy_vip':{'In':"44916",'Out':"45097"},'syslog_smtplog_vip':{'In':"45044",'Out':"45225"},'timesten17005_vip':{'In':"45038",'Out':"45219"},'tuan_new_vip':{'In':"44971",'Out':"45152"},'un_vip':{'In':"44879",'Out':"45060"},'vmsinfo1_vip':{'In':"44972",'Out':"45153"},'wuliu_vip':{'In':"46045",'Out':"46046"},'www_vip':{'In':"44889",'Out':"45070"},'wwwim_vip':{'In':"44918",'Out':"45099"}}		
		self.vip_list = []
		threads = []
		l = threading.Lock()
		for k,v in VIP.items():
			t = threading.Thread(target=f5_vip1, args=(self,l,k,v))
			threads.append(t)
		for i,t in zip(range(len(threads)),threads):
			t.start()
			if i % 20 == 0:
				time.sleep(0.5)
		for t in threads:
			t.join()
		totle_in = 0
		totle_out = 0
		for i in self.vip_list:
			totle_in = totle_in + float(i[1])
			totle_out = totle_out + float(i[2])
		self.vip_list.append(['TOTLE',totle_in,totle_out])
		return self.vip_list
	'''
# if __name__=='__main__':

	# a = Zabbix()
	# a.login()
	# print a.f5()
	# a.f5_vip()
	# a.group_get()
	# a.host_get()
	# a.item_info()
	# print a.huiming()