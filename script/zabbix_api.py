#!/usr/bin/env python
#coding:utf-8
import json
import urllib2
from urllib2 import URLError
import sys


class Zabbix(object):
	def __init__(self):
		# based url and required header
		self.url = "http://192.168.45.237/zabbix/api_jsonrpc.php"
		self.header = {"Content-Type":"application/json"}
	
	def login(self):
		# auth user and password
		data = json.dumps(
		{
		   "jsonrpc": "2.0",
		   "method": "user.login",
		   "params": {
		   "user": "Admin",
		   "password": "jd07gm09cx"
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
			return response['result']

	def host_get(self):
		hostinfo = []
		groupinfo = self.group_get()
		for group in groupinfo:
			data = json.dumps(
			{
			   "jsonrpc":"2.0",
			   "method":"host.get",
			   "params":{
				   "output":["hostid","name"],
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
					hostinfo.append([group['name'],host['hostid'],host['name']])
			
			# for line in  hostinfo:
				# print line[0],line[1],line[2],'\n'
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
					print host['itemid'],host['key_']
					#print "Host ID:",host['hostid'],"HostName:",host['name']
					iteminfo.append([item[0],item[2],host['itemid'],host['key_']])
					
		# return iteminfo
		with open('item1.txt','r+') as f:
			for line in iteminfo:
				f.write(json.dumps(line))
				f.write('\n')
		print len(iteminfo)
		# item_key = ["system.cpu.load[percpu,avg5]","vm.memory.size[available]","vfs.fs.size[/,free]"]
	
	def f5(self):
		info = []
		f5_dic = {}
		item_id = ['47107','47109','47110','47092','47094','47219','34411','34462']
		keys = ['CPU','CPU1','CPU2','connections','memorytotal','memoryused','ifInOctets2.1','ifOutOctets2.1']
		for id,k in zip(item_id,keys):
			data = json.dumps(
			{
			   "jsonrpc":"2.0",
			   "method":"history.get",
			   "params":{
				   "output":"extend",
				   "history":3,
				   "itemids":id,
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
					# print k,host['value'].encode('utf-8')
					f5_dic[k] = float(host['value'].encode('utf-8'))
					# print "Host ID:",host['hostid'],"HostName:",host['name']
				
		info.append('F5')
		info.append('%.2f' % ((f5_dic["CPU"]-f5_dic["CPU1"]+f5_dic["CPU2"])/f5_dic["CPU"]*100))
		info.append('%.2f' % ((f5_dic["memorytotal"]-f5_dic["memoryused"])/1048576))
		info.append('%.2f' % (f5_dic["ifInOctets2.1"]/1048576))
		info.append('%.2f' % (f5_dic["ifOutOctets2.1"]/1048576))
		info.append(f5_dic["connections"])
		# print info
		return info
		# print info
		# print f5_dic
		

	def f5_vip(self):
		VIP = {'activityb2b_vip':{'In':"45001",'Out':"45182"},'alarmorg_vip':{'In':"44959",'Out':"45140"},'allyes_22_vip':{'In':"44974",'Out':"45155"},'allyes_vip':{'In':"44919",'Out':"45100"},'anyipforward':{'In':"44960",'Out':"45141"},'api_un_vip':{'In':"44920",'Out':"45101",},'ask_vip':{'In':"44881",'Out':"45062"},'bbs_jsp_vip':{'In':"44943",'Out':"45124"},'bbsjz_vip':{'In':"44901",'Out':"45082"},'bjmrtg_vip':{'In':"44921",'Out':"45102"},'care_vip':{'In':"44890",'Out':"45071"},'cem_vip':{'In':"44882",'Out':"45063"},'chat_vip':{'In':"44891",'Out':"45072"},'cms_info_vip':{'In':"44961",'Out':"45142"},'cms_infoftp_vip':{'In':"45002",'Out':"45183"},'cmstest_vip':{'In':"44944",'Out':"45125"},'cognos_vip':{'In':"44922",'Out':"45103"},'comment_vip':{'In':"44945",'Out':"45126"},'cookiesorg_vip':{'In':"44988",'Out':"45169",},'credit_ftp_vip':{'In':"44989",'Out':"45170"},'credit_vip':{'In':"44923",'Out':"45104"},'crm53_vip':{'In':"44902",'Out':"45083",},'db_monitor_vip':{'In':"44990",'Out':"45171"},'detailb2b_vip':{'In':"44975",'Out':"45156"},'dsp_new_vip':{'In':"44946",'Out':"45127",},'dxcrm_vip':{'In':"44903",'Out':"45084"},'edmcobar8066_vip':{'In':"45016",'Out':"45197"},'edmcobar9066_vip':{'In':"45017",'Out':"45198",},'edmorg_vip':{'In':"44924",'Out':"45105"},'edmsmtp_vip':{'In':"44947",'Out':"45128"},'edoc_vip':{'In':"44892",'Out':"45073"},'ehetong_vip':{'In':"44948",'Out':"45129"},'ehr_new_vip':{'In':"44949",'Out':"45130"},'ehr_vip':{'In':"44883",'Out':"45064"},'espinc_vip':{'In':"44925",'Out':"45106"},'ework_pool':{'In':"44926",'Out':"45107"},'fhftp_vip':{'In':"44904",'Out':"45085"},'flow_vip':{'In':"47272",'Out':"47273"},'ganglia_vip':{'In':"44950",'Out':"45131"},'hcmta2_vip':{'In':"44927",'Out':"45108"},'hcpad_80_vip':{'In':"44962",'Out':"45143"},'hcpad_vip':{'In':"44905",'Out':"45086"},'hcpadnew_80_vip':{'In':"45003",'Out':"45184"},'hcproxy2_110_vip':{'In':"45018",'Out':"45199"},'hcproxy2_143_vip':{'In':"45019",'Out':"45200"},'hcproxy2_80_vip':{'In':"45004",'Out':"45185"},'hcproxy2_993_vip':{'In':"45020",'Out':"45201"},'hcproxy2_995_vip':{'In':"45021",'Out':"45202"},'hetong_vip':{'In':"44928",'Out':"45109"},'hetongcrm_vip':{'In':"44976",'Out':"45157"},'hetongpdf_vip':{'In':"44977",'Out':"45158"},'hfbzhifu_vip':{'In':"44963",'Out':"45144"},'homeinc_vip':{'In':"44951",'Out':"45132"},'hr_vip':{'In':"44878",'Out':"45059"},'huifubao_gateway80_vip':{'In':"45056",'Out':"45237"},'hycrm_vip':{'In':"44906",'Out':"45087"},'im_9000_vip':{'In':"44952",'Out':"45133"},'im_file_vip':{'In':"44953",'Out':"45134"},'im_hcact_vip':{'In':"44964",'Out':"45145"},'im_manage_vip':{'In':"44978",'Out':"45159"},'im_online2_vip':{'In':"44991",'Out':"45172"},'im_sms_vip':{'In':"44929",'Out':"45110"},'im_ws_80_vip':{'In':"44965",'Out':"45146"},'im_ws_vip':{'In':"44907",'Out':"45088"},'imchat_vip':{'In':"44930",'Out':"45111"},'imchatroom_vip':{'In':"44992",'Out':"45173"},'img108_vip':{'In':"44931",'Out':"45112"},'imgb2b_vip':{'In':"44932",'Out':"45113"},'imgup_vip':{'In':"44908",'Out':"45089"},'imlogin_443_vip':{'In':"45005",'Out':"45186"},'imlogin_5222_vip':{'In':"45023",'Out':"45204"},'imlogin_80_vip':{'In':"44993",'Out':"45174"},'imonline_web_vip':{'In':"45024",'Out':"45205"},'imp2pold443_vip':{'In':"45006",'Out':"45187"},'imp2pold80_vip':{'In':"44994",'Out':"45175"},'imyz2_vip':{'In':"44909",'Out':"45090"},'imyz_vip':{'In':"44893",'Out':"45074"},'info_delivery_vip':{'In':"45029",'Out':"45210"},'info_pubnew_vip':{'In':"45007",'Out':"45188"},'info_upload_80_vip':{'In':"45039",'Out':"45220"},'logb2b_vip':{'In':"44933",'Out':"45114"},'logorg_vip':{'In':"44934",'Out':"45115"},'mail_hc360_rec_vip':{'In':"45040",'Out':"45221"},'mail_hc360_send_1_vip':{'In':"45054",'Out':"45235"},'mail_hc360_send_2_vip':{'In':"45055",'Out':"45236"},'mail_hcmailbox1_vip':{'In':"45046",'Out':"45227"},'mail_mta_rec_vip_25':{'In':"45047",'Out':"45228"},'mail_mta_send_vip_25':{'In':"45050",'Out':"45231"},'log2_vip_34.243':{'In':"45008",'Out':"45189"},'log2_vip_34.243_3306':{'In':"45049",'Out':"45230"},'log2_vip_34.243_55535':{'In':"45053",'Out':"45234"},'mail_proxy_vip_110':{'In':"45041",'Out':"45222"},'mail_proxy_vip_143':{'In':"45042",'Out':"45223"},'mail_proxy_vip_80':{'In':"45030",'Out':"45211"},'manage-im_vip':{'In':"44979",'Out':"45160"},'manageb2b_vip':{'In':"44980",'Out':"45161"},'managecredit_ftp_vip':{'In':"45051",'Out':"45232"},'managecredit_vip':{'In':"45025",'Out':"45206"},'managevms_vip':{'In':"44981",'Out':"45162"},'markettrends_vip':{'In':"45026",'Out':"45207"},'miniportal_vip':{'In':"44995",'Out':"45176"},'mis_vip':{'In':"44884",'Out':"45065"},'mjcrm_vip':{'In':"44910",'Out':"45091"},'mjdown_vip':{'In':"44935",'Out':"45116"},'mmtclient_ftp_vip':{'In':"45031",'Out':"45212"},'mmtclient_vip':{'In':"44982",'Out':"45163"},'mobile_info_vip':{'In':"45009",'Out':"45190"},'mweb_vip':{'In':"44895",'Out':"45076"},'myb2b2_vip':{'In':"44936",'Out':"45117"},'myb2b_vip':{'In':"44911",'Out':"45092"},'mycredit_vip':{'In':"44966",'Out':"45147"},'nagios_vip':{'In':"44937",'Out':"45118"},'newbbs_vip':{'In':"44938",'Out':"45119"},'ngniximg00-14_vip':{'In':"45032",'Out':"45213"},'ngniximg15-29_vip':{'In':"45033",'Out':"45214"},'ngniximg_b2b_vip':{'In':"45027",'Out':"45208"},'ngniximg_info_vip':{'In':"45034",'Out':"45215"},'openapi_vip':{'In':"44954",'Out':"45135"},'opencrm_web_vip':{'In':"45010",'Out':"45191"},'order_b2b_vip':{'In':"44983",'Out':"45164"},'order_pub_vip':{'In':"44984",'Out':"45165"},'otrs_vip':{'In':"44896",'Out':"45077"},'partnercredit_vip':{'In':"45035",'Out':"45216"},'pay_styles_vip':{'In':"44996",'Out':"45177"},'pay_vip':{'In':"44885",'Out':"45066"},'phone_vip':{'In':"44912",'Out':"45093"},'press_org_8080_vip':{'In':"45043",'Out':"45224"},'press_org_ftp_vip':{'In':"45036",'Out':"45217"},'press_org_vip':{'In':"44985",'Out':"45166"},'qdcrm_vip':{'In':"44913",'Out':"45094"},'qdcrm_web_vip':{'In':"44986",'Out':"45167"},'qiye_manage_vip':{'In':"45013",'Out':"45194"},'qiye_web_vip':{'In':"44967",'Out':"45148"},'renwu_vip':{'In':"44914",'Out':"45095"},'renwumgr_vip':{'In':"44968",'Out':"45149"},'reporter9300_vip':{'In':"45028",'Out':"45209"},'reporter_vip':{'In':"44969",'Out':"45150"},'rilimanager_vip':{'In':"45014",'Out':"45195"},'score_vip':{'In':"44915",'Out':"45096"},'sdclog_vip':{'In':"44939",'Out':"45120"},'search2_vip':{'In':"44956",'Out':"45137"},'search_lvci_3360_vip':{'In':"45052",'Out':"45233"},'search_new_vip':{'In':"44997",'Out':"45178"},'search_vip':{'In':"44940",'Out':"45121"},'searchlvci_vip':{'In':"44998",'Out':"45179"},'sell_vip':{'In':"44898",'Out':"45079"},'sem_vip':{'In':"44886",'Out':"45067"},'serviceorg_vip':{'In':"44999",'Out':"45180"},'sessiondata_org_vip':{'In':"45048",'Out':"45229"},'shehui_vip':{'In':"44941",'Out':"45122"},'shopdns_vip':{'In':"44957",'Out':"45138"},'sousuo_dsp_vip':{'In':"45000",'Out':"45181"},'sso_https_vip':{'In':"44987",'Out':"45168"},'sso_vip':{'In':"44887",'Out':"45068"},'survy_vip':{'In':"44916",'Out':"45097"},'syslog_smtplog_vip':{'In':"45044",'Out':"45225"},'timesten17003_vip':{'In':"45037",'Out':"45218"},'timesten17005_vip':{'In':"45038",'Out':"45219"},'trademobile_vip':{'In':"45015",'Out':"45196"},'tuan_ftp_vip':{'In':"44970",'Out':"45151"},'tuan_new_vip':{'In':"44971",'Out':"45152"},'uidorg_vip':{'In':"44942",'Out':"45123"},'un_vip':{'In':"44879",'Out':"45060"},'vmsim_vip':{'In':"44917",'Out':"45098"},'vmsinfo1_vip':{'In':"44972",'Out':"45153"},'vmsinfo_vip':{'In':"44958",'Out':"45139"},'ws_vip':{'In':"44880",'Out':"45061"},'wtd_vip':{'In':"44888",'Out':"45069"},'wuliu_vip':{'In':"46045",'Out':"46046"},'www1_bak_vip':{'In':"44973",'Out':"45154"},'www_vip':{'In':"44889",'Out':"45070"},'wwwim_vip':{'In':"44918",'Out':"45099"}}
		vip_info = []
		for k,v in VIP.items():
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
					if hasattr(e, 'reason'):
						print 'We failed to reach a server.'
						print 'Reason: ', e.reason
					elif hasattr(e, 'code'):
						print 'The server could not fulfill the request.'
						print 'Error code: ', e.code	
				else:
					response = json.loads(result.read())
					result.close()
					# print  ks,response['result']
					for host in response['result']:
						info[ks] = ('%.2f' % (float(host['value'].encode('utf-8'))/1048576))
						# print k,info
						# print k,host['value'].encode('utf-8')
						# f5_dic[k] = float(host['value'].encode('utf-8'))	
			vip_info.append([k,info['In'],info['Out']])
		# print vip_info
		return vip_info















if __name__=='__main__':

	a = Zabbix()
	a.login()
	a.f5()
	# a.item_info()
	


