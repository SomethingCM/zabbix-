#!/usr/bin/env python
#coding:utf-8
import json
import urllib2
from urllib2 import URLError
import sys
import threading, time
url = "http://ip/zabbix/api_jsonrpc.php"
header = {"Content-Type":"application/json"}
global vip_list
def login():
	# auth user and password
	data = json.dumps(
	{
	   "jsonrpc": "2.0",
	   "method": "user.login",
	   "params": {
	   "user": "Admin",
	   "password": "admin"
	},
	"id": 0
	})
	# create request object
	request = urllib2.Request(url,data)
	for key in header:
		request.add_header(key,header[key])
	# auth and get authid
	try:
		result = urllib2.urlopen(request)
	except URLError as e:
		print "Auth Failed, Please Check Your Name AndPassword:",e.code
	else:
		response = json.loads(result.read())
		result.close()
		return response['result']

# def f5_vip1(l,k,v,vip_list):
def f5_vip1(k,v,vip_list):
	# print k
	# print v
	# print "++++++++++++++++++++++++++"
	# l.acquire()
	info = {}
	for ks,vs in v.items():	
		# print ks,vs
		time_e = time.time()
		time_s = time_e - 400
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
		   "auth":login(),
		   "id":2,
		})
		request = urllib2.Request(url,data)
		for key in header:
			request.add_header(key,header[key])
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
		# print info
		vip_list.append([k,info['In'],info['Out']])
	# return .vip_list
	# l.release()

def vip_demo():
	VIP ={'BI_vip':{'In':'61620','Out':'61800'},'activityb2b_vip':{'In':'61746','Out':'61926'},'alarmorg_vip':{'In':'61702','Out':'61882'},'anyipforward':{'In':'61703','Out':'61883'},'ask_vip':{'In':'61624','Out':'61804'},'bbs_jsp_vip':{'In':'61688','Out':'61868'},'bjmrtg_vip':{'In':'61668','Out':'61848'},'care_vip':{'In':'61634','Out':'61814'},'cem_vip':{'In':'61625','Out':'61805'},'chat_vip':{'In':'61635','Out':'61815'},'cmall_vip':{'In':'61647','Out':'61827'},'cms_info_vip':{'In':'61704','Out':'61884'},'cmstest_vip':{'In':'61689','Out':'61869'},'cognos_vip':{'In':'61669','Out':'61849'},'comment_vip':{'In':'61690','Out':'61870'},'cookiesorg_vip':{'In':'61733','Out':'61913'},'credit_ftp_vip':{'In':'61734','Out':'61914'},'crm53_vip':{'In':'61648','Out':'61828'},'daikuanorder_vip':{'In':'61760','Out':'61940'},'db_monitor_vip':{'In':'61735','Out':'61915'},'detailb2b_vip':{'In':'61718','Out':'61898'},'dsp_new_vip':{'In':'61691','Out':'61871'},'dxcrm_vip':{'In':'61649','Out':'61829'},'edmcobar8066_vip':{'In':'61761','Out':'61941'},'edmcobar9066_vip':{'In':'61762','Out':'61942'},'edmorg_vip':{'In':'61670','Out':'61850'},'edoc_vip':{'In':'61636','Out':'61816'},'ehetong_vip':{'In':'61692','Out':'61872'},'ehr_vip':{'In':'61626','Out':'61806'},'espinc_vip':{'In':'61671','Out':'61851'},'fhftp_vip':{'In':'61650','Out':'61830'},'flow_vip':{'In':'61637','Out':'61817'},'ganglia_vip':{'In':'61693','Out':'61873'},'hcmta2_vip':{'In':'61672','Out':'61852'},'hcpad_80_vip':{'In':'61705','Out':'61885'},'hcpad_vip':{'In':'61651','Out':'61831'},'hcpadnew_80_vip':{'In':'61747','Out':'61927'},'hcproxy2_110_vip':{'In':'61763','Out':'61943'},'hcproxy2_143_vip':{'In':'61764','Out':'61944'},'hcproxy2_80_vip':{'In':'61748','Out':'61928'},'hcproxy2_993_vip':{'In':'61765','Out':'61945'},'hcproxy2_995_vip':{'In':'61766','Out':'61946'},'hetongcrm_vip':{'In':'61719','Out':'61899'},'hetongpdf_vip':{'In':'61720','Out':'61900'},'hfbzhifu_vip':{'In':'61706','Out':'61886'},'homeinc_vip':{'In':'61694','Out':'61874'},'hotso8080_vip':{'In':'61721','Out':'61901'},'hotso_vip':{'In':'61652','Out':'61832'},'hr_vip':{'In':'61621','Out':'61801'},'huifubao_gateway':{'In':'61767','Out':'61947'},'huifubao_gateway80_vip':{'In':'61797','Out':'61977'},'hycrm_vip':{'In':'61653','Out':'61833'},'im_9000_vip':{'In':'61695','Out':'61875'},'im_file_vip':{'In':'61696','Out':'61876'},'im_hcact_vip':{'In':'61707','Out':'61887'},'im_manage_vip':{'In':'61722','Out':'61902'},'im_online2_vip':{'In':'61736','Out':'61916'},'im_sms_vip':{'In':'61673','Out':'61853'},'im_ws_80_vip':{'In':'61708','Out':'61888'},'im_ws_vip':{'In':'61654','Out':'61834'},'imchat_vip':{'In':'61674','Out':'61854'},'imchatroom_vip':{'In':'61737','Out':'61917'},'imgb2b_vip':{'In':'61675','Out':'61855'},'imgup_vip':{'In':'61655','Out':'61835'},'imlogin_443_vip':{'In':'61749','Out':'61929'},'imlogin_5222_vip':{'In':'61768','Out':'61948'},'imlogin_80_vip':{'In':'61738','Out':'61918'},'imonline_web_vip':{'In':'61769','Out':'61949'},'imp2pold443_vip':{'In':'61750','Out':'61930'},'imp2pold80_vip':{'In':'61739','Out':'61919'},'imyz2_vip':{'In':'61656','Out':'61836'},'imyz_vip':{'In':'61638','Out':'61818'},'info_delivery_vip':{'In':'61774','Out':'61954'},'info_pubnew_vip':{'In':'61751','Out':'61931'},'info_upload_80_vip':{'In':'61783','Out':'61963'},'infoweb3':{'In':'61639','Out':'61819'},'infoweb4_vip':{'In':'61709','Out':'61889'},'jdcrm_vip':{'In':'61657','Out':'61837'},'log2_vip_34.243':{'In':'61752','Out':'61932'},'log2_vip_34.243_3306':{'In':'61790','Out':'61970'},'log2_vip_34.243_55535':{'In':'61794','Out':'61974'},'log4_vip':{'In':'61640','Out':'61820'},'log5_vip':{'In':'61641','Out':'61821'},'logb2b_vip':{'In':'61676','Out':'61856'},'logorg_vip':{'In':'61677','Out':'61857'},'logorg_vip_34.64_81':{'In':'61787','Out':'61967'},'mail_hc360_rec_vip':{'In':'61784','Out':'61964'},'mail_hc360_send_1_vip':{'In':'61795','Out':'61975'},'mail_hc360_send_2_vip':{'In':'61796','Out':'61976'},'mail_hcmailbox1_vip':{'In':'61788','Out':'61968'},'manage-im_vip':{'In':'61723','Out':'61903'},'manageb2b_vip':{'In':'61724','Out':'61904'},'managecredit_ftp_vip':{'In':'61791','Out':'61971'},'managecredit_vip':{'In':'61770','Out':'61950'},'managevms_vip':{'In':'61725','Out':'61905'},'markettrends_vip':{'In':'61771','Out':'61951'},'miniportal_vip':{'In':'61740','Out':'61920'},'mis2_vip':{'In':'61642','Out':'61822'},'mis_vip':{'In':'61627','Out':'61807'},'mjcrm_vip':{'In':'61658','Out':'61838'},'mjdown_vip':{'In':'61678','Out':'61858'},'mmtclient_ftp_vip':{'In':'61775','Out':'61955'},'mmtclient_vip':{'In':'61726','Out':'61906'},'mobile_info_vip':{'In':'61753','Out':'61933'},'mweb_vip':{'In':'61643','Out':'61823'},'myb2b2_vip':{'In':'61679','Out':'61859'},'myb2b_vip':{'In':'61659','Out':'61839'},'mycredit_vip':{'In':'61710','Out':'61890'},'nagios_vip':{'In':'61680','Out':'61860'},'newbbs_vip':{'In':'61681','Out':'61861'},'ngniximg00-14_vip':{'In':'61776','Out':'61956'},'ngniximg15-29_vip':{'In':'61777','Out':'61957'},'ngniximg_b2b_vip':{'In':'61772','Out':'61952'},'ngniximg_info_vip':{'In':'61778','Out':'61958'},'nps_vip':{'In':'61628','Out':'61808'},'openapi_vip':{'In':'61697','Out':'61877'},'opencrm_web_vip':{'In':'61754','Out':'61934'},'order_b2b_vip':{'In':'61727','Out':'61907'},'order_pub_vip':{'In':'61728','Out':'61908'},'partercredit8080_vip':{'In':'61792','Out':'61972'},'partnercredit_vip':{'In':'61779','Out':'61959'},'pay_dingdan_443':{'In':'61755','Out':'61935'},'pay_logs':{'In':'61644','Out':'61824'},'pay_logs_80':{'In':'61698','Out':'61878'},'pay_mmt_gateway':{'In':'61756','Out':'61936'},'pay_styles_vip':{'In':'61741','Out':'61921'},'pay_vip':{'In':'61629','Out':'61809'},'phone_vip':{'In':'61660','Out':'61840'},'press_org_8080_vip':{'In':'61785','Out':'61965'},'press_org_ftp_vip':{'In':'61780','Out':'61960'},'press_org_vip':{'In':'61729','Out':'61909'},'qdcrm_vip':{'In':'61661','Out':'61841'},'qdcrm_web_vip':{'In':'61730','Out':'61910'},'qiye_manage_vip':{'In':'61757','Out':'61937'},'qiye_web_vip':{'In':'61711','Out':'61891'},'renwu_vip':{'In':'61662','Out':'61842'},'renwumgr_vip':{'In':'61712','Out':'61892'},'reporter9300_vip':{'In':'61773','Out':'61953'},'reporter_vip':{'In':'61713','Out':'61893'},'rili':{'In':'61618','Out':'61798'},'rilimanager_vip':{'In':'61758','Out':'61938'},'score_vip':{'In':'61663','Out':'61843'},'sdclog_vip':{'In':'61682','Out':'61862'},'search2_vip':{'In':'61699','Out':'61879'},'search_lvci_3360_vip':{'In':'61793','Out':'61973'},'search_new_vip':{'In':'61742','Out':'61922'},'search_vip':{'In':'61683','Out':'61863'},'searchlvci_vip':{'In':'61743','Out':'61923'},'sell_vip':{'In':'61645','Out':'61825'},'sem_vip':{'In':'61630','Out':'61810'},'serviceorg_vip':{'In':'61744','Out':'61924'},'sessiondata_org_vip':{'In':'61789','Out':'61969'},'shehui_vip':{'In':'61684','Out':'61864'},'shopdns_vip':{'In':'61700','Out':'61880'},'sousuo_dsp_vip':{'In':'61745','Out':'61925'},'sso_https_vip':{'In':'61731','Out':'61911'},'sso_vip':{'In':'61631','Out':'61811'},'survy_vip':{'In':'61664','Out':'61844'},'syslog_smtplog_vip':{'In':'61786','Out':'61966'},'test':{'In':'61619','Out':'61799'},'test8082':{'In':'61646','Out':'61826'},'timesten17003_vip':{'In':'61781','Out':'61961'},'timesten17005_vip':{'In':'61782','Out':'61962'},'trademobile_vip':{'In':'61759','Out':'61939'},'tuan_ftp_vip':{'In':'61714','Out':'61894'},'tuan_new_vip':{'In':'61715','Out':'61895'},'uidorg_vip':{'In':'61685','Out':'61865'},'un_vip':{'In':'61622','Out':'61802'},'vmsim_vip':{'In':'61665','Out':'61845'},'vmsinfo1_vip':{'In':'61716','Out':'61896'},'vmsinfo_vip':{'In':'61701','Out':'61881'},'weixin_vip':{'In':'61686','Out':'61866'},'weshop_vip':{'In':'61687','Out':'61867'},'wlgateway_vip':{'In':'61732','Out':'61912'},'ws_vip':{'In':'61623','Out':'61803'},'wtd_vip':{'In':'61632','Out':'61812'},'wuliu_vip':{'In':'61666','Out':'61846'},'www1_bak_vip':{'In':'61717','Out':'61897'},'www_vip':{'In':'61633','Out':'61813'},'wwwim_vip':{'In':'61667','Out':'61847'}}
	vip_list = []
	threads = []
	# l = threading.Lock()
	for k,v in VIP.items():
		t = threading.Thread(target=f5_vip1, args=(k,v,vip_list))
		# t = threading.Thread(target=f5_vip1, args=(l,k,v,vip_list))
		threads.append(t)
	for i,t in zip(range(len(threads)),threads):
		t.start()
		if i % 30 == 0:
			time.sleep(0.05)
	for t in threads:
		t.join()
	totle_in = 0
	totle_out = 0
	for i in vip_list:
		totle_in = totle_in + float(i[1])
		totle_out = totle_out + float(i[2])
	vip_list.append(['TOTLE',totle_in,totle_out])
	return vip_list
	# print vip_list

# if __name__=='__main__':
	# vip_demo()
	


