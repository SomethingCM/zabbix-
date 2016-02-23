#-*- coding: utf-8 -*-  
#!/usr/bin/env python  
import os,json
import traceback
import cloudstackapi
def net_info():
	curl_list = ['curl -o /dev/null -s -w %{remote_ip}:%{time_total}"\n" www.hc360.com','curl -o /dev/null -s -w %{remote_ip}:%{time_total}"\n" www.1688.com','curl -o /dev/null -s -w %{remote_ip}:%{time_total}"\n" www.baidu.com']
	url_list = ['www.hc360.com','www.1688.com','www.baidu.com']

	info = []

	try:
		for url,cmd in zip(url_list,curl_list):
			curl_back = os.popen(cmd).read().strip('\n').split(':')
			ping_cmd =  "ping %s -c 50 -f | sed '$!d' |awk '{print $4}'|awk -F '/' '{print $2}'" % curl_back[0]
			ping_back = os.popen(ping_cmd).read().strip('\n')
			info.append([url,curl_back[0],float('%.4f'curl_back[1]),float('%.4f'ping_back]))
		print type(json.dumps(info))
		return json.dumps(info)
	except Exception,e:
		print traceback.format_exc()
		print e
		return info
		
if __name__=='__main__':
	print net_info()






