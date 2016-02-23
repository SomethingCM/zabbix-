#-*- coding: utf-8 -*-  
#!/usr/bin/env python  
import paramiko  
import traceback,json
#远程连接函数
def ssh2(ip,port,username,passwd,cmd): 
	try:	
		ssh = paramiko.SSHClient() #调用paramiko类
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  
		ssh.connect(ip,port,username,passwd,timeout=2) 
		# print cmd
		stdin, stdout, stderr = ssh.exec_command(cmd)  
		# stdin.write("Y")
		out = stdout.readlines()
		# print out
		open_delay =  json.loads(out[0].strip('\n'))
		ssh.close()  
		return open_delay
	except Exception,e:
		print traceback.format_exc()
		print e
		print '%s\tError\n'%(ip)  
		
def net_info():
	try:
		info = {}
		data = []
		cmd = 'sudo python /root/curlping.py'#远程命令。执行远程机器固定目录下的curlping.py脚本
		cmd1 = 'python /root/curlping.py'
		#定义主机
		info['bgq'] = ssh2("ip1",22,"cm","admin",cmd)
		info['yz'] = ssh2("ip2",22,"root","admin",cmd1)
		# print info
		data.append([float(info['bgq'][0][2].encode('utf-8')),float(info['yz'][0][2].encode('utf-8'))])
		data.append([float(info['bgq'][0][3].encode('utf-8')),float(info['yz'][0][3].encode('utf-8'))])
		data.append([float(info['bgq'][1][2].encode('utf-8')),float(info['yz'][1][2].encode('utf-8'))])
		data.append([float(info['bgq'][1][3].encode('utf-8')),float(info['yz'][1][3].encode('utf-8'))])
		data.append([float(info['bgq'][2][2].encode('utf-8')),float(info['yz'][2][2].encode('utf-8'))])
		data.append([float(info['bgq'][2][3].encode('utf-8')),float(info['yz'][2][3].encode('utf-8'))])
		# data.append([[info['bgq'][0][0].encode('utf-8'),info['bgq'][0][1].encode('utf-8')]
		# ,[info['bgq'][1][0].encode('utf-8'),info['bgq'][1][1].encode('utf-8')]
		# ,[info['bgq'][2][0].encode('utf-8'),info['bgq'][2][1].encode('utf-8')]])
		data.append([[info['bgq'][0][0].encode('utf-8'),info['bgq'][0][1].encode('utf-8'),info['yz'][0][1].encode('utf-8')],[info['bgq'][1][0].encode('utf-8'),info['bgq'][1][1].encode('utf-8'),info['yz'][1][1].encode('utf-8')],[info['bgq'][2][0].encode('utf-8'),info['bgq'][2][1].encode('utf-8'),info['yz'][2][1].encode('utf-8')]])
		
		# print data
		'''
		# info['bgq'] = ssh2("192.168.46.71",2222,"cm","chenmeng",cmd)

		##info['tn'] = ssh2("192.168.19.160",22,"root","jd07gm09cx",cmd1)

		##info['syq'] = ssh2("192.168.19.251",22,"root","jd07gm09cx",cmd1)
		# info['syq'] = ssh2("123.103.76.83",22,"root","jd07gm09",cmd1)
	
		data.append([float(info['bgq'][0][2].encode('utf-8')),float(info['syq'][0][2].encode('utf-8')),float(info['tn'][0][2].encode('utf-8'))])
		data.append([float(info['bgq'][0][3].encode('utf-8')),float(info['syq'][0][3].encode('utf-8')),float(info['tn'][0][3].encode('utf-8'))])
		data.append([float(info['bgq'][1][2].encode('utf-8')),float(info['syq'][1][2].encode('utf-8')),float(info['tn'][1][2].encode('utf-8'))])
		data.append([float(info['bgq'][1][3].encode('utf-8')),float(info['syq'][1][3].encode('utf-8')),float(info['tn'][1][3].encode('utf-8'))])
		data.append([float(info['bgq'][2][2].encode('utf-8')),float(info['syq'][2][2].encode('utf-8')),float(info['tn'][2][2].encode('utf-8'))])
		data.append([float(info['bgq'][2][3].encode('utf-8')),float(info['syq'][2][3].encode('utf-8')),float(info['tn'][2][3].encode('utf-8'))])
		data.append([[info['bgq'][0][0].encode('utf-8'),info['bgq'][0][1].encode('utf-8'),info['syq'][0][1].encode('utf-8'),info['tn'][0][1].encode('utf-8')],[info['bgq'][1][0].encode('utf-8'),info['bgq'][1][1].encode('utf-8'),info['syq'][1][1].encode('utf-8'),info['tn'][1][1].encode('utf-8')],[info['bgq'][2][0].encode('utf-8'),info['bgq'][2][1].encode('utf-8'),info['syq'][2][1].encode('utf-8'),info['tn'][2][1].encode('utf-8')]])
		# data['curl_hc']=[info['bgq'][0][2],info['syq'][0][2],info['tn'][0][2]]
		# data['ping_hc']=[info['bgq'][0][3],info['syq'][0][3],info['tn'][0][3]]
		# data['curl_al']=[info['bgq'][1][2],info['syq'][1][2],info['tn'][1][2]]
		# data['ping_al']=[info['bgq'][1][3],info['syq'][1][3],info['tn'][1][3]]
		# data['curl_bd']=[info['bgq'][2][2],info['syq'][2][2],info['tn'][2][2]]
		# data['ping_bd']=[info['bgq'][2][3],info['syq'][2][3],info['tn'][2][3]]
		# data['bgq_ip']=[info['bgq'][0][1],info['syq'][1][1],info['tn'][2][1]]
		# data['tn_ip']=[info['tn'][0][1],info['tn'][1][1],info['tn'][2][1]]
		# data['syq_ip']=[info['syq'][0][1],info['syq'][1][1],info['syq'][2][1]]
		# print data '''
		return data
	except Exception,e:
		print traceback.format_exc()
		print e
#远程执行moniItems-cm.py，返回lvs流量信息
def lvs_io():
	try:
		cmd = 'python /root/moniItems-cm.py'
		lvs = ssh2("ip",22,"root","admin",cmd)
		# print lvs
		return lvs
	except Exception,e:
		return 'error'
if __name__=='__main__':
	print lvs_info()
 
    