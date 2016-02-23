#-*- coding: utf-8 -*-
#!/usr/bin/env python
import json
import os
import traceback
#获取lvs vip流量信息
def getLvs():
	try:
		IN = 0
		OUT = 0
		AC = 0
		IC = 0
		vip_name = []
		lvs_io= []
		for line in (os.popen('ipvsadm -L -n --rate').readlines()):
			lvs_io.append(line)
		info = lvs_io[3:]
		lvs_io_list = []
		for line in info:
			dic = []
			dic1 = line.split()
			#print dic1
			dic.append(dic1[1])
			dic.append('%.4f' % (float(dic1[5])/1048576))
			dic.append('%.4f' % (float(dic1[6])/1048576))
			lvs_io_list.append(dic)
			#return traffic_dic
		lvs_cnn = []
		for line in (os.popen('ipvsadm -L -n').readlines()):
			lvs_cnn.append(line)
		info1 = lvs_cnn[3:]
		#print info1
		lvs_cnn_dic = {}
		lvs_cnn_len = []
		for i,line in zip(range(len(info1)),info1):
			#print len(line.split())
			if len(line.split()) != 6:
				lvs_cnn_len.append(i)
		for i in range(len(lvs_cnn_len)):
			if (i+1)!= len(lvs_cnn_len): 
				lvs_list = info1[lvs_cnn_len[i]:lvs_cnn_len[i+1]]
				ActiveConn = 0
				InActConn = 0
				for i in range(1,len(lvs_list)):
					ActiveConn += int(lvs_list[i].split()[4])
					InActConn += int(lvs_list[i].split()[5])
				for line in lvs_list:
					if len(line.split()) != 6:
						vip_name.append(line.split()[1])
						lvs_cnn_dic[line.split()[1]] = [ActiveConn,InActConn]
					else:
						lvs_cnn_dic[line.split()[1]] = [line.split()[4],line.split()[5]]
			else:
				lvs_list = info1[lvs_cnn_len[i]:]
				ActiveConn = 0
				InActConn = 0
				for i in range(1,len(lvs_list)):
					ActiveConn += int(lvs_list[i].split()[4])
                                        InActConn += int(lvs_list[i].split()[5])
                                for line in lvs_list:
                                        if len(line.split()) != 6:
						vip_name.append(line.split()[1])
                                                lvs_cnn_dic[line.split()[1]] = [ActiveConn,InActConn]
                                        else:
                                                lvs_cnn_dic[line.split()[1]] = [line.split()[4],line.split()[5]]
			
		lvs1 = []
		for line in lvs_io_list:
			if line[0] in lvs_cnn_dic.keys():
				lvs1.append(line + lvs_cnn_dic[line[0]])
			else:
				lvs1.append(line + [0,0])
		#return lvs
		lvs = []
		for name in vip_name:
			for line in lvs1:
				if name == line[0]:
					IN += float(line[1])
					OUT += float(line[2])
					AC += int(line[3])
#					IC += int(line[4])
		cpu_list = []
		for line in (os.popen("cat /proc/stat |head -n 1 |awk '{Total=$2+$3+$4+$5+$6+$7;print (Total-$5)/Total*100}'").readlines()):
                        cpu_list.append(line)
			#print cpu_list[0]
                mem_list = []
                for line in (os.popen("free -m|grep buffers/|awk '{print $4}'").readlines()):
                        mem_list.append(line)
			#print mem_list[0]
		lvs.append(lvs1)
		lvs.append(['LVS-209.160','%.2f' % float(cpu_list[0].split('\n')[0]),mem_list[0].split('\n')[0],'%.2f' % IN,'%.2f' % OUT,AC])
		#print lvs
		return json.dumps(lvs)

	except:
		print traceback.format_exc()
if __name__ == "__main__":
	print getLvs()
#	for line in data:
#		print line
#	print data
