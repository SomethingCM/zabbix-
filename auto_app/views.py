# -*- coding: UTF-8 -*-
from django.shortcuts import render_to_response
import datetime,json,time,datetime,traceback
from django.http import HttpResponse,HttpResponseRedirect
from django.contrib import auth
from auto_app.models import Port_traffic 
from auto_auth import models
from django.contrib.auth.decorators import login_required
from auto_auth.views.permission import PermissionVerify
from automation.common.CommonPaginator import SelfPaginator
import salt
import subprocess
import cloudstackapi  #cloudstack封装api
import urllib2
from urllib2 import URLError
import sys
import threading, time
import threadpool
from curl_ping import * #模块中定义两台主机，并获取他们打开慧聪网、百度、阿里网页的网络情况
from zabbixsql2 import * #导入zabbix数据库查询模块，直接查询数据库获取数据
from Zabbix_db import *#同上
from Zabbix_db1 import *#同上
from zapi import * #zabbix api
from zabbix_api import *
from django.db.models import Q
# from zabbix_api1 import *
# Create your views here.
######################################登陆视图函数，权限认证###############################
#'权限认证函数'
def Auto(request):
	return HttpResponse('ok')
def is_root():
	try:
		info = 0
		user = request.user
		user_info = models.AuthUser.objects.get(user__username=user.username)
		return user_info.supper_root 
	except:
		print traceback.format_exc()
		return info		
	
# def w_group():
	# try:
		# info = 0
		# user = request.user
		# user_info = models.auto_user.objects.get(user__username=user.username)
		# return user_info.group_perm
	# except:
		# print traceback.format_exc()
		# return info			



#'视图函数'
#登陆函数
def login(request):
	
	return render_to_response('login.html')
#登陆认证
def login_auth(request):
	try:
		USERNAME,PASSWORD = request.POST.get('Username'),request.POST.get('Password')
		user_auth = auth.authenticate(username=USERNAME, password = PASSWORD)
		print '_'*30,user_auth
		
		if user_auth is not None: #username and passwd correct 
			auth.login(request, user_auth)
			return HttpResponseRedirect('/autoApp/index')
		else:
			return render_to_response('login.html', {'login_err': 'Wrong username or password!'})
	except:
		print traceback.format_exc()
		return HttpResponse('error')


#退出
def logout(request):
	try:
		auth.logout(request)
		return HttpResponseRedirect('/login/')
	except:
		print traceback.format_exc()
		return HttpResponse('error')
##############################end 登陆函数################################

#index主页面
@login_required(login_url="/login/")	
def index(request):
	user = request.user
	return render_to_response('index.html',{'user':user})
	
################告警视图################
@login_required(login_url="/login/")	
@PermissionVerify()
def alarm(request):
	user = request.user
	return render_to_response('alarm.html',{'user':user})
def triggers(request):
	try:
		info = []
		t = ZabbixTools() #调用zapi的ZabbixTools类
		content = t.trigger_get()
		# print content
		for line in content:
			info.append([line['host'],time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(int(line['lastchange'].encode('utf-8')))),line['description']])
		print len(info)
		# for i in info:
			# print i
		if request.GET.get('test') == 'test':
			return HttpResponse(json.dumps(info))
		else:
			# list = []
			# for line in content:
				# list.append([line['host'],time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(int(line['lastchange'].encode('utf-8')))),line['description']])
			return HttpResponse(json.dumps(info[0:12]))
	except:
		# print traceback.format_exc()
		return HttpResponse('error')

		
#####################监控信息状态##################


@login_required(login_url="/login/")
# @PermissionVerify()
def Switch_status(request):
	user = request.user
	return render_to_response('Switch_status.html',{'user':user})

@login_required(login_url="/login/")
# @PermissionVerify()
def Physical_status(request):
	user = request.user
	return render_to_response('Physical_status.html',{'user':user})
@login_required(login_url="/login/")
# @PermissionVerify()
def Windows_status(request):
	user = request.user
	return render_to_response('Windows_status.html',{'user':user})

def monitor_check(request,group1):
	try:
		group_dict = {}
		group_list = ['Templates','Linux servers','Zabbix servers','Discovered hosts','Virtual machines','Hypervisors','CISCO Templates',"办公网","测试网","正式网","生产环境交换机 172.16.8.0","公网交换机","搜索部60段","运维服务器","云","BigIP",'Switch','Physical server','Windows']
		# group_list = ['Switch',]
		group =group1.encode("utf-8")
		print group
		for item in group_list:
			# print item
			zabbix = ReportForm(item)#调用Zabbix_db1类，从数据库中获取服务器的状态信息
			if item == group and group == 'Switch':
				print "+++++++++++"
				zabbix.getInfo()
				# print zabbix.InfoList
				if zabbix.IpInfoList:
					for ip ,list in  zabbix.IpInfoList.items():
						if zabbix.IpInfoList[ip]['cpmCPUTotal5min']['avg']:
							group_dict[ip] = [zabbix.IpInfoList[ip]['groupname'],zabbix.IpInfoList[ip]['ip'],zabbix.IpInfoList[ip]['cpmCPUTotal5min']['avg'],zabbix.IpInfoList[ip]['ciscoMemoryPoolFree1']['avg'],zabbix.IpInfoList[ip]['vfs.fs.size[/,free]']['avg']]
						elif zabbix.IpInfoList[ip]['cpmCPUTotal5min0']['avg']:
							group_dict[ip] = [zabbix.IpInfoList[ip]['groupname'],zabbix.IpInfoList[ip]['ip'],zabbix.IpInfoList[ip]['cpmCPUTotal5min0']['avg'],zabbix.IpInfoList[ip]['ciscoMemoryPoolFree1']['avg'],zabbix.IpInfoList[ip]['vfs.fs.size[/,free]']['avg']]
						else:
							group_dict[ip] = [zabbix.IpInfoList[ip]['groupname'],zabbix.IpInfoList[ip]['ip'],zabbix.IpInfoList[ip]['cpmCPUTotal5min']['avg'],zabbix.IpInfoList[ip]['ciscoMemoryPoolFree1']['avg'],zabbix.IpInfoList[ip]['vfs.fs.size[/,free]']['avg']]
				# print group_dict
				return HttpResponse(json.dumps(group_dict))
			elif item == 'Physical server' and group == 'Physical':
				zabbix.getInfo()
				# print zabbix.InfoList
				if zabbix.IpInfoList:
					for ip ,list in  zabbix.IpInfoList.items():
						group_dict[ip] = [zabbix.IpInfoList[ip]['groupname'],zabbix.IpInfoList[ip]['ip'],zabbix.IpInfoList[ip]['system.cpu.load[percpu,avg5]']['avg'],zabbix.IpInfoList[ip]['vm.memory.size[available]']['avg'],zabbix.IpInfoList[ip]['vfs.fs.size[/,free]']['avg']]                                            
				# print group_dict
				return HttpResponse(json.dumps(group_dict))
			elif item == group and group == 'Windows':
				zabbix.getInfo()
				# print zabbix.InfoList
				if zabbix.IpInfoList:
					for ip ,list in  zabbix.IpInfoList.items():
						group_dict[ip] = [zabbix.IpInfoList[ip]['groupname'],zabbix.IpInfoList[ip]['ip'],zabbix.IpInfoList[ip]['system.cpu.load[percpu,avg5]']['avg'],zabbix.IpInfoList[ip]['vm.memory.size[available]']['avg'],zabbix.IpInfoList[ip]['vfs.fs.size[/,free]']['avg']]
				# print group_dict
				return HttpResponse(json.dumps(group_dict))	
			# else:
				# return HttpResponse('error')
	except:
		print traceback.format_exc()
		return HttpResponse('error')
		
		
############################******************saltstack end

"""
C.X   lvs 流量信息
"""
@login_required(login_url="/login/")
@PermissionVerify()	
def net_traffic(request):
	user = request.user
	return render_to_response('traffic.html',{'user':user})
##调用的Zabbix_db的函数search_zabbix
def get_Zabbix_db(request):
	try:
		aa = search_zabbix()
		
		
#		res = []
#		for item in list:
#			y,m,da=item.date.encode("utf-8").split('-')
#			d = datetime.date(int(y),int(m),int(da))
#			t = time.mktime(d.timetuple())*1000
#			print y,m,da,d
#			res.append([t,float(item.fault_rate)])
		return HttpResponse(json.dumps(aa))
	except:
		print traceback.format_exc()
		return HttpResponse('error')
#部分交换机流量
#调用的Zabbix_db1的函数search_zabbix1
def get_Zabbix_db1(request,num):
	hostinfo = [["172.16.8.150-SYQ-B02","%Gi1/0/49"],["172.16.8.54-HCY-D27","%Gi1/0/6"],["172.16.8.54-HCY-D27","%Gi1/0/12"],["172.16.8.54-HCY-D27","%Gi2/0/12"],["172.16.8.211-TN-A02","%Gi2/0/26"],["172.16.8.211-TN-A02","%Gi2/0/28"],["172.16.8.200-HCY-XJF","%Gi1/0/8"],["172.16.8.200-HCY-XJF","%Gi1/0/20"],["172.16.18.2-HCY-XJF","%Gi1/0/19"],["172.16.8.12-MMT-1F-E","%Gi1/0/10"],["172.16.18.1-HCY-XJF","%Gi2/0/4"],]
	nu = int(num) - 1
	# print nu
	try:
		if hostinfo[nu]:
			info = search_zabbix1(hostinfo[nu][0],hostinfo[nu][1])
			return HttpResponse(json.dumps(info))
	except:
		print traceback.format_exc()
		return HttpResponse('error')
		


'''
def service_status(request):
	user = request.user
	return render_to_response('service_status.html',{'user':user})
def monitor_check(request):
	try:
		group_dict = {}
		group_list = ['Templates','Linux servers','Zabbix servers','Discovered hosts','Virtual machines','Hypervisors','CISCO Templates',"办公网","测试网","正式网","生产环境交换机 172.16.8.0","公网交换机","搜索部60段","运维服务器","云","BigIP"]
		# group_list = ['CISCO Templates',"公网交换机","Switch"]
		
		for item in group_list:
			# print item
			zabbix = ReportForm(item)

			zabbix.getInfo()
			print zabbix.InfoList
			if zabbix.IpInfoList:
				for ip ,list in  zabbix.IpInfoList.items():
					group_dict[ip] = [zabbix.IpInfoList[ip]['groupname'],zabbix.IpInfoList[ip]['ip'],zabbix.IpInfoList[ip]['system.cpu.load[percpu,avg5]']['avg'],zabbix.IpInfoList[ip]['vm.memory.size[available]']['avg'],zabbix.IpInfoList[ip]['vfs.fs.size[/,free]']['avg']]
					# group_dict[ip] = [zabbix.IpInfoList[ip]['groupname'],zabbix.IpInfoList[ip]['ip'],zabbix.IpInfoList[ip]['cpmCPUTotal5min']['avg'],zabbix.IpInfoList[ip]['vm.memory.size[available]']['avg'],zabbix.IpInfoList[ip]['vfs.fs.size[/,free]']['avg']]
			print group_dict
		return HttpResponse(json.dumps(group_dict))
	except:
		# print traceback.format_exc()
		return HttpResponse('error')
'''
#############web_ssh#########################
@login_required(login_url="/login/")
@PermissionVerify()	
#web ssh跳转连接到gateone
def web_ssh(request):
	user = request.user
	return render_to_response('web_ssh.html',{'user':user})	
'''
##################基础用户中心####################
@login_required(login_url="/login/")	
def user_center(request):
	user = request.user
	return render_to_response('user_center.html',{'user':user})	
@login_required(login_url="/login/")	
def passwd_change(request):
	try:
		user = request.user
		
		USERNAME,PASSWORD1,PASSWORD2 = request.POST.get('username'),request.POST.get('password1'),request.POST.get('password2')
		print USERNAME,PASSWORD1,PASSWORD2
		print type(USERNAME),type(PASSWORD1),type(PASSWORD2)
		User = auth.authenticate(username=USERNAME,password=PASSWORD1)
		if User is not None:
			user_ch = models.auto_user.objects.get(user__username = USERNAME)
			# user_ch.user.password = PASSWORD2
			# print user_ch.user.username
			user_ch.user.set_password(PASSWORD2)
			# print '++++++++'
			user_ch.user.save()
			# print '========'
			# user_ch.save()
			# User.set_password(PASSWORD2)
			# User.save()

			return render_to_response('user_center.html',{'user':user,'info':'密码修改成功!'})	
		else:
			return render_to_response('user_center.html',{'user':user,'info':'用户名或密码错误!'})	

		
		# elif PASSWORD1 
	except:
		print traceback.format_exc()
		return render_to_response('user_center.html',{'user':user,'info':'密码修改失败，请联系管理员!'})

'''	
		
###########**************************saltstack start*********************************###########

		
# def saltstackhtml(request):
	# user = request.user
	# form = UploadFileForm()
	# return render_to_response('saltstack.html',{'user':user,'form':form})
@login_required(login_url="/login/")
@PermissionVerify()		
#salt 远程执行
def saltstack(request):
    user = request.user
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login/')
    username=request.session.get('username')
    #ret=subprocess.Popen('salt "node2" test.ping',shell=True,stdout=subprocess.PIPE).stdout.read()
    error = False
    ret_msg=[]
    ret_cmd_msg=[]
    ret_err=[]
    ret_nohost=''
    ret_nocmd=''
    ret_badcmd=''
    ret_bad=''
    if request.method == "POST":
        print request.POST
        host=request.POST.getlist('cmd_run_command_host')
        cmd=request.POST.get('cmd_run_command_cmd')
        print len(host),'xxxxxoooo'
        print request.POST.get('chechk_alive_host_name').split(',')
        print request.POST.get('check_alive_host_cmd')
        if host[0] == '':
            host=request.POST.get('chechk_alive_host_name').split(',')
            cmd=request.POST.get('check_alive_host_cmd')
        print len(host),host,cmd
        #ret=salt.client.LocalClient().cmd('node2','cmd.run',['ping -c 4 8.8.8.8'])
        bad_cmd=['rm','shutdown','cat /etc/passwd']
        if host[0] !='' and cmd != "" and cmd not in bad_cmd:
           # node_list=node.split(',')
            for node in host:
                print node
                allow_cmd=['test.ping','test.version']
                print "*"*45
                print node,cmd
                if cmd in allow_cmd:
                    try:
                        print '111%%%%%%%%%%%%%%%%%%%%%%'
                        msg=salt.client.LocalClient().cmd_full_return(node,cmd)
                        msg=str(node)+" "*24+str(msg[node]['ret'])
                        print msg
                        ret_msg.append(msg)
                        print ret_msg,'[[[[[[[[[[[[[['
                    except:
                        msg=str(node)+" "*24+"False"
                        print msg,'msg'
                        ret_err.append(msg)
                        print ret_err,'ret'
                        print '222%%%%%%%%%%%%%%%%%%%%%%'
                else:
                    try:
                        ret=salt.client.LocalClient().cmd(node,'cmd.run',[cmd])
                        print "=================="
                        if len(ret)<1:
                            err=str(node)+" "*24+'minions is not running'
                            ret_err.append(err)
                            print ret_err
                        #ret=str(node)+" "*24+str(ret[node])
                        ret_cmd_msg=str(node)+":\n"+"="*24+"\n"+str(ret[node])
                        print node,ret[node]
                        print ret
                        print "err============================="
                    except:
                        err=str(node)+" "*24+"The command is error\n"
                        ret_err.append(err)
                        print ret_err
                #ret=node+':\n'+u'ret[node]['ret']'
                print ret_msg
                print ret_err
                print "++++++++++++====+++"
        elif host == "":
            ret_bad="hostname is can not null"
            error=True
        elif cmd == "":
            ret_bad="command is can not null"
            error=True
        elif cmd  in bad_cmd:
            ret_bad="the command is not allow to use"
            error=True
        return render_to_response('saltstack.html',{'user':user,"ret_msg":ret_msg,"ret_cmd_msg":ret_cmd_msg,"error":error,"ret_err":ret_err,'ret_bad':ret_bad,'ret_nocmd':ret_nocmd,'ret_badcmd':ret_badcmd})


    elif request.method == "GET":
        print request.META['REMOTE_ADDR'],request.META['HTTP_USER_AGENT']

        ###############################grains info####################################
        # node='192.168.46.71'
        # cmd='grains.items'
        # grains_info=salt.client.LocalClient().cmd_full_return(node,cmd)[node]['ret']
        # id=grains_info['id']
        # host=grains_info['host']
        # domain=grains_info['domain']
        # fqdn=grains_info['fqdn']
        # nodename=grains_info['nodename']
        # localhost=grains_info['localhost']
        # server_id=grains_info['server_id']
        # master=grains_info['master']
        # ipv4=grains_info['ipv4']
        # saltversion=grains_info['saltversion']
        # pythonversion=grains_info['pythonversion']
        # shell=grains_info['shell']
        # defaultencoding=grains_info['defaultencoding']
        # defaultlanguage=grains_info['defaultlanguage']
        # os=grains_info['os']
        # os_family=grains_info['os_family']
        # kernel=grains_info['kernel']
        # kernelrelease=grains_info['kernelrelease']
        # ps=grains_info['ps']
        # virtual=grains_info['virtual']
        # cpu_model=grains_info['cpu_model']
        # cpuarch=grains_info['cpuarch']
        # num_cpus=grains_info['num_cpus']
        # cpu_flags=grains_info['cpu_flags']
        # num_gpus=grains_info['num_gpus']
        # gpus=grains_info['gpus']
        # mem_total=grains_info['mem_total']
        # ip=grains_info['ipv4']
        # path=grains_info['path']
        # saltpath=grains_info['saltpath']
        # pythonpath=grains_info['pythonpath']
        ###############################grains info####################################
        ###################################master_config################################
        f=open('/etc/salt/master','r')
        sshd_config=f.read()
        f.close()
        ##################################master_config################################
        ret = ""
        return render_to_response('saltstack.html',{'user':user,"username":username,"sshd_config":sshd_config,"result_data":ret,"error":error})
        # return render_to_response('saltstack.html',{'user':user,"username":username,"sshd_config":sshd_config,"result_data":ret,"error":error,"path":path,"id":id,"host":host,"domain":domain,"fqdn":fqdn,"nodename":nodename,"localhost":localhost,"server_id":server_id,"master":master,"ipv4":ipv4,"saltversion":saltversion,"pythonversion":pythonversion,"shell":shell,"defaultencoding":defaultencoding,"defaultlanguage":defaultlanguage,"os":os,"os_family":os_family,"kernel":kernel,"kernelrelease":kernelrelease,"ps":ps,"virtual":virtual,"cpu_model":cpu_model,"cpuarch":cpuarch,"num_cpus":num_cpus,"cpu_flags":cpu_flags,"num_gpus":num_gpus,"gpus":gpus,"mem_total":mem_total,"ipv4":ipv4,"path":path,"saltpath":saltpath,"pythonpath":pythonpath})
    return render_to_response('saltstack.html',{'user':user,"result_data":ret,"error":error})
@PermissionVerify()
#salt key
def salt_key(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    proc = subprocess.Popen('salt-key', stdout=subprocess.PIPE)
    salt_key = proc.stdout.read().replace('\n','<br>')
    #return render_to_response('saltstack.html',{"salt_key":salt_key},context_instance=RequestContext(request))
    return HttpResponse(salt_key)
@PermissionVerify()
#salt master conf 配置
def saltstack_master_config(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    if request.is_ajax():
        if request.method == "POST":
            #response=HttpResponse()
            #response['Content-Type']="text/javascript"
            data=request.POST.get('name')
            print type(data)
            try:
                f=open('/etc/salt/master','r+')
                f.write(data)
                f.close()
            except:
                pass
        if request.method == "GET":
            try:
                f=open('/etc/salt/master','r')
                data=f.read()
                f.close()
            except:
                data="The file /etc/salt/master is not exist"
    elif not request.is_ajax():
        print "-----------"
        return render_to_response('saltstack.html')
    return HttpResponse(data)
@PermissionVerify()
##salt master 组
def saltstack_master_group(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    data='method is not allowed'
    if not os.path.isdir('/etc/salt/master.d'):
        os.mkdir('/etc/salt/master.d')
    if not os.path.exists('/etc/salt/master.d/node.conf'):
        f=open('/etc/salt/master.d/node.conf','w')
        f.write('#You should setting group in /etc/salt/master.d/node.conf')
        f.close()
    if request.is_ajax():
        if request.method == "POST":
            data=request.POST['name']
            print data
            try:
                f=open('/etc/salt/master.d/node.conf','r+')
                f.write(data)
                f.close()
                print "add group"
            except:
                pass
        if request.method == "GET":
            try:
                f=open('/etc/salt/master.d/node.conf')
                data=f.read()
                f.close()
            except:
                data="The file /etc/salt/master.d/node.conf is not exist "
    return HttpResponse(data)
@PermissionVerify()
#salt 顶级状态文件
def saltstack_top_sls(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    data='method is not allowed'
    if not os.path.isdir('/srv/salt'):
        os.mkdir('/srv/salt')
    if not os.path.exists('/srv/salt/top.sls'):
        f=open('/srv/salt/top.sls','w')
        f.write('You should modify the /srv/salt/top.sls')
        f.close()
    if request.is_ajax():
        if request.method == "POST":
            data=request.POST['name']
            print data
            try:
                f=open('/srv/salt/top.sls','r+')
                f.write(data)
                f.close()
            except:
                pass
        if request.method == "GET":
            try:
                f=open('/srv/salt/top.sls')
                data=f.read()
                f.close()
            except:
                data="The file /srv/salt/top.sls is not exist "
    return HttpResponse(data)


@PermissionVerify()
#获取指定路径下的文件
def os_path_edit(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    data='method is not allowed'
    if request.is_ajax():
        if request.method == "POST":
            path=request.POST.get('os_path_edit_path').encode('utf-8')
            data=request.POST.get('os_path_edit_path_text').encode('utf-8')
            print path
            print type(data)
            try:
                if not os.path.exists(path):
                    f=open(path,'w')
                    f.write(data)
                    f.cloase()
                    print '**************************'
                else:
                    with open(path, 'r+') as fp: 
                        print '+++++++++++++++++++++++++' 
                        fp.write(data) 
                        print '======================'
                data="The file "+path+" saved ok "
            except Exception,ex:
                print Exception,":",ex
                data="The file "+path+" is not exist "
        if request.method == "GET":
            path=request.GET.get('os_path_edit_path')
            try:
                f=open(path,'r')
                data=f.read()
                f.close()
            except:
                data="The file "+path+" is not exist "
    return HttpResponse(data)



 ########上传############
from django import forms

class UploadFileForm(forms.Form):
    # title = forms.CharField(max_length=50)
    file = forms.FileField()

'''文件上传'''
import os,simplejson
# def handle_uploaded_file(f):
    # file_name = ""
    # try:
        # path = "/srv/salt/" 
        # if not os.path.exists(path):
            # os.makedirs(path)
        # file_name = path + f.name.encode('utf-8')
        # with open(file_name, 'wb+') as destination:
            # for chunk in f.chunks():
                # destination.write(chunk)
        # return 'ok'
    # except :
        # return 'fail'  
#####################上传视图函数##################

# def upload_file(request):
    # if request.method == 'POST':
        # form = UploadFileForm(request.POST, request.FILES)
        # if form.is_valid():
            # data = handle_uploaded_file(request.FILES['file'])
            # print data
            # if data == 'ok':
                
                # return HttpResponse('ok')
    # else:
        # form = UploadFileForm()
        # return HttpResponse('fail')

############upload   example##############
# def upload_file(request):
	# try:
		# if request.method == 'POST':
			# f = handle_uploaded_file(request.FILES['file'])
		# if f == 'ok':
			# return HttpResponse('ok')
		# else:
			# return HttpResponse('fail')
		# return render_to_response('saltstack.html', {'file':f})
	# except :
		# return HttpResponse('fail')
 
# def handle_uploaded_file(f):
	# try:
		# path = '/srv/salt/'
		# if not os.path.exists(path):
			# os.makedirs(path)
		# filename = path + f.name.encode('utf-8')
		# with open(filename, 'wb+') as info:
			# for chunk in f.chunks():
				# info.write(chunk)
		# return 'ok'
	# except :
		# return 'fail' 
############easy example##############
#上传文件
def upload_file(request):  
    ret="0"  
    file = request.FILES.get("Filedata",None)
    print file
    if file:   
        result,new_name = profile_upload(file)  
        if result:  
            ret="1"  
        else:  
            ret="2"                      
        json={'ret':ret,'save_name':new_name}  
    return HttpResponse(simplejson.dumps(json,ensure_ascii = False))  
  
  
def profile_upload(file):  
    '''''文件上传函数''' 
    
    if file:  
        path='/srv/salt/'  
        file_name = file.name.encode('utf-8')
        path_file=path + file_name
        with open(path_file, 'wb') as fp: 
            for content in file.chunks():   
                fp.write(content)  
  
        return (True,file_name) #change  
    return (False,file_name)   #change  
  
#删除附件  
 
 
# def profile_delte(request):  
    # del_file=request.POST.get("delete_file",'')  
    # if del_file:  
        # path_file='/srv/salt/' + del_file 
        # os.remove(path_file)  





		
#############仪表盘#########################
	
def dashboard(request):
	user = request.user
	return render_to_response('dashboard.html',{'user':user})	

	
#ping延时
def curl_ping(request):
	try:
		# data1 = [[1,2,3],[0.6,0.8,1],[1,2,3],[1,0.4,0.6],[0.6,0.8,1],[1,2,3]]
		data = net_info()          #调用curl_ping模块中net_info函数获取返回值
		# print type(data)
		# print data
		# print data1
		return HttpResponse(json.dumps(data))
	except:
		print traceback.format_exc()
		return HttpResponse('error')
#f5的状态信息
def loadbance(request):	
	try:
		data = []
		a = Zabbix()#调用zabbix_api中的Zabbix类
		f5 = a.f5()
		# huiming = a.huiming()
		# lvs = lvs_io()[1]
		# print f5
		data.append(f5)
		# data.append(lvs)
		# data.append(huiming)
		# data.append(['LVS-a',0,0,0,0,0])
		# data.append(['LVS-b',0,0,0,0,0])
		# data.append(['LVS-c',0,0,0,0,0])
		# data.append(['LVS-d',0,0,0,0,0])
		
		return HttpResponse(json.dumps(data))
	except:
		print traceback.format_exc()
		return HttpResponse('error')	
#############cloudstack####################### 废弃

# @login_required(login_url="/")	
# def cloud_web(request):
	# user = request.user
	# return render_to_response('cloud_web.html',{'user':user})	
	
#cloudstack登陆函数
def signin(user):
	try:
		global api   #定义一个全局变量
		user_in = models.AuthUser.objects.get(user__username=user.username)
		api = cloudstackapi.CloudStackAPI("http://192.168.151.240:8080/client/api",user_in.api_key,user_in.secretkey)   
		return 'ok'
	except:
		return 'err'
@login_required(login_url="/login/")	
def cloud_web(request):
	user = request.user
	try:
		if signin(user) == 'ok':
			request = {'install':'True'}
			result = api.listVirtualMachines(request)
			# print result['virtualmachine']
			return render_to_response('cloud_web.html',{'user':user,'results':result['virtualmachine']})
		else:
			return render_to_response('cloud_web.html',{'user':user,'err':'您没有云平台使用权限，请联系管理员!'})
	except:
			return render_to_response('cloud_web.html',{'user':user,'err':'您没有云平台使用权限，请联系管理员!'})
#cloudstack创建虚拟机     废弃
def cloud_register(request):
	user = request.user
	try:
		
		if signin(user) == 'ok' and request.method == 'POST' and request.POST.get('name'):
			if request.POST.get('os') == "5":
				templateid='767ec96e-d1fd-11e3-9f89-364fcd750268'
			elif request.POST.get('os') == "6":
				templateid='f5fe5e47-664b-417d-bf87-60274c35ff78'
			data = {
			'serviceofferingid':'2bfa8165-3a24-464e-ae64-2ffe87dabe57',
			'templateid':templateid,
			'zoneid':'e10b562a-4b52-4883-8e47-affcd48f5d5c',
			'networkids': 'da76db39-45c3-4f55-9fff-a1edb1a16123',
			'name':request.POST.get('name')
			}
			response_info = api.deployVirtualMachine(data)
			# print response_info
			return HttpResponseRedirect('/autoApp/cloud_web/')
		else:
			return render_to_response('cloud_web.html',{'user':user,'info':'添加失败!'})
	except:
		return render_to_response('cloud_web.html',{'user':user,'info':'添加失败!'})
		
################F5 和 LVS#####################################################
##########################################################################


#zabbix api登陆
def login2():
	# auth user and password
	url = "http://192.168.45.237/zabbix/api_jsonrpc.php"
	header = {"Content-Type":"application/json"}
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
#获取指定监控项的数据
def f5_vip1(k,v,vip_list):

	url = "http://192.168.45.237/zabbix/api_jsonrpc.php"
	header = {"Content-Type":"application/json"}
	info = {}
	# l.acquire()
	# for ks,vs in v.items():	
	time_e = time.time()
	time_s = time_e - 800
	data1 = json.dumps(
	{
	   "jsonrpc":"2.0",
	   "method":"history.get",
	   "params":{
		   "output":"extend",
		   "time_from":time_s,
			"time_till":time_e,
		   "history":3,
		   "itemids":v['In'],
		   "limit":1
	   },
	   "auth":login2(),
	   "id":2,
	})
	request1 = urllib2.Request(url,data1)
	for key in header:
		request1.add_header(key,header[key])
		# get host list				
	try:
		result1 = urllib2.urlopen(request1)
	except URLError as e:
		# continue
		if hasattr(e, 'reason'):
			print 'We failed to reach a server.'
			print 'Reason: ', e.reason
		elif hasattr(e, 'code'):
			print 'The server could not fulfill the request.'
			print 'Error code: ', e.code
	else:
		response1 = json.loads(result1.read())
		# print response1['result']
		result1.close()
	data2 = json.dumps(
	{
	   "jsonrpc":"2.0",
	   "method":"history.get",
	   "params":{
		   "output":"extend",
		   "time_from":time_s,
			"time_till":time_e,
		   "history":3,
		   "itemids":v['Out'],
		   "limit":1
	   },
	   "auth":login2(),
	   "id":2,
	})
	request2 = urllib2.Request(url,data2)
	for key in header:
		request2.add_header(key,header[key])
		# get host list				
	try:
		result2 = urllib2.urlopen(request2)
	except URLError as e:
		# continue
		if hasattr(e, 'reason'):
			print 'We failed to reach a server.'
			print 'Reason: ', e.reason
		elif hasattr(e, 'code'):
			print 'The server could not fulfill the request.'
			print 'Error code: ', e.code
	else:
		response2 = json.loads(result2.read())
		# print response2['result']
		# print response1['result'] ,response2['result']
		# print 
	if not response1['result']:
		tag1 = 1
	else:
		tag1 = 0
	if not response2['result']:
		tag2 = 1
	else:
		tag2 = 0
	if tag1 == 1 or tag2 == 1:
		print k,v
		# print response1['result'],response2['result']
	if response1['result'] and response2['result']:
		value1 = float(response1['result'][0]['value'].encode('utf-8'))/1048576
		value2 = float(response2['result'][0]['value'].encode('utf-8'))/1048576
		if value1 or value2:
			vip_list.append([k,value1,value2])
	# l.release()

	'''
		# print response['result']
		result.close()
			tag = True
			if response['result']:
				for host in response['result']:
					# info[ks] = ('%.2f' % (float(host['value'].encode('utf-8'))/1048576))
					info[ks] = (float(host['value'].encode('utf-8'))/1048576)
					# print type(info[ks])
			else:
				tag = False
	if tag:
		# print info
		if info['In'] or info['Out']:
			vip_list.append([k,info['In'],info['Out']])
	# return vip_list
	# l.release()
     '''
#调用f5_vip1获取监控值
def vip_demo():
	VIP ={'BI_vip':{'In':'61620','Out':'61800'},'activityb2b_vip':{'In':'61746','Out':'61926'},'alarmorg_vip':{'In':'61702','Out':'61882'},'anyipforward':{'In':'61703','Out':'61883'},'ask_vip':{'In':'61624','Out':'61804'},'bbs_jsp_vip':{'In':'61688','Out':'61868'},'bjmrtg_vip':{'In':'61668','Out':'61848'},'care_vip':{'In':'61634','Out':'61814'},'cem_vip':{'In':'61625','Out':'61805'},'chat_vip':{'In':'61635','Out':'61815'},'cmall_vip':{'In':'61647','Out':'61827'},'cms_info_vip':{'In':'61704','Out':'61884'},'cmstest_vip':{'In':'61689','Out':'61869'},'cognos_vip':{'In':'61669','Out':'61849'},'comment_vip':{'In':'61690','Out':'61870'},'cookiesorg_vip':{'In':'61733','Out':'61913'},'credit_ftp_vip':{'In':'61734','Out':'61914'},'crm53_vip':{'In':'61648','Out':'61828'},'daikuanorder_vip':{'In':'61760','Out':'61940'},'db_monitor_vip':{'In':'61735','Out':'61915'},'detailb2b_vip':{'In':'61718','Out':'61898'},'dsp_new_vip':{'In':'61691','Out':'61871'},'dxcrm_vip':{'In':'61649','Out':'61829'},'edmcobar8066_vip':{'In':'61761','Out':'61941'},'edmcobar9066_vip':{'In':'61762','Out':'61942'},'edmorg_vip':{'In':'61670','Out':'61850'},'edoc_vip':{'In':'61636','Out':'61816'},'ehetong_vip':{'In':'61692','Out':'61872'},'ehr_vip':{'In':'61626','Out':'61806'},'espinc_vip':{'In':'61671','Out':'61851'},'fhftp_vip':{'In':'61650','Out':'61830'},'flow_vip':{'In':'61637','Out':'61817'},'ganglia_vip':{'In':'61693','Out':'61873'},'hcmta2_vip':{'In':'61672','Out':'61852'},'hcpad_80_vip':{'In':'61705','Out':'61885'},'hcpad_vip':{'In':'61651','Out':'61831'},'hcpadnew_80_vip':{'In':'61747','Out':'61927'},'hcproxy2_110_vip':{'In':'61763','Out':'61943'},'hcproxy2_143_vip':{'In':'61764','Out':'61944'},'hcproxy2_80_vip':{'In':'61748','Out':'61928'},'hcproxy2_993_vip':{'In':'61765','Out':'61945'},'hcproxy2_995_vip':{'In':'61766','Out':'61946'},'hetongcrm_vip':{'In':'61719','Out':'61899'},'hetongpdf_vip':{'In':'61720','Out':'61900'},'hfbzhifu_vip':{'In':'61706','Out':'61886'},'homeinc_vip':{'In':'61694','Out':'61874'},'hotso8080_vip':{'In':'61721','Out':'61901'},'hotso_vip':{'In':'61652','Out':'61832'},'hr_vip':{'In':'61621','Out':'61801'},'huifubao_gateway':{'In':'61767','Out':'61947'},'huifubao_gateway80_vip':{'In':'61797','Out':'61977'},'hycrm_vip':{'In':'61653','Out':'61833'},'im_9000_vip':{'In':'61695','Out':'61875'},'im_file_vip':{'In':'61696','Out':'61876'},'im_hcact_vip':{'In':'61707','Out':'61887'},'im_manage_vip':{'In':'61722','Out':'61902'},'im_online2_vip':{'In':'61736','Out':'61916'},'im_sms_vip':{'In':'61673','Out':'61853'},'im_ws_80_vip':{'In':'61708','Out':'61888'},'im_ws_vip':{'In':'61654','Out':'61834'},'imchat_vip':{'In':'61674','Out':'61854'},'imchatroom_vip':{'In':'61737','Out':'61917'},'imgb2b_vip':{'In':'61675','Out':'61855'},'imgup_vip':{'In':'61655','Out':'61835'},'imlogin_443_vip':{'In':'61749','Out':'61929'},'imlogin_5222_vip':{'In':'61768','Out':'61948'},'imlogin_80_vip':{'In':'61738','Out':'61918'},'imonline_web_vip':{'In':'61769','Out':'61949'},'imp2pold443_vip':{'In':'61750','Out':'61930'},'imp2pold80_vip':{'In':'61739','Out':'61919'},'imyz2_vip':{'In':'61656','Out':'61836'},'imyz_vip':{'In':'61638','Out':'61818'},'info_delivery_vip':{'In':'61774','Out':'61954'},'info_pubnew_vip':{'In':'61751','Out':'61931'},'info_upload_80_vip':{'In':'61783','Out':'61963'},'infoweb3':{'In':'61639','Out':'61819'},'infoweb4_vip':{'In':'61709','Out':'61889'},'jdcrm_vip':{'In':'61657','Out':'61837'},'log2_vip_34.243':{'In':'61752','Out':'61932'},'log2_vip_34.243_3306':{'In':'61790','Out':'61970'},'log2_vip_34.243_55535':{'In':'61794','Out':'61974'},'log4_vip':{'In':'61640','Out':'61820'},'log5_vip':{'In':'61641','Out':'61821'},'logb2b_vip':{'In':'61676','Out':'61856'},'logorg_vip':{'In':'61677','Out':'61857'},'logorg_vip_34.64_81':{'In':'61787','Out':'61967'},'mail_hc360_rec_vip':{'In':'61784','Out':'61964'},'mail_hc360_send_1_vip':{'In':'61795','Out':'61975'},'mail_hc360_send_2_vip':{'In':'61796','Out':'61976'},'mail_hcmailbox1_vip':{'In':'61788','Out':'61968'},'manage-im_vip':{'In':'61723','Out':'61903'},'manageb2b_vip':{'In':'61724','Out':'61904'},'managecredit_ftp_vip':{'In':'61791','Out':'61971'},'managecredit_vip':{'In':'61770','Out':'61950'},'managevms_vip':{'In':'61725','Out':'61905'},'markettrends_vip':{'In':'61771','Out':'61951'},'miniportal_vip':{'In':'61740','Out':'61920'},'mis2_vip':{'In':'61642','Out':'61822'},'mis_vip':{'In':'61627','Out':'61807'},'mjcrm_vip':{'In':'61658','Out':'61838'},'mjdown_vip':{'In':'61678','Out':'61858'},'mmtclient_ftp_vip':{'In':'61775','Out':'61955'},'mmtclient_vip':{'In':'61726','Out':'61906'},'mobile_info_vip':{'In':'61753','Out':'61933'},'mweb_vip':{'In':'61643','Out':'61823'},'myb2b2_vip':{'In':'61679','Out':'61859'},'myb2b_vip':{'In':'61659','Out':'61839'},'mycredit_vip':{'In':'61710','Out':'61890'},'nagios_vip':{'In':'61680','Out':'61860'},'newbbs_vip':{'In':'61681','Out':'61861'},'ngniximg00-14_vip':{'In':'61776','Out':'61956'},'ngniximg15-29_vip':{'In':'61777','Out':'61957'},'ngniximg_b2b_vip':{'In':'61772','Out':'61952'},'ngniximg_info_vip':{'In':'61778','Out':'61958'},'nps_vip':{'In':'61628','Out':'61808'},'openapi_vip':{'In':'61697','Out':'61877'},'opencrm_web_vip':{'In':'61754','Out':'61934'},'order_b2b_vip':{'In':'61727','Out':'61907'},'order_pub_vip':{'In':'61728','Out':'61908'},'partercredit8080_vip':{'In':'61792','Out':'61972'},'partnercredit_vip':{'In':'61779','Out':'61959'},'pay_dingdan_443':{'In':'61755','Out':'61935'},'pay_logs':{'In':'61644','Out':'61824'},'pay_logs_80':{'In':'61698','Out':'61878'},'pay_mmt_gateway':{'In':'61756','Out':'61936'},'pay_styles_vip':{'In':'61741','Out':'61921'},'pay_vip':{'In':'61629','Out':'61809'},'phone_vip':{'In':'61660','Out':'61840'},'press_org_8080_vip':{'In':'61785','Out':'61965'},'press_org_ftp_vip':{'In':'61780','Out':'61960'},'press_org_vip':{'In':'61729','Out':'61909'},'qdcrm_vip':{'In':'61661','Out':'61841'},'qdcrm_web_vip':{'In':'61730','Out':'61910'},'qiye_manage_vip':{'In':'61757','Out':'61937'},'qiye_web_vip':{'In':'61711','Out':'61891'},'renwu_vip':{'In':'61662','Out':'61842'},'renwumgr_vip':{'In':'61712','Out':'61892'},'reporter9300_vip':{'In':'61773','Out':'61953'},'reporter_vip':{'In':'61713','Out':'61893'},'rili':{'In':'61618','Out':'61798'},'rilimanager_vip':{'In':'61758','Out':'61938'},'score_vip':{'In':'61663','Out':'61843'},'sdclog_vip':{'In':'61682','Out':'61862'},'search2_vip':{'In':'61699','Out':'61879'},'search_lvci_3360_vip':{'In':'61793','Out':'61973'},'search_new_vip':{'In':'61742','Out':'61922'},'search_vip':{'In':'61683','Out':'61863'},'searchlvci_vip':{'In':'61743','Out':'61923'},'sell_vip':{'In':'61645','Out':'61825'},'sem_vip':{'In':'61630','Out':'61810'},'serviceorg_vip':{'In':'61744','Out':'61924'},'sessiondata_org_vip':{'In':'61789','Out':'61969'},'shehui_vip':{'In':'61684','Out':'61864'},'shopdns_vip':{'In':'61700','Out':'61880'},'sousuo_dsp_vip':{'In':'61745','Out':'61925'},'sso_https_vip':{'In':'61731','Out':'61911'},'sso_vip':{'In':'61631','Out':'61811'},'survy_vip':{'In':'61664','Out':'61844'},'syslog_smtplog_vip':{'In':'61786','Out':'61966'},'test':{'In':'61619','Out':'61799'},'test8082':{'In':'61646','Out':'61826'},'timesten17003_vip':{'In':'61781','Out':'61961'},'timesten17005_vip':{'In':'61782','Out':'61962'},'trademobile_vip':{'In':'61759','Out':'61939'},'tuan_ftp_vip':{'In':'61714','Out':'61894'},'tuan_new_vip':{'In':'61715','Out':'61895'},'uidorg_vip':{'In':'61685','Out':'61865'},'un_vip':{'In':'61622','Out':'61802'},'vmsim_vip':{'In':'61665','Out':'61845'},'vmsinfo1_vip':{'In':'61716','Out':'61896'},'vmsinfo_vip':{'In':'61701','Out':'61881'},'weixin_vip':{'In':'61686','Out':'61866'},'weshop_vip':{'In':'61687','Out':'61867'},'wlgateway_vip':{'In':'61732','Out':'61912'},'ws_vip':{'In':'61623','Out':'61803'},'wtd_vip':{'In':'61632','Out':'61812'},'wuliu_vip':{'In':'61666','Out':'61846'},'www1_bak_vip':{'In':'61717','Out':'61897'},'www_vip':{'In':'61633','Out':'61813'},'wwwim_vip':{'In':'61667','Out':'61847'}}
	global vip_list
	vip_list = []
	threads = []
	# l = threading.Lock()
	for k,v in VIP.items():
		t = threading.Thread(target=f5_vip1, args=(k,v,vip_list)) #多线程调用
		# t = threading.Thread(target=f5_vip1, args=(l,k,v,vip_list))
		threads.append(t)
	for i,t in zip(range(len(threads)),threads):
		t.start()
		if i % 50 == 0:
			time.sleep(0.05)
	for t in threads:
		t.join()
	totle_in = 0
	totle_out = 0
	vip_list = sorted(vip_list,key=lambda vip_list:vip_list[2])
	vip_list.reverse()
	for i in vip_list:
		totle_in = totle_in + float(i[1])
		totle_out = totle_out + float(i[2])
		i[1] = '%.5f' % i[1]
		i[2] = '%.5f' % i[2]
	totle_in = ('%.2f' % totle_in)
	totle_out = ('%.2f' % totle_out)
	vip_list.append(['TOTLE',totle_in,totle_out])	
	return vip_list
	
###########################################################################
@login_required(login_url="/login/")
@PermissionVerify()
def F5_vip(request):
	user = request.user
	return render_to_response('F5_vip.html',{'user':user})	
def vip_info(request):
	user = request.user
	try:
		# a = Zabbix()
		# data = a.f5_vip()
		data = vip_demo()#调用vip_demo函数获取vip的值
		print len(data)
		print data.__sizeof__() 
		return HttpResponse(json.dumps(data))
	except:
		print traceback.format_exc()
		return HttpResponse('error')
@login_required(login_url="/login/")
@PermissionVerify()
def lvs(request):
	user = request.user
	return render_to_response('LVS_info.html',{'user':user})	
def lvs_info(request):#lvs取消了
	user = request.user
	#lvs_info取lvs的信息函数写在curlping.py
	try:
		data = []
		# data = lvs_io()
		# if data != 'error':
			# return HttpResponse(json.dumps(data[0]))
		# else:
		return HttpResponse(json.dumps(data))
	except:
		print traceback.format_exc()
		return HttpResponse('error')
################END F5 和 LVS#####################################################

# 1434351600
# 1434351900
####################prot traffic################
def port_traffic(request):#端口流量
	user = request.user
	try:
		t_time = time.time()
		# ts = t_time - 900
		ts = t_time - 1500
		mList=Port_traffic.objects.filter(times__gte=ts).order_by('-values')
		#分页功能
		# for i in mList:
			# print i
		lst = SelfPaginator(request,mList, 50)
		return render_to_response('Port_traffic.html',{'user':user,'lPage':lst})
	except:
		print traceback.format_exc()
		return HttpResponse('error')
def search(request):#后台数据库过滤指定时间段数据
	try:
		user = request.user
		ip = request.GET.get('ip')
		t_time = time.time()
		# ts = t_time - 900
		ts = t_time - 1500
		mList=Port_traffic.objects.filter(Q(hostname__icontains=ip)).filter(times__gte=ts).order_by('-values')
		lst = SelfPaginator(request,mList, 50)
		return render_to_response('Port_traffic.html',{'user':user,'lPage':lst})
	except:
		print traceback.format_exc()
		return HttpResponse('error')