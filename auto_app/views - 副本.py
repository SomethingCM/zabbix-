# -*- coding: UTF-8 -*-
from django.shortcuts import render_to_response
import datetime,json,time,datetime,traceback
from django.http import HttpResponse,HttpResponseRedirect
from django.contrib import auth
from auto_app import models
from django.contrib.auth.decorators import login_required

import salt
import subprocess
import cloudstackapi

from curl_ping import *
from zabbixsql2 import *
from Zabbix_db import *
from Zabbix_db1 import *
from zapi import *
from zabbix_api import *
# Create your views here.
######################################登陆视图函数，权限认证###############################
#'权限认证函数'

def is_root():
	try:
		info = 0
		user = request.user
		user_info = models.auto_user.objects.get(user__username=user.username)
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
def login(request):
	
	return render_to_response('login.html')
	
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


		
def logout(request):
	try:
		auth.logout(request)
		return HttpResponseRedirect('/login/')
	except:
		print traceback.format_exc()
		return HttpResponse('error')
##############################end 登陆函数################################


@login_required(login_url="/login/")	
def index(request):
	user = request.user
	return render_to_response('index.html',{'user':user})
	
################告警视图################
@login_required(login_url="/login/")	
def alarm(request):
	user = request.user
	return render_to_response('alarm.html',{'user':user})
def triggers(request):
	try:
		info = {}
		t = ZabbixTools()
		content = t.trigger_get()
		# print content
		for line in content:
			info[line['host']]=[line['host'],line['description']]
		# print info
		if request.GET.get('test') == 'test':
			return HttpResponse(json.dumps(info))
		else:
			list = []
			for line in content:
				list.append([line['host'],line['description']])
			return HttpResponse(json.dumps(list[0:5]))
	except:
		# print traceback.format_exc()
		return HttpResponse('error')

		
#####################监控信息状态##################
@login_required(login_url="/login/")	
def service_status(request):
	user = request.user
	return render_to_response('service_status.html',{'user':user})
def monitor_check(request):
	try:
		group_dict = {}
		group_list = ['Templates','Linux servers','Zabbix servers','Discovered hosts','Virtual machines','Hypervisors','CISCO Templates',"办公网","测试网","正式网","生产环境交换机 172.16.8.0","公网交换机","搜索部60段","运维服务器","云","BigIP"]
		
		for item in group_list:
			# print item
			zabbix = ReportForm(item)

			zabbix.getInfo()
			# print zabbix.InfoList
			if zabbix.IpInfoList:
				for ip ,list in  zabbix.IpInfoList.items():
					group_dict[ip] = [zabbix.IpInfoList[ip]['groupname'],zabbix.IpInfoList[ip]['ip'],zabbix.IpInfoList[ip]['system.cpu.load[percpu,avg5]']['avg'],zabbix.IpInfoList[ip]['vm.memory.size[available]']['avg'],zabbix.IpInfoList[ip]['vfs.fs.size[/,free]']['avg']]
			# print group_dict
		return HttpResponse(json.dumps(group_dict))
	except:
		# print traceback.format_exc()
		return HttpResponse('error')
#############web_ssh#########################
@login_required(login_url="/login/")	
def web_ssh(request):
	user = request.user
	return render_to_response('web_ssh.html',{'user':user})	
	
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

		
		
###########**************************saltstack start*********************************###########

		
# def saltstackhtml(request):
	# user = request.user
	# form = UploadFileForm()
	# return render_to_response('saltstack.html',{'user':user,'form':form})
@login_required(login_url="/login/")		
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
        node='192.168.46.71'
        cmd='grains.items'
        grains_info=salt.client.LocalClient().cmd_full_return(node,cmd)[node]['ret']
        id=grains_info['id']
        host=grains_info['host']
        domain=grains_info['domain']
        fqdn=grains_info['fqdn']
        nodename=grains_info['nodename']
        localhost=grains_info['localhost']
        server_id=grains_info['server_id']
        master=grains_info['master']
        ipv4=grains_info['ipv4']
        saltversion=grains_info['saltversion']
        pythonversion=grains_info['pythonversion']
        shell=grains_info['shell']
        defaultencoding=grains_info['defaultencoding']
        defaultlanguage=grains_info['defaultlanguage']
        os=grains_info['os']
        os_family=grains_info['os_family']
        kernel=grains_info['kernel']
        kernelrelease=grains_info['kernelrelease']
        ps=grains_info['ps']
        virtual=grains_info['virtual']
        cpu_model=grains_info['cpu_model']
        cpuarch=grains_info['cpuarch']
        num_cpus=grains_info['num_cpus']
        cpu_flags=grains_info['cpu_flags']
        num_gpus=grains_info['num_gpus']
        gpus=grains_info['gpus']
        mem_total=grains_info['mem_total']
        ip=grains_info['ipv4']
        path=grains_info['path']
        saltpath=grains_info['saltpath']
        pythonpath=grains_info['pythonpath']
        ###############################grains info####################################
        ###################################master_config################################
        f=open('/etc/salt/master','r')
        sshd_config=f.read()
        f.close()
        ##################################master_config################################
        ret = ""
        return render_to_response('saltstack.html',{'user':user,"username":username,"sshd_config":sshd_config,"result_data":ret,"error":error,"path":path,"id":id,"host":host,"domain":domain,"fqdn":fqdn,"nodename":nodename,"localhost":localhost,"server_id":server_id,"master":master,"ipv4":ipv4,"saltversion":saltversion,"pythonversion":pythonversion,"shell":shell,"defaultencoding":defaultencoding,"defaultlanguage":defaultlanguage,"os":os,"os_family":os_family,"kernel":kernel,"kernelrelease":kernelrelease,"ps":ps,"virtual":virtual,"cpu_model":cpu_model,"cpuarch":cpuarch,"num_cpus":num_cpus,"cpu_flags":cpu_flags,"num_gpus":num_gpus,"gpus":gpus,"mem_total":mem_total,"ipv4":ipv4,"path":path,"saltpath":saltpath,"pythonpath":pythonpath})
    return render_to_response('saltstack.html',{'user':user,"result_data":ret,"error":error})

def salt_key(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    proc = subprocess.Popen('salt-key', stdout=subprocess.PIPE)
    salt_key = proc.stdout.read().replace('\n','<br>')
    #return render_to_response('saltstack.html',{"salt_key":salt_key},context_instance=RequestContext(request))
    return HttpResponse(salt_key)
	
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
                f.close
            except:
                pass
        if request.method == "GET":
            try:
                f=open('/etc/salt/master','r')
                data=f.read()
                f.close
            except:
                data="The file /etc/salt/master is not exist"
    elif not request.is_ajax():
        print "-----------"
        return render_to_response('saltstack.html')
    return HttpResponse(data)

def saltstack_master_group(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    data='method is not allowed'
    if not os.path.isdir('/etc/salt/master.d'):
        os.mkdir('/etc/salt/master.d')
    if not os.path.exists('/etc/salt/master.d/node.conf'):
        f=open('/etc/salt/master.d/node.conf','w')
        f.write('You should setting group in /etc/salt/master.d/node.conf')
        f.close
    if request.is_ajax():
        if request.method == "POST":
            data=request.POST['name']
            print data
            try:
                f=open('/etc/salt/master.d/node.conf','r+')
                f.write(data)
                f.close
                print "add group"
            except:
                pass
        if request.method == "GET":
            try:
                f=open('/etc/salt/master.d/node.conf')
                data=f.read()
                f.close
            except:
                data="The file /etc/salt/master.d/node.conf is not exist "
    return HttpResponse(data)

def saltstack_top_sls(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    data='method is not allowed'
    if not os.path.isdir('/srv/salt'):
        os.mkdir('/srv/salt')
    if not os.path.exists('/srv/salt/top.sls'):
        f=open('/srv/salt/top.sls','w')
        f.write('You should modify the /srv/salt/top.sls')
        f.close
    if request.is_ajax():
        if request.method == "POST":
            data=request.POST['name']
            print data
            try:
                f=open('/srv/salt/top.sls','r+')
                f.write(data)
                f.close
            except:
                pass
        if request.method == "GET":
            try:
                f=open('/srv/salt/top.sls')
                data=f.read()
                f.close
            except:
                data="The file /srv/salt/top.sls is not exist "
    return HttpResponse(data)



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
                f.close
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




############################******************saltstack end

"""
C.X   lvs 流量信息
"""
@login_required(login_url="/login/")	
def net_traffic(request):
	user = request.user
	return render_to_response('traffic.html',{'user':user})

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
def get_Zabbix_db1(request):
	try:
		dd = search_zabbix1()
		
		
#		res = []
#		for item in list:
#			y,m,da=item.date.encode("utf-8").split('-')
#			d = datetime.date(int(y),int(m),int(da))
#			t = time.mktime(d.timetuple())*1000
#			print y,m,da,d
#			res.append([t,float(item.fault_rate)])
		return HttpResponse(json.dumps(dd))
	except:
		print traceback.format_exc()
		return HttpResponse('error')
		
		
#############仪表盘#########################
	
def dashboard(request):
	user = request.user
	return render_to_response('dashboard.html',{'user':user})	
	
def curl_ping(request):
	try:
		# data1 = [[1,2,3],[0.6,0.8,1],[1,2,3],[1,0.4,0.6],[0.6,0.8,1],[1,2,3]]
		data = net_info()
		# print type(data)
		# print data
		# print data1
		return HttpResponse(json.dumps(data))
	except:
		print traceback.format_exc()
		return HttpResponse('error')

def loadbance(request):	
	try:
		data = []
		a = Zabbix()
		f5 = a.f5()
		# print f5
		data.append(f5)
		data.append(['慧敏',0,0,0,0])
		data.append(['LVS-a',0,0,0,0])
		data.append(['LVS-b',0,0,0,0])
		data.append(['LVS-c',0,0,0,0])
		return HttpResponse(json.dumps(data))
	except:
		print traceback.format_exc()
		return HttpResponse('error')	
#############cloudstack#######################

# @login_required(login_url="/")	
# def cloud_web(request):
	# user = request.user
	# return render_to_response('cloud_web.html',{'user':user})	
	
	
def signin(user):
	try:
		global api   #定义一个全局变量
		user_in = models.auto_user.objects.get(user__username=user.username)
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
			# print result['virtualmachine'][0]
			return render_to_response('cloud_web.html',{'user':user,'results':result['virtualmachine']})
		else:
			return render_to_response('cloud_web.html',{'user':user,'err':'您没有云平台使用权限，请联系管理员!'})
	except:
			return render_to_response('cloud_web.html',{'user':user,'err':'您没有云平台使用权限，请联系管理员!'})
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
			
