#-*- coding: utf-8 -*-
from django.db import models
from django.contrib.auth.models import User
# Create your models here.


# '用户表'
class auto_user(models.Model):
	user = models.OneToOneField(User)
	department_choice = (('1','系统部'),('2','网络部'),('3','---'),)
	department = models.CharField(max_length=50,choices=department_choice,default='---')
	perm_choice = (('1','有'),('2','无'),)
	group_perm =  models.CharField(max_length=20,choices=perm_choice,default='无')
	root_choice = (('1','是'),('2','不是'),)
	supper_root =  models.CharField(max_length=20,choices=root_choice,default='不是')
	api_key = models.CharField(max_length=200,blank=True)
	secretkey = models.CharField(max_length=200,blank=True)
	add_date = models.DateTimeField(auto_now_add=True)
	del_date = models.DateTimeField(null=True,blank=True)
	def __unicode__(self):
		return self.user.username
#交换机端口流量信息
class Port_traffic(models.Model):
	hostname = models.CharField(max_length=50,blank=True)
	key = models.CharField(max_length=50,blank=True)
	time_c = models.CharField(max_length=100,blank=True)
	times = models.IntegerField(blank=True)
	values = models.FloatField(blank=True)
	def __unicode__(self):
		return "%s-%s:%s" % (self.hostname,self.key,self.values)
#ip '主表'

# class hosts(models.Model):
	# ip = models.IPAddressField(unique=True)
	# hostname = models.CharField(max_length=100,blank=True)
	# department_choice = (('1','系统部'),('2','网络部'),('3','---'),)
	# department = models.CharField(max_length=50,choices=department_choice,default='---')
	# area = models.CharField(max_length=100,blank=True)
	# user_id = models.IntegerField(default=0)
	# run_state_choice = (('1','运行'),('2','未运行'),)
	# run_state = models.CharField(max_length=50,choices=run_state_choice,default='运行')
	# online_choice = (('1','在线'),('2','已删除'),)
	# is_online = models.CharField(max_length=50,choices=online_choice,default='在线')
	# add_date = models.DateTimeField(auto_now_add=True)
	# del_date = models.DateTimeField(null=True,blank=True)
	
	# def __unicode__(self):
		# return self.ip

		
		
#'资产表'

# class assets(models.Model):
	# ip = models.IPAddressField(unique=True)
	# equipment_choice = (('1','服务器'),('2','网络设备'),('3','其他'),)
	# equipment_type = models.CharField(max_length=50,choices=equipment_choice,default='其他')
	# machine_model = models.CharField(max_length=100,blank=True)
	# rack_location = models.CharField(max_length=100,blank=True)
	# machine_info = models.TextField(blank=True)
	# area = models.CharField(max_length=100,blank=True)
	
	# def __unicode__(self):
		# return self.ip


