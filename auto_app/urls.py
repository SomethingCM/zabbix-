from django.conf.urls import patterns, include, url
from django.contrib import admin
from views import *
urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'automation.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
	# (r'^user_center/$', user_center),
	# (r'^passwd_change/$', passwd_change),
	url(r'^index/$', index),
	(r'^triggers/$', triggers),
	(r'^alarm/$', alarm),
	(r'^Switch_status/$', Switch_status),
	(r'^Physical_status/$', Physical_status),
	(r'^Windows_status/$', Windows_status),
	(r'^monitor_check/(\w+)/$', monitor_check),
	(r'^F5_vip/$', F5_vip),
	(r'^vip_info/$', vip_info),
	(r'^lvs/$', lvs),
	(r'^lvs_info/$', lvs_info),
	(r'^net_traffic/$', net_traffic),
	
	(r'^port_traffic/$', port_traffic),
	(r'^search/$', search),

	(r'^get_Zabbix_db/$', get_Zabbix_db),
	(r'^get_Zabbix_db1/(\d+)/$', get_Zabbix_db1),


	(r'^web_ssh/$', web_ssh),
	

	(r'^saltstack/$', saltstack),
	(r'^salt_key/$', salt_key),
	(r'^saltstack_master_config/$', saltstack_master_config),
	(r'^saltstack_master_group/$', saltstack_master_group),
	(r'^saltstack_top_sls/$', saltstack_top_sls),
	(r'^saltstack_os_path_edit/$', os_path_edit),
	(r'^upload_file/$', upload_file),
	
	(r'^dashboard/$', dashboard),
	(r'^curl_ping/$', curl_ping),
	(r'^loadbance/$', loadbance),
	
	
	(r'^cloud_web/$', cloud_web),
	(r'^cloud_register/$', cloud_register),
	# (r'^cloud_create/$', cloud_create),
	
)
