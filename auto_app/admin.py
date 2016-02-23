from django.contrib import admin

# Register your models here.



from auto_app.models import *

class auto_userAdmin(admin.ModelAdmin):
    # list_display  = ('user','department') 
    list_display  = ('user','department','group_perm','supper_root','api_key','secretkey')
class Port_trafficAdmin(admin.ModelAdmin):
    # list_display  = ('user','department') 
    list_display  = ('hostname','key','time_c','times','values') 
# class hostsAdmin(admin.ModelAdmin):
    # list_display = ('ip','hostname')  
    # list_display = ('ip','hostname','department','user_id','run_state','is_online','add_date','del_date')
# class assetsAdmin(admin.ModelAdmin):
    # list_display = ('ip','equipment_type','machine_model','rack_location','machine_info','area')



admin.site.register(auto_user, auto_userAdmin)
admin.site.register(Port_traffic, Port_trafficAdmin)
# admin.site.register(hosts, hostsAdmin)
# admin.site.register(assets, assetsAdmin)

