#!/usr/bin/env python

import sys,os,time
import django
platform=sys.platform
if platform.startswith('win'):
    cur_dir = os.path.split(os.path.realpath(sys.argv[0]))[0].split('\\')
else:
    cur_dir = os.path.split(os.path.realpath(sys.argv[0]))[0].split('/')[:-1]
    # print cur_dir
base_dir = '/'.join(cur_dir)
print base_dir

sys.path.append(base_dir)

os.environ['DJANGO_SETTINGS_MODULE'] ='automation.settings'
django.setup()
#--------Use Django Mysql model----------------
# from auto_auth import models
