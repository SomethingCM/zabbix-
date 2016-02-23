# -*- coding: UTF-8 -*-
########上传############
from django import forms

class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=50)
    file = forms.FileField()

'''文件上传'''
import os
def handle_uploaded_file(f):
    file_name = ""

    try:
        path = "/srv/salt/" 
        if not os.path.exists(path):
            os.makedirs(path)
            file_name = path + f.name.encode('utf-8')
            destination = open(file_name, 'wb+')
            for chunk in f.chunks():
                destination.write(chunk)
            destination.close()
            data = 'ok'
            return data
    except Exception, e:
        print e
        data = 'fail'
        return data