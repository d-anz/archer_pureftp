#!/usr/bin/python
# -*- coding:utf-8 -*-
from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.decorators import login_required
from server.lib.server_forms import *
from server.lib.server_lib import *
from django.template import RequestContext
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.decorators import user_passes_test
from library.common import paging
import json


def super_user_required(login_url=None):
    # return user_passes_test(lambda u: u.is_staff, login_url='/error_403')
    return user_passes_test(lambda u: u.is_superuser, login_url='/error_403')


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def server_list(request):
    """
    服务器列表
    :param request:
    :return:
    """
    page = request.REQUEST.get('page', 1)
    data = Server.objects.all()
    data, page_range = paging(page, data, 40)
    return render_to_response('server/list.html', {'data': data, 'page_range':page_range},
                              context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def server_add(request):
    """
    批量添加服务器
    :param request:
    :return:
    """
    if request.method == 'POST':
        form = ServerAddForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            server_name = cd['server_name']
            server_ip = cd['server_ip']
            server_description = cd['server_description'] if cd['server_description'] else ''  # 描述
            res, msg = False, '机器已经存在，请核实'
            try:
                Server.objects.get(server_ip=server_ip)
            except Server.DoesNotExist:
                s = Server(server_name=server_name, server_ip=server_ip, server_description=server_description)
                s.save()
                res, msg = True, '机器添加成功'
            # 前端提示
            if res:
                messages.add_message(request, messages.SUCCESS, msg)
            else:
                messages.add_message(request, messages.ERROR, msg)
        else:
            messages.add_message(request, messages.ERROR, '数据提交不完整！')
        return HttpResponseRedirect('/server/list/')
    else:
        users = User.objects.all()
        return render_to_response('server/add.html',
                                  {'users': users},
                                  context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def server_edit(request):
    """
    修改服务器信息
    :param request:
    :return:
    """
    if request.method == 'POST':
        form = ServerEditForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            ops_server = OpsServer()
            res, msg = ops_server.edit_server(cd)
            # process_logs
            messages.add_message(request, messages.SUCCESS, msg)
        else:
            messages.add_message(request, messages.ERROR, '参数不足！')
        return HttpResponseRedirect('/server/list/')
    else:
        "编辑页面"
        server_id = request.REQUEST.get('server_id', '')
        if server_id == '':
            messages.add_message(request, messages.ERROR, 'server_id异常！')
            return HttpResponseRedirect('/server/list/')
        else:
            ops_server = OpsServer()
            data = ops_server.get_server_info(server_id)
            users = User.objects.all()
            data['users'] = users
            return render_to_response('server/edit.html', data, context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def server_del(request):
    """
    :param request:
    :return:
    """
    server_id = request.GET.get('server_id')
    if server_id != '':
        try:
            Server.objects.get(pk=server_id).delete()
            msg = '删除成功'
        except Server.DoesNotExist:
            msg = '删除失败, 不存在!'

    else:
        msg = '删除失败, server_id为空'
    messages.add_message(request, messages.INFO, msg)
    return HttpResponseRedirect('/server/list/')
