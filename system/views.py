#!/usr/bin/python
# -*- coding:utf-8 -*-
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.template import RequestContext
from django.contrib import messages
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render_to_response
from library.common import paging
from system.models import UserProfile
from system.forms import *
import pyotp
import urllib
import urllib2
import json


def super_user_required(login_url='/error_403'):
    """
    check permission
    :param login_url:
    :return:
    """
    return user_passes_test(lambda u: u.is_superuser, login_url=login_url)


def post_data(data, url):
    """
    POST方法
    :param data:
    :param url:
    :return:
    """
    try:
        data = urllib.urlencode(data)
        req = urllib2.Request(url, data, {})
        req.add_header('User-Agent', 'archer v1.0.1')
        content = urllib2.urlopen(req)
        # content = json.load(response)
        rs = True
    except urllib2.HTTPError, e:
        rs, content = False, 'Http接口请求异常，错误原因：' + e.message + ", code: " + e.code + ", url：" + \
                      url + ", data: " + str(data)
    except Exception, e:
        rs, content = False, 'Http接口请求异常，错误原因：' + e.message + ", url：" + url \
                      + ", data: " + str(data)
    return rs, content


def user_login(request):
    """
    用户登录视图
    :param request:
    :return:
    """

    archer_st = request.COOKIES.get('ARCHER_ST', '')
    st = request.REQUEST.get('st', '')
    response = HttpResponseRedirect('/')
    if request.user.is_authenticated():
        return response

    if st:
        response.set_cookie('ARCHER_ST', value=st, path='/')

    if archer_st or st:
        data = dict()
        data['st'] = archer_st if archer_st else st
        rs, content = post_data(data, settings.PASSPORT_USER)
        if rs:
            content = json.load(content)
        if rs and content["users_name"] and content['users_active']:
            try:
                user = User.objects.get(username=content['users_name'])
            except User.DoesNotExist:
                user = User.objects.create_user(content['users_name'], content['users_name']+'@archer.xin', '123456')
                user.is_superuser = True
                user.is_staff = True
                user.save()
            user = authenticate(username=user.username, password='')
            login(request, user)
        else:
            print archer_st
            messages.add_message(request, messages.ERROR, content)
            response = HttpResponseRedirect('/error_500')
            response.delete_cookie('ARCHER_ST', path='/')
        return response
    else:
        return HttpResponseRedirect(settings.PASSPORT_LOGIN + '?app_id=' + str(settings.APP_ID) +
                                    '&next=/system/u/login')


def user_logout(request):
    """
    用户注销
    :param request:
    :return:
    """
    response = HttpResponseRedirect(settings.PASSPORT_LOGOUT)
    response.delete_cookie('ARCHER_ST', path='/')
    logout(request)
    return response


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def user_list(request):
    """
    User list
    :param request:
    :return:
    """
    page = int(request.REQUEST.get('page', 1))
    data = User.objects.all().order_by('id')
    data, page_range = paging(page, data, 40)
    return render_to_response('system/user_list.html', {'data': data, 'page_range': page_range},
                              context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
def user_profile(request):
    """
    User Profile
    :param request:
    :return:
    """
    return render_to_response('system/profile.html', {}, context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def user_add(request):
    if request.method == 'POST':
        username = request.POST.get('username', '')
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')
        group = request.POST.get('group', '')
        permission = request.POST.getlist('permission')
        user = User.objects.filter(username=username)
        if not user:
            u = User.objects.create_user(username, email, password)
            u.last_name = last_name
            u.first_name = first_name
            u.groups = group
            u.user_permissions = permission
            u.save()
            p = UserProfile(user=u, otp=pyotp.random_base32(), avatar='')
            p.save()
            msg = '创建成功'
            res = True
        else:
            msg = '用户已经存在'
            res = False
        if res:
            messages.add_message(request, messages.SUCCESS, msg)
            return HttpResponseRedirect(reverse('system:system_user_list'))
        else:
            messages.add_message(request, messages.ERROR, msg)
            return HttpResponseRedirect(reverse('system:system_user_add'))
    else:
        groups = Group.objects.all()
        perms = Permission.objects.all()
        return render_to_response('system/create.html',
                                  {'groups': groups, 'perms': perms},
                                  context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def user_edit(request, uid):
    if request.method == 'POST':
        uid = request.POST.get('uid', '')
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        email = request.POST.get('email', '')
        group = request.POST.get('group', '')
        permission = request.POST.getlist('permission')
        try:
            u = User.objects.get(pk=uid)
            u.first_name = first_name
            u.last_name = last_name
            u.email = email
            u.groups = group
            u.user_permissions = permission
            u.save()
            res, msg = True, '用户：' + str(uid) + '修改成功！'
        except User.DoesNotExist:
            res, msg = False, '用户：' + str(uid) + '不存在！'
        if res:
            messages.add_message(request, messages.SUCCESS, msg)
        else:
            messages.add_message(request, messages.SUCCESS, msg)
        return HttpResponseRedirect(reverse('system:system_user_list'))
    else:
        data = User.objects.get(pk=uid)
        # group
        groups = Group.objects.all()
        group = data.groups.all()
        # permission
        permissions = Permission.objects.all()
        permission = data.user_permissions.all()
        return render_to_response('system/edit.html',
                                  {'data': data, 'permission': permission,
                                   'permissions': permissions,
                                   'groups': groups, 'group': group}, context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def user_del(request, uid):
    if uid:
        try:
            user = User.objects.get(pk=uid)
            msg = '用户：' + str(user.username) + ', 删除成功！'
            messages.add_message(request, messages.SUCCESS, msg)
            user.delete()
        except User.DoesNotExist:
            msg = '用户ID: ' + uid + ', 用户不存在！'
            messages.add_message(request, messages.SUCCESS, msg)
    return HttpResponseRedirect(reverse('system:system_user_list'))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def group_list(request):
    page = int(request.REQUEST.get('page', 1))
    data = Group.objects.all().order_by('id')
    data, page_range = paging(page, data, 40)
    return render_to_response('system/group_list.html', {'data': data, 'page_range': page_range},
                              context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def group_add(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        permission = request.POST.getlist('permission')
        try:
            Group.objects.get(name=name)
            res, msg = False, 'GroupIsExists!'
        except Group.DoesNotExist:
            g = Group(name=name)
            g.permissions = permission
            g.save()
            # for p in permission:
            #     g.permissions.add(p)
            res, msg = True, 'Create Success!'
        if res:
            messages.add_message(request, messages.SUCCESS, msg)
        else:
            messages.add_message(request, messages.ERROR, msg)

        return HttpResponseRedirect(reverse('system:system_group_list'))
    else:
        data = Permission.objects.all()
        return render_to_response('system/group_create.html',
                                  {'data': data}, context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def group_edit(request, gid):
    if request.method == 'POST':
        gid = request.POST.get('gid')
        name = request.POST.get('name')
        permission = request.POST.getlist('permission')
        try:
            g = Group.objects.get(pk=gid)
            g.name = name
            g.permissions = permission
            g.save()
            res, msg = True, 'role：edit success！'
        except User.DoesNotExist:
            res, msg = False, 'role：not exists！'
        if res:
            messages.add_message(request, messages.SUCCESS, msg)
        else:
            messages.add_message(request, messages.ERROR, msg)
        return HttpResponseRedirect(reverse('system:system_group_list'))
    else:
        data = Group.objects.get(pk=gid)
        group_perms = data.permissions.all()
        all_perms = Permission.objects.all()
        return render_to_response('system/group_edit.html',
                                  {'data': data, 'group_perms': group_perms,
                                   'all_perms': all_perms}, context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def group_del(request, gid):
    if gid:
        try:
            group = Group.objects.get(pk=gid)
            msg = '角色：' + str(group.username) + ', 删除成功！'
            messages.add_message(request, messages.SUCCESS, msg)
            group.delete()
        except Group.DoesNotExist:
            msg = '角色：' + str(gid) + ', 不存在，删除失败！！'
            messages.add_message(request, messages.ERROR, msg)
    return HttpResponseRedirect(reverse('system:system_group_list'))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def permit_list(request):
    data = Permission.objects.all().order_by('id')
    return render_to_response('system/permit_list.html', {'data': data}, context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def permit_add(request):
    """
    添加权限
    :param request:
    :return:
    """
    if request.method == 'POST':
        p = Permission()
        p.name = request.POST['name']
        p.codename = request.POST['codename']
        p.content_type_id = request.POST['content_type_id']
        p.save()
        res, msg = True, '权限添加成功，name: ' + request.POST['name'] + ' ,codename' + request.POST['codename']

        page = int(request.REQUEST.get('page', 1))
        if res:
            messages.add_message(request, messages.SUCCESS, msg)
        else:
            messages.add_message(request, messages.ERROR, msg)
        return HttpResponseRedirect(reverse('system:system_permit_list') + '?page=' + str(page))
    else:
        content_type_list = ContentType.objects.all()
        return render_to_response('system/permit_add.html', {'content_type_list': content_type_list},
                                  context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def permit_edit(request, pid):
    if request.method == 'POST':
        pid = request.POST.get('id')
        name = request.POST.get('name')
        try:
            g = Permission.objects.get(pk=pid)
            g.name = name
            g.save()
            res, msg = True, 'Success!'
        except Permission.DoesNotExist:
            res, msg = False, 'PermissionNotExists!'
        if res:
            messages.add_message(request, messages.SUCCESS, msg)
        else:
            messages.add_message(request, messages.ERROR, msg)
        return HttpResponseRedirect(reverse('system:system_permit_list'))
    else:
        data = Permission.objects.get(pk=pid)
        content_type_list = ContentType.objects.all()
        return render_to_response('system/permit_edit.html', {'data': data, 'content_type_list': content_type_list},
                                  context_instance=RequestContext(request))


@login_required(login_url='/system/u/login/')
@super_user_required(login_url="/error_403")
def permit_delete(request, pid):
    """
    添加权限
    :param pid:
    :param request:
    :return:
    """
    page = int(request.REQUEST.get('page', 1))
    try:
        Permission.objects.get(pk=pid).delete()
        msg = '删除权限成功，codename：' + p.codename + ', name:' + str(p.name)
        messages.add_message(request, messages.SUCCESS, msg)
    except Permission.DoesNotExist:
        msg = 'PermissionNotExists'
        messages.add_message(request, messages.ERROR, msg)
    return HttpResponseRedirect(reverse('system:system_permit_list') + '?page=' + str(page))