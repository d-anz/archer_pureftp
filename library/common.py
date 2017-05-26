#!/usr/bin/env python
# -*- coding: utf-8 -*-
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib import messages
import re
import subprocess


def check_ip(ip):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(ip):
        return True
    else:
        return False


def render_message(request, message_error=False, msg=''):
    if message_error:
        messages.add_message(request, messages.ERROR, msg)
    else:
        messages.add_message(request, messages.SUCCESS, msg)


def runshell(command, stdinstr=''):
    """exec shell"""
    p = subprocess.Popen(command, shell=True, universal_newlines=True, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
    stdoutdata, stderrdata = p.communicate(stdinstr)
    p.stdin.close()
    return p.returncode, stdoutdata, stderrdata


def paging(page, data, size):
    """
    分页
    :param page:
    :param data:
    :param size:
    :return:
    """
    # 分页----开始
    paginator = Paginator(data, size)
    try:
        data = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        data = paginator.page(1)
        page = 1
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        data = paginator.page(paginator.num_pages)
        page = paginator.num_pages

    # 分页范围
    after_range_num = 5  # 当前页前显示5页
    before_range_num = 4  # 当前页后显示4页
    if page >= after_range_num:
        page_range = paginator.page_range[page - after_range_num:page + before_range_num]
    else:
        page_range = paginator.page_range[0:int(page) + before_range_num]
    # 分页----结束
    return data, page_range