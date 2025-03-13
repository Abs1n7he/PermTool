import re
import sys
import ast
import json
import inspect
import requests
import urllib3
urllib3.disable_warnings()
import xml.etree.ElementTree as ET

def ecd(str):
    return str.replace('<','&lt;').replace('>','&gt;')

def json_or_xml_body(headers,body):
    try:
        if 'Content-Type' in headers.keys():
            if 'json' in headers['Content-Type']:
                return json.dumps(json.loads(body), indent=4, ensure_ascii=False, sort_keys=False,separators=(',', ':'))
            elif 'xml' in headers['Content-Type']:
                return printXML(body).replace('ns0:','')
            else:
                return '\n'+body
        else:
            return '\n' + body
    except:
        print('响应格式化报错'+body)
        return '\n' + body

def str_to_json(str):
    dict1={}
    for i in str.split('\n'):
        dict1[i.partition(':')[0].strip()]=i.partition(':')[2].strip()
    return dict(filter(lambda x: x[0]!='',dict1.items())) #删除空key

def json_to_str(dict):
    return ''.join([key+': '+value+'\n' for key,value in dict.items()])

def str_to_cookie(str):
    dict1={}
    for i in str.split(';'):
        dict1[i.partition('=')[0].strip()]=i.partition('=')[2].strip()
    return dict(filter(lambda x: x[0]!='',dict1.items())) #删除空key

def cookie_to_str(dict):
    return '; '.join([key+'='+value for key,value in dict.items()])

def updateCookie(dict_headers,key,value):
    if 'Cookie' in dict_headers.keys():
        temp = str_to_cookie(dict_headers['Cookie'])
    else:
        temp={}
    temp[str(key)] = str(value)
    dict_headers['Cookie']=cookie_to_str(temp)
    return dict_headers

def printXML(str):          # XML 字符串格式化打印
    # 创建XML元素
    element = ET.XML(str)
    # 使用indent()函数进行格式化打印
    ET.indent(element)
    return ET.tostring(element, encoding='unicode')
    
def GetRequest(http,req): #从字符串获取请求内容
    method= req.partition(' ')[0].strip().lower()
    if method not in  ['get', 'options', 'delete','head','post', 'put']:
        return False,'请求方式错误','','','','','',''
    path=   req.partition(' ')[2].partition(' ')[0].strip()
    host=   req.partition('\n')[2].partition('\n')[0].partition(':')[2].strip()
    url = http + "://" + host + path
    headers=req.partition('\n')[2].partition('\n')[2].partition('\n\n')[0].strip()
    headers = str_to_json(headers)
    try:
        del headers['Content-Length']
    except:
        pass
    body = req.partition('\n\n')[2]
    if 'Content-Type' in headers.keys() and 'json' in headers['Content-Type'] and body.strip().startswith('{'):
        isjson=True
        body=str(''.join([i.strip() for i in body.strip().split('\n')]))
        try:
            body = json.loads(body)
        except:
            isjson=False
    else:
        isjson=False
    if not (method and path and host):#缺失告警
        return False,method,path,host,url,headers,isjson,body
    else:
        return True,method,path,host,url,headers,isjson,body

def GetResponse(method,url,headers,isjson,body,proxies):
    try:
        if method in ['get', 'options', 'delete','head','post', 'put']:
            if isjson:
                res = eval('requests.' + method + '(url,headers=headers,json=body,timeout=20,verify=False,proxies=proxies,allow_redirects=False)')
            else:
                res = eval('requests.' + method + '(url,headers=headers,data=body,timeout=20,verify=False,proxies=proxies,allow_redirects=False)')
        else:#请求方式错误告警
            return False
    except:
        return False
    return res

def get_set_cookie(res_header,set_cookie):  # dict(res.headers)
    SetCookie = re.split(r',\s*(?=[^;]+=)', res_header[set_cookie])
    return [[i.partition(';')[0].partition('=')[0].strip(),i.partition(';')[0].partition('=')[2].strip(),i.partition(';')[2].strip()] for i in SetCookie]



