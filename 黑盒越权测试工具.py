import os
import re
import sys
import ast
import time
import json
import glob
import yaml
import base64
import requests
import urllib3
urllib3.disable_warnings()
from PyQt6.QtGui import *
from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from my_requests import *


# green   #00A000
# red     #DC143C
# orange  #FF8C00

ToolName='黑盒越权测试工具'
Version='V1.2.0'
Author='Abs1nThe'

################ 线程 ################
class WorkerThread(QThread):
    response_T=pyqtSignal(str)
    textEdit_T=pyqtSignal(str)
    showMessage_T=pyqtSignal(str)

    def __init__(self, headerTxt,textEdit,proxy_button,proxy,https,onlyCookies,mode,request,response,Patterns,delete_req_header,delete_header_button,
                 check_res_header,check_res_header_button,LogSwitch,action_printHtml,action_SetCookie):
        super().__init__()
        self.mode = mode
        self.proxy = proxy
        self.https = https
        self.request = request
        self.textEdit = textEdit
        self.response = response
        self.Patterns = Patterns
        self.LogSwitch = LogSwitch
        self.headerTxt = headerTxt
        self.onlyCookies = onlyCookies
        self.proxy_button = proxy_button
        self.check_res_header = check_res_header
        self.action_printHtml = action_printHtml
        self.action_SetCookie = action_SetCookie
        self.delete_req_header = delete_req_header
        self.delete_header_button = delete_header_button
        self.check_res_header_button = check_res_header_button

    def run(self):
        self.logFile = time.strftime("./logs/%Y%m%d.html", time.localtime(time.time()))
        header = self.textEdit.toPlainText()

        ############## 设置代理 ##############
        if self.proxy_button.isChecked():
            proxies.update({'http': self.proxy.text(), 'https': self.proxy.text()})
        else:
            proxies.update({'http': '', 'https': ''})

        ############## 从request获取请求方式、path、header等 ##############
        req = self.request.toPlainText()
        if req.strip() == '':
            self.response_T.emit('<span style="color:#DC143C">bad request</span>')
            return
        iferror, method, path, host, url, headers, isjson, body = GetRequest(self.https.currentText(), req)
        if not iferror:  # 缺失告警
            self.response_T.emit('<span style="color:#DC143C">bad request</span>')
            self.showMessage_T.emit('Error 请求失败,检查method,path,host')
            return

        bakheaders = headers.copy()
        ############## 替换header ##############
        if header.strip() != '':
            jsonHeader = str_to_json(header)        # header 来自替换
            for key, value in jsonHeader.items():
                headers[key] = value                # headers 来自request
        else:
            jsonHeader={}

        ############## 删除指定请求头 ##############
        if self.delete_header_button.isChecked():
            delete = re.split('[,.;，。；、]',self.delete_req_header.toPlainText().partition('#')[0]) # 取值
            delete = [i.lower() for i in delete]  # 小写
            delete = list(filter(lambda x: x.strip() != '', delete))  # 去空
            delete = list(set(delete))  # 去重
            doDelete = []
            for key in headers.keys():
                if key.lower() in delete:
                    doDelete.append(key)
            for key in doDelete:
                headers.pop(key)
        self.showMessage_T.emit('Loading...')

        ############## 发送请求 ##############
        res = GetResponse(method, url, headers, isjson, body, proxies)
        if res==False:
            self.response_T.emit('<span style="color:#DC143C">request fail,check url</span>')
            self.showMessage_T.emit('Error 请求失败,检查url')
            return
        status=res.status_code
        dict_res_header = dict(res.headers)
        reason=res.reason
        body=res.text

        ############## 更新token ##############
        try:
            txt=self.Patterns.currentText()
            if '标准' not in txt:
                for mode in self.mode:
                    if mode['mode']==txt:
                        n=1
                        while n in mode.keys():
                            if status == mode[n]['status'] and any(i in body for i in mode[n]['body']):
                                with open(mode[n]['request'],'r',encoding='utf-8') as f:
                                    if 'https' in mode[n]['request']:
                                        Tiferror, Tmethod, Tpath, Thost, Turl, Theaders, Tisjson, Tbody = GetRequest('https', f.read())
                                    else:
                                        Tiferror, Tmethod, Tpath, Thost, Turl, Theaders, Tisjson, Tbody = GetRequest('http', f.read())
                                    f.close()
                                if Tiferror==False:
                                    show_popup('Error', '更新token: txt解析错误')
                                    return
                                else:
                                    Theaders={**{'Cookie':headers['Cookie']},**Theaders}
                                    Tres=GetResponse(Tmethod,Turl,Theaders,Tisjson,Tbody,proxies)
                                    if Tres.status_code==mode[n]['get_token']['status']:
                                        # 从响应体获取token
                                        result = eval(mode[n]['get_token']['where'])
                                        # 更新请求头token
                                        Ttoken=mode[n]['get_token']['value']
                                        jsonHeader[Ttoken]=result
                                        if Ttoken not in self.onlyCookies.text():
                                            self.onlyCookies.setText(f'{self.onlyCookies.text()},{Ttoken}')
                                        self.textEdit_t.emit(json_to_str(jsonHeader))
                                self.response_T.emit('<span style="color:#00A000">更新 token 成功,重新请求</span>')
                                return
                            n+=1

        except:pass

        ############## 记录日志 ##############
        req_1 = '\n'.join(req.split('\n')[0:2])
        req_2 = req.partition('\n\n')[2]
        if self.LogSwitch == True:
            if not os.path.isdir('./logs'):
                os.mkdir('./logs')
            if not os.path.isfile(self.logFile):
                with open(self.logFile, 'a', encoding='utf-8') as log:
                    log.write('<head><style type="text/css">.div1{margin-left:40px;}</style><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/></head>')
                    log.close()
            with open(self.logFile, 'a', encoding='utf-8') as log:
                log.write(time.strftime("<details><summary>[%Y/%m/%d %H:%M:%S] ",time.localtime(time.time())) + url +
                          " ["+ecd(self.headerTxt)+"]</summary>" + # self.headerTxt1.text()
                          "<div class=\"div1\"><p>" + req_1.replace('\n', '<br>') + '<br>' +
                          ''.join([key + ': ' + value + '<br>' for key, value in headers.items()]) +
                          '<br>' + req_2.replace('\n', '<br>') + "</p><br>")
                log.write('<p>[response:]<br>' + str(status) + " " + reason + "<br>" +
                          ''.join([k + ':' + v + '<br>' for k, v in dict_res_header.items()]) + "<br><span>" +
                          ecd(body).encode("utf-8").decode() + "</span></p></div></details>")
                log.close()

        ############## 检查响应头 ##############
        bad_res_header = []  # 错误响应头
        lack_res_header = []  # 缺失响应头
        if self.check_res_header_button.isChecked():
            dict_check_res_header = str_to_json(self.check_res_header.toPlainText())
            dict_res_header2 = {key.lower(): dict_res_header[key].replace(' ', '').lower() for key, value in dict_res_header.items()}
            dict_res_header3 = {key.lower(): dict_res_header[key] for key, value in dict_res_header.items()}
            for key, value in dict_check_res_header.items():
                try:
                    if key.lower() not in dict_res_header2.keys():
                        lack_res_header.append(ecd(key))  # 缺失
                    elif value.strip() == '':  # 只检查是否存在
                        pass
                    elif (value.replace(' ', '').lower() == dict_res_header2[key.lower()] or re.findall(value,dict_res_header3[key.lower()],re.IGNORECASE)):
                        pass
                    elif value.replace(' ', '').lower() != dict_res_header2[key.lower()]:
                        bad_res_header.append(ecd(key.lower()))  # 错误
                except:
                    pass

        ############## 输出响应码，响应头 ##############
        set_cookie_flag=False
        response_text = str(status) + ' ' + reason + '<br>'
        for key, value in dict_res_header.items():
            if key.lower() in bad_res_header:
                response_text += f'<span style="color:#DC143C">{key}: {str(value)}</span><br>'
            elif key.lower() in ['content-length','server']:
                response_text += f'<span style="color:#FF8C00">{key}:</span> {str(value)}<br>'
            elif key.lower() == 'set-cookie':
                set_cookie = get_set_cookie(dict_res_header)
                set_cookie_flag=True
                for i in set_cookie:
                    response_text += f'<span style="color:#FF8C00">{key}:</span> <span style="color:#4682B4">{str(i[0])}</span>={str(i[1])}; {str(i[2])}<br>'
            else:
                response_text += f'<span style="color:#00A000">{key}:</span> {str(value)}<br>'
        if len(lack_res_header) > 0:
            response_text += '<span style="color:#DC143C">缺失安全响应头: <br>' + '<br>'.join(lack_res_header) + '</span><br>'
        self.response_T.emit(response_text)

        ############## 输出响应体 ##############
        if self.action_printHtml.isChecked():
            self.response_T.emit('<span style="color:#000000">%s</span><br>' % json_or_xml_body(res.headers, res.text.strip()).replace('\n', '<br>').replace(' ', '&nbsp;'))
        else:
            self.response_T.emit('<span style="color:#000000">%s</span><br>' % ecd(json_or_xml_body(res.headers, res.text.strip())).replace('\n', '<br>').replace(' ', '&nbsp;'))
        self.showMessage_T.emit('Success 请求成功')

        ############## Set-Cookie ##############
        if self.action_SetCookie.isChecked() and status<400:
            if set_cookie_flag==True:
                if 'Cookie' not in self.onlyCookies.text():
                    self.onlyCookies.setText(self.onlyCookies.text() + ',Cookie')
                if 'Cookie' in bakheaders.keys() and 'Cookie' not in jsonHeader.keys():
                    jsonHeader={**{'Cookie':bakheaders['Cookie']},**jsonHeader}
                for i in set_cookie:
                    jsonHeader=updateCookie(jsonHeader, i[0], i[1])
                self.textEdit_T.emit(json_to_str(jsonHeader))

################ 自定义QTextEdit + 失焦 ################
class MyQTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super(MyQTextEdit, self).__init__(parent)

    def setColor(self):
        if self.objectName().startswith('zhushi'):
            txt=self.toPlainText().strip().split('\n')
            output=[]
            for i in txt:
                if '#' in i:
                    output.append(f'{i.partition("#")[0]}<span style="color:#A5A5A5">#{i.partition("#")[2]}</span>')
                else:
                    output.append(f'<span style="color:#000000">{i}</span>')
            self.setText('<br>'.join(output))
        elif self.objectName() == 'request':
            req = self.toPlainText()
            headers = req.partition('\n')[2].partition('\n\n')[0].strip()
            if req and headers:
                body=req.partition(headers)[2].strip()
                temp = []
                for i in headers.split('\n'):
                    key=ecd(i.partition(':')[0])
                    value=ecd(i.partition(':')[2].strip())
                    if key.lower() =='cookie':
                        dict1=str_to_cookie(value)
                        dict1= {'<span style="color:#4682B4 ">%s</span>' % key:dict1[key] for key, value in dict1.items()}
                        value=cookie_to_str(dict1)
                    temp.append(f'<span style="color:#00A000">{key}</span>: {value}')
                self.setText(ecd(req.partition(headers)[0]).replace('\n', '<br>') + '<br>'.join(temp) + '<br>')
                tempheaders=str_to_json(headers)
                if 'Content-Type' in tempheaders and 'json' in tempheaders['Content-Type']:
                    try:
                        jsonBody = str(''.join([i.strip() for i in body.strip('\n')]))
                        self.append(ecd(json_or_xml_body({"Content-Type":'json'},jsonBody)).replace('\n','<br>').replace(' ','&nbsp;'))
                    except:
                        self.append(ecd(body).replace('\n', '<br>'))
                else:
                    self.append(ecd(body).replace('\n', '<br>'))
        elif 'header' in self.objectName():
            try:
                list1 = self.parent().parent().onlyCookies.text().partition('筛选请求头:')[2]  # 失焦触发
            except:
                list1 = self.parent().onlyCookies.text().partition('筛选请求头:')[2]  # self.header1.setColor() 初次
            list1 = re.split('[,.;，。；、]',list1)
            list1 = list(filter(lambda x: x.strip() != '', list1))  # 去空
            list1 = list(set(list1))  # 去重
            temp = []
            for i in self.toPlainText().strip().split('\n'):
                if i:
                    key = ecd(i.partition(':')[0])
                    value = ecd(i.partition(':')[2].strip())
                    if key.lower() =='cookie':
                        dict1=str_to_cookie(value)
                        dict1= {'<span style="color:#4682B4 ">%s</span>' % key:dict1[key] for key, value in dict1.items()}
                        value=cookie_to_str(dict1)
                    if list1 != []:
                        if key in list1:
                            temp.append(f'<span style="color:#00A000">{key}</span>: {value}')
                    else:
                        temp.append(f'<span style="color:#00A000">{key}</span>: {value}')
            self.setText('<br>'.join(temp))
        else:
            temp = []
            for i in self.toPlainText().strip().split('\n'):
                if i:
                    temp.append(f'<span style="color:#00A000">{ecd(i.partition(":")[0])}</span>: {ecd(i.partition(":")[2].strip())}')
            self.setText('<br>'.join(temp))

    def focusOutEvent(self, event):  # 失焦
        super(MyQTextEdit, self).focusOutEvent(event)
        self.setColor()


class Example(QMainWindow):
    def __init__(self):
        super().__init__()
        ############## 获取配置文件，初始化配置文件 ##############
        self.configFile = './config/config.yaml'
        if not os.path.isdir('./config'):
            os.mkdir('./config')
        if not os.path.isfile(self.configFile):
            with open(self.configFile, 'w', encoding='utf-8') as f:
                f.write('#日志记录\nLog: true\n\n' +
                        '#http代理\nproxy: "http://127.0.0.1:8080"\n\n' +
                        '#筛选请求头\nonlyCookies: "筛选请求头:Cookie,X-Csrf-Token"\n\n' +
                        'header: ["请求头1","请求头2","请求头3","请求头4","请求头5","请求头6"]\n' +
                        'header5: {"Cookie":"","X-Csrf-Token":""}\n\n' +
                        'header6: {"Origin":"http://1.huawei.com","Referer":"http://1.huawei.com"}\n\n' +
                        '#请求\n' +
                        'request: ""\n\n' +
                        '#删除指定请求头\n' +
                        'delete_req_header: "Cookie,X-Csrf-Token,Referer#,Origin"\n\n' +
                        '#检查响应头\n' +
                        'check_res_header: {' +
                        '"x-frame-options":"(SAMEORIGIN)|(DENY)",' +
                        '"x-content-type-options":"nosniff",' +
                        '"x-xss-protection":"1;mode=block",' +
                        '"strict-transport-security":"",' +
                        '"content-security-policy":"",' +
                        '"access-control-allow-origin":"^http(.*?).huawei.com",' +
                        '"access-control-allow-credentials":"true"}')
                f.close()

        ############## 读取基本配置 ##############
        self.LogSwitch = False
        self.proxy1 = 'http://127.0.0.1:8080'
        self.onlyCookies1='筛选请求头:'
        self.listHeader=['请求头1','请求头2','请求头3','请求头4','请求头5','请求头6']
        self.headers = ['','','','','','']
        self.request1=''
        self.delete_req_header1=''
        self.check_res_header1=''
        with open(self.configFile, 'r', encoding='utf-8') as f:
            config=yaml.safe_load(f)
            f.close()
        if 'Log' in config.keys():
            self.LogSwitch = config['Log']
        if 'proxy' in config.keys():
            self.proxy1 = config['proxy']
        if 'onlyCookies' in config.keys():
            self.onlyCookies1 = config['onlyCookies']
        if 'header' in config.keys():
            self.listHeader = config['header']
        if 'header1' in config.keys():
            self.headers[0] = config['header1']
        if 'header2' in config.keys():
            self.headers[1] = config['header2']
        if 'header3' in config.keys():
            self.headers[2] = config['header3']
        if 'header4' in config.keys():
            self.headers[3] = config['header4']
        if 'header5' in config.keys():
            self.headers[4] = config['header5']
        if 'header6' in config.keys():
            self.headers[5] = config['header6']
        if 'delete_req_header' in config.keys():
            self.delete_req_header1 = config['delete_req_header']
        if 'check_res_header' in config.keys():
            self.check_res_header1 = config['check_res_header']
        if 'request' in config.keys():
            self.request1 = config['request']

        ############## 读取模式配置 ##############
        try:
            with open('./config/mode.yaml', 'r', encoding='utf-8') as f:
                self.mode=yaml.load(f,yaml.Loader)
                f.close()
        except:pass

        self.initUI()
        self.menu()
        self.show()
        ############## 状态栏显示 ##############
        self.status = self.statusBar()
        self.status.showMessage(f'{ToolName} {Version}   By:{Author}',5000)  # 状态栏显示 文本 5秒

    def update_check_state(self, action):
        if action.isChecked():
            action.setIconVisibleInMenu(True)  # 显示勾号
            value = True
        else:
            action.setIconVisibleInMenu(False)  # 隐藏勾号
            value = False
        if action.objectName() == 'log':
            self.LogSwitch = value

    def freedomHeaderDef(self,check):
        if check:
            self.headerTxt6.setText('自由头')
            self.headerTxt6.setReadOnly(True)
            self.header6.setObjectName('freedomHeader')
        else:
            self.headerTxt6.setText('请求头6')
            self.headerTxt6.setReadOnly(False)
            self.header6.setObjectName('header6')
        self.header6.setColor()

    ############## 保存窗口 ##############
    def saveConfig_windows(self):  
        self.new_window = QWidget()

        self.new_window.resize(int(self.windows.width() * 0.3),int(self.windows.height() * 0.3))
        self.new_window.setWindowTitle('保存配置')
        grid1 = QGridLayout()

        self.save_log = QCheckBox("日志", self)
        self.save_proxy = QCheckBox("代理", self)
        self.save_onlyCookies = QCheckBox("筛选请求头", self)
        self.save_header1 = QCheckBox("请求头1", self)
        self.save_header2 = QCheckBox("请求头2", self)
        self.save_header3 = QCheckBox("请求头3", self)
        self.save_header4 = QCheckBox("请求头4", self)
        self.save_header5 = QCheckBox("请求头5", self)
        self.save_header6 = QCheckBox("请求头6", self)
        self.save_req = QCheckBox("request", self)
        self.save_req_header = QCheckBox("删除请求头", self)
        self.save_res_header = QCheckBox("检查响应头", self)
        self.selectAll_btn = QPushButton("全选", clicked=lambda: self.selectAll(self.new_window))
        self.saveConfig_btn = QPushButton("保存", clicked=lambda: self.saveConfig())

        grid1.addWidget(self.save_header1, 0, 0)
        grid1.addWidget(self.save_header2, 1, 0)
        grid1.addWidget(self.save_header3, 2, 0)
        grid1.addWidget(self.save_header4, 3, 0)
        grid1.addWidget(self.save_header5, 4, 0)
        grid1.addWidget(self.save_header6, 5, 0)
        grid1.addWidget(self.save_log, 0, 1)
        grid1.addWidget(self.save_proxy, 1, 1)
        grid1.addWidget(self.save_onlyCookies, 2, 1)
        grid1.addWidget(self.save_req, 3, 1)
        grid1.addWidget(self.save_req_header, 4, 1)
        grid1.addWidget(self.save_res_header, 5, 1)
        grid1.addWidget(self.selectAll_btn, 6, 0)
        grid1.addWidget(self.saveConfig_btn, 6, 1)

        self.new_window.setLayout(grid1)
        self.new_window.show()


    def selectAll(self,action):
        for checkbox in action.findChildren(QCheckBox):  # self.new_window中全部的QCheckBox
            checkbox.setChecked(True)

    def saveConfig(self):
        data={
        'Log': self.LogSwitch,
        'proxy': self.proxy.text(),
        'onlyCookies': self.onlyCookies.text(),
        'header': [self.headerTxt1.text(),self.headerTxt2.text(),self.headerTxt3.text(),self.headerTxt4.text(),self.headerTxt5.text(),self.headerTxt6.text()],
        'header1': str_to_json(self.header1.toPlainText()),
        'header2': str_to_json(self.header2.toPlainText()),
        'header3': str_to_json(self.header3.toPlainText()),
        'header4': str_to_json(self.header4.toPlainText()),
        'header5': str_to_json(self.header5.toPlainText()),
        'header6': str_to_json(self.header6.toPlainText()),
        'request': self.request.toPlainText().replace("\n","\\n"),
        'delete_req_header':self.delete_req_header.toPlainText(),
        'check_res_header':str_to_json(self.check_res_header.toPlainText())
        }
        with open(self.configFile,'w',encoding='utf-8') as f:
            yaml.dump(data,f,allow_unicode=True)
            f.close()
        self.new_window.close()  # 关闭窗口

    def menu(self):
        ############## 菜单栏 ##############
        bar = self.menuBar()
        # 往菜单栏添加菜单项目
        file = bar.addMenu("菜单")
        # 给菜单项目添加子菜单
        # new = file.addAction("新建")
        save = file.addAction("保存配置")
        save.setShortcut("CTRL+S")  # 设置快捷键
        save.triggered.connect(self.saveConfig_windows)

        action_log = QAction('记录日志', self, checkable=True)
        action_log.setObjectName('log')
        if self.LogSwitch == True:
            action_log.setChecked(True)
        action_log.triggered.connect(lambda: self.update_check_state(action_log))
        file.addAction(action_log)

        self.action_SetCookie = QAction('Set-Cookie', self, checkable=True)
        # self.action_SetCookie.setObjectName('setCookie')
        self.action_SetCookie.setChecked(True)
        # self.SetCookieSwitch='True'
        self.action_SetCookie.triggered.connect(lambda: self.update_check_state(self.action_SetCookie))
        file.addAction(self.action_SetCookie)

        self.action_printHtml = QAction('响应解析富文本', self, checkable=True)
        # self.action_printHtml.setObjectName('printHtml')
        self.action_printHtml.setChecked(False)
        self.action_printHtml.triggered.connect(lambda: self.update_check_state(self.action_printHtml))
        file.addAction(self.action_printHtml)

        self.freedomHeader = QAction('请求头6不筛选', self, checkable=True)
        self.freedomHeader.setChecked(True)
        self.freedomHeader.triggered.connect(lambda: self.update_check_state(self.freedomHeader))
        self.freedomHeader.triggered.connect(lambda: self.freedomHeaderDef(self.freedomHeader.isChecked()))
        self.freedomHeaderDef(self.freedomHeader.isChecked())
        file.addAction(self.freedomHeader)


    def initUI(self):
        self.setWindowTitle(f'{ToolName} {Version}   By:{Author}')
        self.windows=app.primaryScreen().availableGeometry()
        self.resize(int(self.windows.width() * 0.9),int(self.windows.height() * 0.8))

        ############## base64 Logo ##############
        ico = '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'
        logo = QPixmap()
        logo.loadFromData(base64.b64decode(ico))
        icon = QIcon()
        icon.addPixmap(logo)
        self.setWindowIcon(icon)
        # self.setWindowIcon(QIcon('logo.ico'))

        ############## 1 ##############
        grid = QGridLayout()
        self.https = QComboBox(self)
        self.https.addItems(['https', 'http'])
        grid.addWidget(self.https, 0, 0)
        self.headerTxt1 = QLineEdit(self)
        self.headerTxt2 = QLineEdit(self)
        self.headerTxt3 = QLineEdit(self)
        self.headerTxt4 = QLineEdit(self)
        self.headerTxt5 = QLineEdit(self)
        self.headerTxt6 = QLineEdit(self)
        grid.addWidget(self.headerTxt1, 1, 0)
        grid.addWidget(self.headerTxt2, 2, 0)
        grid.addWidget(self.headerTxt3, 3, 0)
        grid.addWidget(self.headerTxt4, 4, 0)
        grid.addWidget(self.headerTxt5, 5, 0)
        grid.addWidget(self.headerTxt6, 6, 0, 2, 1)

        ############## 2 ##############
        self.onlyCookies = QLineEdit(self)
        self.onlyCookies.setPlaceholderText('筛选请求头')
        self.onlyCookies.editingFinished.connect(lambda: self.onlyCookiesEditingFinished())  # self.onlyCookies 失焦时，处理全部header
        self.header1 = MyQTextEdit(self)  # 失焦
        self.header2 = MyQTextEdit(self)
        self.header3 = MyQTextEdit(self)
        self.header4 = MyQTextEdit(self)
        self.header5 = MyQTextEdit(self)
        self.header6 = MyQTextEdit(self)
        self.header1.setObjectName('header1')
        self.header2.setObjectName('header2')
        self.header3.setObjectName('header3')
        self.header4.setObjectName('header4')
        self.header5.setObjectName('header5')
        self.header6.setObjectName('header6')
        grid.addWidget(self.onlyCookies, 0, 1)
        grid.addWidget(self.header1, 1, 1)
        grid.addWidget(self.header2, 2, 1)
        grid.addWidget(self.header3, 3, 1)
        grid.addWidget(self.header4, 4, 1)
        grid.addWidget(self.header5, 5, 1)
        grid.addWidget(self.header6, 6, 1, 2, 1)

        ############## 3 ##############
        self.proxy_button = QCheckBox("启用代理", self)
        grid.addWidget(self.proxy_button, 0, 2)
        run1 = QPushButton("run", clicked=lambda: self.start_thread(self.header1,self.headerTxt1.text()))
        run2 = QPushButton("run", clicked=lambda: self.start_thread(self.header2,self.headerTxt2.text()))
        run3 = QPushButton("run", clicked=lambda: self.start_thread(self.header3,self.headerTxt3.text()))
        run4 = QPushButton("run", clicked=lambda: self.start_thread(self.header4,self.headerTxt4.text()))
        run5 = QPushButton("run", clicked=lambda: self.start_thread(self.header5,self.headerTxt5.text()))
        run6 = QPushButton("run", clicked=lambda: self.start_thread(self.header6,self.headerTxt6.text()))
        grid.addWidget(run1, 1, 2)
        grid.addWidget(run2, 2, 2)
        grid.addWidget(run3, 3, 2)
        grid.addWidget(run4, 4, 2)
        grid.addWidget(run5, 5, 2)
        grid.addWidget(run6, 6, 2, 2, 1)

        ############## 4 ##############
        self.proxy = QLineEdit(self)
        self.request = MyQTextEdit(self)  # 失焦
        self.request.setObjectName('request')
        self.request.setPlaceholderText("request")
        self.delete_header_button = QCheckBox("删除指定请求头", self)
        self.delete_req_header = MyQTextEdit(self)
        self.delete_req_header.setObjectName('zhushi')
        grid.addWidget(self.proxy, 0, 3)
        grid.addWidget(self.request, 1, 3, 5, 1)
        grid.addWidget(self.delete_header_button, 6, 3)
        grid.addWidget(self.delete_req_header, 7, 3)

        ############## 5 ##############
        self.Patterns = QComboBox(self)
        try:
            self.Patterns.addItems([i['mode'] for i in self.mode])
        except:pass
        self.Patterns.currentIndexChanged.connect(lambda: self.select_mode(self.Patterns.currentText()))
        self.response = QTextEdit(self)
        self.response.setPlaceholderText("response")
        self.response.setReadOnly(True)
        self.check_res_header_button = QCheckBox("检查响应头", self)
        self.check_res_header_button.setChecked(True)
        self.check_res_header = MyQTextEdit(self)  # 失焦
        grid.addWidget(self.Patterns, 0, 4)
        grid.addWidget(self.response, 1, 4, 5, 1)
        grid.addWidget(self.check_res_header_button, 6, 4)
        grid.addWidget(self.check_res_header, 7, 4)

        ############## 布局 ##############
        grid.setColumnStretch(0, 1)  # 第1列占总长度的1/ 1+5+1+10+10
        grid.setColumnStretch(1, 7)
        grid.setColumnStretch(2, 1)
        grid.setColumnStretch(3, 10)
        grid.setColumnStretch(4, 10)
        # grid.setRowStretch(0, 10)  # 第 1 行占总高度的 10%

        ############## 赋值 ##############
        try:
            for i in range(6):
                if self.headers[i] !='':
                    eval('self.header'+str(i+1)+'.setText(ecd(json_to_str(self.headers['+str(i)+'])))')
                eval('self.headerTxt'+str(i+1)+'.setText(self.listHeader['+str(i)+'].strip())')
            self.proxy.setText(self.proxy1.strip())
            self.onlyCookies.setText(self.onlyCookies1.strip())
            self.request.setText(ecd(self.request1.replace("\\n", "\n")))
            self.delete_req_header.setText(ecd(self.delete_req_header1.strip()))
            self.check_res_header.setText(ecd(json_to_str(self.check_res_header1)))
        except:
            show_popup('Error', 'config文件不规范')
            



        ############## 上色 ##############
        self.header1.setColor()
        self.header2.setColor()
        self.header3.setColor()
        self.header4.setColor()
        self.header5.setColor()
        #self.header6.setColor()
        self.check_res_header.setColor()
        self.request.setColor()
        self.delete_req_header.setColor()

        ############## 不接受用户的富文本插入 ##############
        self.header1.setAcceptRichText(False)
        self.header2.setAcceptRichText(False)
        self.header3.setAcceptRichText(False)
        self.header4.setAcceptRichText(False)
        self.header5.setAcceptRichText(False)
        self.header6.setAcceptRichText(False)
        self.check_res_header.setAcceptRichText(False)
        self.response.setAcceptRichText(False)
        self.delete_req_header.setAcceptRichText(False)
        self.request.setAcceptRichText(False)

        ############## 创建主界面窗口并设置为中心窗口 ##############
        mainwidget = QWidget()
        mainwidget.setLayout(grid)
        self.setCentralWidget(mainwidget)
    def start_thread(self,textEdit,headerTxt):
        self.response.clear()
        self.work_thread=WorkerThread(headerTxt,textEdit,self.proxy_button,self.proxy,self.https,self.onlyCookies,self.mode,self.request,self.response,
                self.Patterns,self.delete_req_header,self.delete_header_button,self.check_res_header,self.check_res_header_button,
                self.LogSwitch,self.action_printHtml,self.action_SetCookie)
        self.work_thread.response_T.connect(self.update_text_edit1)
        self.work_thread.textEdit_T.connect(lambda string:self.update_text_edit2(string,textEdit))
        self.work_thread.showMessage_T.connect(lambda string:self.status.showMessage(string,5000))
        self.work_thread.start()
    def update_text_edit1(self,string):
        self.response.append(string)
        self.response.moveCursor(QTextCursor.MoveOperation.Start)

    def update_text_edit2(self, string,textEdit):
        textEdit.setText(string)
        textEdit.setColor()
    def select_mode(self,txt):
        try:
            for i in self.mode:
                if i['mode']==txt:
                    self.onlyCookies.setText(i['onlyCookies'])
                    break
        except:pass

    def onlyCookiesEditingFinished(self):
        for i in range(6):
            n=str(i+1)
            if eval('self.header'+n+'.objectName()')=='header'+n:
                eval('self.header'+n+'.setColor()')





if __name__ == '__main__':
    proxies = {}
    app = QApplication(sys.argv)
    try:
        with open(glob.glob("*.qss")[0]) as f:
            app.setStyleSheet(f.read())
            f.close()
    except:
        pass
    ex = Example()
    sys.exit(app.exec())
