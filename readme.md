# PermTool

是一款黑盒越权测试工具

## 一、安装：

python3

```
# 安装所需的 python 依赖
pip install requests
pip install PyQt6
```

## 二、主要功能：

### 1、发送请求

选择**http/https**，**筛选请求头**输入用户凭证（如Cookie,X-Csrf-Token），从burp复制需要测试的请求到**request**和**请求头1**，点击**run**会将**request**中的请求头用**请求头1**中的请求头进行替换，然后发送请求，响应在**response**中显示。

![](img/ZXUUCD.png)

```
规则：
(1)、**request**中的内容不会改变；
(2)、**请求头n**中只会保留**筛选请求头**配置的项，所以不需要一个一个复制请求头，复制全部请求填入即可；
```

### 2、越权测试

同理，在**请求头2**中，填入另一个用户的请求头，就可以快速用两个用户的凭证测试同一个接口是否存在越权。

## 附加功能

### 1、删除指定请求头

不需要删除**request**中的请求头，在**删除指定请求头**中配置即可，可用于测试未授权，或临时去掉某个请求头。

![](img/YHCMFG.png)

### 2、检查响应头

检查是否配置安全响应头

```
规则：
(1)、值为空则只判断是否存在
(2)、支持正则匹配
(3)、忽略大小写
```

![](img/TMAEAM.png)

### 3、保存配置

![](img/MMIUDK.png)

![](img/RJYGBN.png)

### 4、记录日志

记录请求和响应到log目录下的html文件

### 5、set-cookie

响应码400以下出现set-cookie，会自动更新到对应的**请求头n**

![](img/WYXXEG.png)

### 6.模式

主要用于预设**筛选请求头**和实现**自动更新token**，此功能解决了测试过程中token总是失效的痛点

配置方法：config/mode.yaml

```yaml
- mode: "模式: 自动更新token"                       #显示名称
  onlyCookies: "筛选请求头:Cookie,X-Csrf-Token"     #配置筛选请求头的内容
  1:                                              #第一种情况，数字必须连续
    status: 400                                   #token失效时的响应码
    body:
    - 'csrf'                                      #token失效时的响应体含csrf或bad
    - 'bad'
    request: "./config/https_update_token.txt"    #将更新token的请求放入txt，文件名中有https，则使用https请求
    get_token:
      status: 200                                 #成功获取token时的响应码
      value: "X-Csrf-Token"                       #token在请求头中的字段
      where: "json.loads(Tres.text)['token']"     #响应Tres的响应体，转为json格式，取'token'的值，为新的token
      #dict(res.headers)['X-Csrf-Token']          #响应Tres的响应头，取'X-Csrf-Token'的值，为新的token
```



## 免责声明：

本工具仅面向合法授权的企业安全建设行为，在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权，请勿对非授权目标进行扫描。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容，除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。