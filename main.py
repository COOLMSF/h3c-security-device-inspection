from abc import ABC
from abc import abstractmethod
import datetime
import sys, os
import requests
import base64
import subprocess
import json
import time
import concurrent.futures
import threading
import paramiko
from kubernetes import client, config
import math

import xml.etree.ElementTree as ET


import ddddocr
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium import webdriver
from rich.console import Console
from rich.table import Table
from urllib.parse import unquote

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

console = Console()

def print_colored(text, color):
    colors = {
        'red': '\033[31m',
        'green': '\033[32m',
        'reset': '\033[0m',
    }
    print(colors[color] + text + colors['reset'])

class CustomException(Exception):
    pass

# TODO: encrypt password
class SSHAuthentication(Exception):
    def __init__(self, oa_type: str, ip: str, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.oa_type = oa_type    
        self.ip = ip
    
    # 因为跳板机可以直接与k8s apiserver通信，
    # 所以直接进去OA层，拿出config文件，然后在跳板机和api server通信
    def get_ssh_client(self) -> any:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # Connect to the SSH server
            ssh_client.connect(self.ip, 22, self.username, self.password)

        except paramiko.AuthenticationException as auth_error:
            print(f"Authentication failed: {auth_error}")

        except paramiko.SSHException as ssh_error:
            print(f"SSH connection failed: {ssh_error}")

        except Exception as e:
            print(f"An error occurred: {e}")

        return ssh_client

class DeviceAuthentication(Exception):
    def __init__(self, dev_type: str, need_captcha: bool, ip: str, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.dev_type = dev_type
        self.need_captcha = need_captcha
        self.cookie = None
        self.session = None
        
    @abstractmethod
    def get_session_cookie(self):
        pass
    
    
# interface
class OAInspectionable(ABC):
    
    @abstractmethod
    def do_all_inspection(self) -> str:
        pass
    
    @abstractmethod
    def pod_inspecton(self) -> str:
        pass
    
class DeviceInspectionable(ABC):
        
    @abstractmethod
    def do_all_inspection(self) -> str:
        pass
    
    # interface method, need to be implemented
    @abstractmethod
    def cpu_inspection(self) -> str:
        pass
    
    # checking memory status
    @abstractmethod
    def memory_inspection(self) -> str:
        pass
    
    # checking storage status
    @abstractmethod
    def storage_inspection(self) -> str:
        pass
    
    @abstractmethod
    def interface_inspection(self) -> str:
        pass
    
    # checking signature library version
    # TODO checking h3c offcial newest version
    @abstractmethod
    def signatures_inspection(self) -> str:
        pass
    
    @abstractmethod
    def license_status_inspection(self) -> str:
        pass
    
    # checking license end time
    @abstractmethod
    def license_deadline_inspection(self) -> str:
        pass
    
    # checking engine or service status
    @abstractmethod
    def engine_inspection(self) -> str:
        pass
    
    # checking if time is right
    @abstractmethod
    def time_inspection(self) -> str:
        pass
    
class AInspection(OAInspectionable, SSHAuthentication):
    
    def __init__(self, oa_type: str, ip: str, username: str, password: str) -> None:
        # all pods information
        self.all_pods_info = {}
        SSHAuthentication.__init__(self, oa_type, ip, username, password)
        self.ssh_client = self.get_ssh_client()
    
    def do_all_inspection(self) -> str:
        self.pod_inspecton()
        # self.other_inspection()
    
    def pod_inspecton(self) -> str:
        try:
            self.copy_k8s_config_to_local()
        except Exception as E:
            print("Failed to copy k8s configuration to local")
            print(E)
            
        try:
            # load k8s config file
            config.load_kube_config(config_file="./config")
            api_instance = client.CoreV1Api()
        
            # List all pods in the default namespace
            namespace = 'default'  # Replace with the desired namespace
            api_response = api_instance.list_namespaced_pod(namespace=namespace)
            for pod in api_response.items:
                # print(f"Name: {pod.metadata.name}, Status: {pod.status.phase}")
                # retrieve the pod information, get name and pod status currently,
                # other info maybe later used, leave place
                self.all_pods_info[pod.metadata.name] = {"status": pod.status.phase}
        except Exception as e:
            print(f"Error: {e}")
        
        # 统计pod数量，数量不为3，并且状态不全未为running，则说明异常
        # TODO: 后续用dict优化一下
        h3c_security_csap_pod_cnt = 0
        h3c_security_dbaudit_pod_cnt = 0
        h3c_security_fortress_pod_cnt = 0
        h3c_security_leakscan_pod_cnt = 0
        h3c_security_logaudit_pod_cnt = 0
        h3c_security_ssms_pod_cnt = 0
        h3c_security_waf_pod_cnt = 0
        # 网页防篡改
        h3c_security_wss_pod_cnt = 0
        
        for pod_name, pod_info in self.all_pods_info.items():
            if pod_name.startswith("h3c-security-csap") and pod_info['status'] == "Running":
                h3c_security_csap_pod_cnt += 1
            elif pod_name.startswith("h3c-security-dbaudit") and pod_info['status'] == "Running":
                h3c_security_dbaudit_pod_cnt += 1
            elif pod_name.startswith("h3c-security-fortress") and pod_info['status'] == "Running":
                h3c_security_fortress_pod_cnt += 1
            elif pod_name.startswith("h3c-security-leakscan") and pod_info['status'] == "Running":
                h3c_security_leakscan_pod_cnt += 1
            elif pod_name.startswith("h3c-security-logaudit") and pod_info['status'] == "Running":
                h3c_security_logaudit_pod_cnt += 1
            elif pod_name.startswith("h3c-security-ssms") and pod_info['status'] == "Running":
                h3c_security_ssms_pod_cnt += 1
            elif pod_name.startswith("h3c-security-waf") and pod_info['status'] == "Running":
                h3c_security_waf_pod_cnt += 1
            elif pod_name.startswith("h3c-security-wss") and pod_info['status'] == "Running":
                h3c_security_wss_pod_cnt += 1
                
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("pod名称")
        table.add_column("在线数量")
        table.add_column("是否异常")
        table.add_row(
            str("h3c_security_csap_pod"), str(h3c_security_csap_pod_cnt), str('是') if h3c_security_csap_pod_cnt != 3 else str('否')
        )
        table.add_row(
            str("h3c_security_dbaudit_pod"), str(h3c_security_dbaudit_pod_cnt), str('是') if h3c_security_dbaudit_pod_cnt != 3 else str('否')
        )
        table.add_row(
            str("h3c_security_fortress_pod"), str(h3c_security_fortress_pod_cnt), str('是') if h3c_security_fortress_pod_cnt != 3 else str('否')
        )
        table.add_row(
            str("h3c_security_leakscan_pod"), str(h3c_security_leakscan_pod_cnt), str('是') if h3c_security_leakscan_pod_cnt != 3 else str('否')
        )
        table.add_row(
            str("h3c_security_logaudit_pod"), str(h3c_security_logaudit_pod_cnt), str('是') if h3c_security_logaudit_pod_cnt != 3 else str('否')
        )
        table.add_row(
            str("h3c_security_ssms_pod"), str(h3c_security_ssms_pod_cnt), str('是') if h3c_security_ssms_pod_cnt != 3 else str('否')
        )
        table.add_row(
            str("h3c_security_waf_pod"), str(h3c_security_waf_pod_cnt), str('是') if h3c_security_waf_pod_cnt != 3 else str('否')
        )
        table.add_row(
            str("h3c_security_wss_pod"), str(h3c_security_wss_pod_cnt), str('是') if h3c_security_wss_pod_cnt != 3 else str('否')
        )
        console.print(table)
    
    def copy_k8s_config_to_local(self) -> None:
        stdin, stdout, stderr = self.ssh_client.exec_command('cat /root/.kube/config')

        # Read and print the command output
        output = stdout.read().decode('utf-8')
            
        # write k8s config to local
        with open('config', 'w') as f:
            f.write(output)
        self.ssh_client.close()
    
class OInspection(OAInspectionable, SSHAuthentication):
    def do_all_inspection(self) -> str:
        pass

    def pod_inspecton(self) -> str:
        pass
    
    def copy_k8s_config_to_local(self):
        pass
    

class BastionhostInspection(DeviceInspectionable, DeviceAuthentication):
    
    def __init__(self, nodename: str, ip: str, username: str, password: str) -> None:
        self.ip = ip
        self.nodename = nodename
        self.username = username
        self.password = password
        self.dev_name = "Bastionhost"
        # e.g. A2000
        self.dev_type = "A2000"
        # 默认不需要验证码，但是如果多次输错密码就需要验证码，后续会根据页面进行判断
        self.need_captcha = False
        
        DeviceAuthentication.__init__(self, self.dev_name, False, ip, username, password)
        
    def get_captcha_str(self) -> str:
        try:
            ocr = ddddocr.DdddOcr(show_ad=False)
            with open('captcha.jpeg', 'rb') as f:
                image_bytes = f.read()

            res = ocr.classification(image_bytes)
            print(res)
            return res
        except Exception as e:
            print(e)
            print("ddddocr识别出错")
            exit(-3)
        
    def get_session_cookie(self):
        
        options = webdriver.ChromeOptions()
        # ignore unsafe https
        options.add_argument('ignore-certificate-errors')
        # options.add_argument('--headless')
        driver = webdriver.Chrome(options=options, executable_path=r'C:\Users\hushanglai\Desktop\inspection\chromedriver.exe')
        self.driver = driver
        url = "https://{}/webui/login".format(self.ip)
        driver.get(url)
        
        # check if captcha
        try:
            time.sleep(3)
            ele = driver.find_element_by_xpath('//*[@id="captchaImg"]')
            if ele.is_displayed():
                print("找到验证码")
                self.need_captcha = True
            else:
                print("未找到验证码")
                self.need_captcha = False
        except Exception as e:
            print("未找到验证码")
            self.need_captcha = False
            
        if self.need_captcha:
            try:
                # 下载验证码
                driver.find_element("id", "captchaImg").screenshot("captcha.jpeg")
            except Exception as e:
                raise CustomException("下载验证码出错")
                
            try:
                # 识别验证码
                captcha_str = self.get_captcha_str()
            except Exception as e:
                raise CustomException("识别验证码出错")
            
            time.sleep(2)
            driver.find_element("xpath", '//*[@id="inputCaptcha"]').send_keys(captcha_str)
        
        
        time.sleep(2)
        driver.find_element("id", "inputUserName").send_keys(self.username)
        time.sleep(2)
        driver.find_element("id", "inputPassword").send_keys(self.password)
        login_btn = driver.find_element("id", "loginBtn")
        login_btn.click()
        
        try:
            time.sleep(2)
            driver.find_element("id", "message")
        except Exception as e:
            print("登陆成功")
                
        sessions = driver.get_cookies()
        driver.close()
        json_sessions = json.dumps(sessions)
        return json.loads(json_sessions)[0]['value'], driver.session_id
        
    def do_all_inspection(self) -> str:
        
        try:
            cookie, session = self.get_session_cookie()
        except Exception as e:
            print(e)
            return "False"
            
        # do inspection on items
        try:
            cpu_info = self.cpu_inspection(cookie, session)
        except Exception as e:
            cpu_info = "巡检出错"
            print(e)
            
        try:
            mem_info = self.memory_inspection(cookie, session)
        except Exception as e:
            mem_info = "巡检出错"
            print(e)
            
        try:
            interface_info = self.interface_inspection(cookie, session)
        except Exception as e:
            interface_info = "巡检出错"
            print(e)
            
        try:
            engine_info = self.engine_inspection(cookie, session)
        except Exception as e:
            engine_info = "巡检出错"
            print(e)
            
        try:
            license_info = self.license_status_inspection(cookie, session)
        except Exception as e:
            license_info = "巡检出错"
            print(e)
            
        try:
            license_status = self.license_deadline_inspection(cookie, session)
        except Exception as e:
            license_status = "巡检出错"
            print(e)
            
        try:
            time_info = self.time_inspection(cookie, session)
        except Exception as e:
            time_info = "巡检出错"
            print(e)
            
        try:
            signature_info = self.signatures_inspection(cookie, session)
        except Exception as e:
            signature_info = "巡检出错"
            print(e)
            
        try:
            storage_info = self.storage_inspection(cookie, session)
        except Exception as e:
            storage_info = "巡检出错"
            print(e)
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("节点信息")
        table.add_column("设备名称")
        table.add_column("设备型号")
        table.add_column("CPU信息")
        table.add_column("内存信息")
        table.add_column("接口信息")
        table.add_column("特征库版本")
        table.add_column("授权状态")
        table.add_column("引擎状态")
        table.add_column("授权信息")
        table.add_column("时间信息")
        table.add_column("存储信息")
        table.add_row(
            str(self.nodename), str(self.dev_name), str(self.dev_type), str(cpu_info), str(mem_info), str(interface_info), str(signature_info), 
            str(license_status), str(engine_info), str(license_info), str(time_info),
            str(storage_info)
        )
        console.print(table)
        
        print("==============================")
        print("节点信息:" + self.nodename)
        print("设备信息:" + self.dev_name)
        print("设备型号:" + self.dev_type)
        print("CPU信息:" + cpu_info)
        print("内存信息:" + mem_info)
        print("磁盘信息:" + storage_info)
        print("接口信息:\n" + interface_info)
        print("特征库版本:\n" + signature_info)
        print("授权状态:\n" + license_status)
        print("引擎状态:" + engine_info)
        print("授权信息:" + license_info)
        print("时间信息:" + time_info)
        print("==============================")
    
    def interface_inspection(self, cookie, session):
        url = f"https://{self.ip}/webui/api/deviceIp/allIfs"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Cookie": f"SESSION={cookie}; SESSION={session}",
            "Referer": f"https://{self.ip}/webui/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "sec-ch-ua-mobile": "?0"
        }
    
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    
        bastionhost_interfaces_json = response.json()
    
        bastionhost_interfaces_str = ""
        for interface in bastionhost_interfaces_json:
            if interface['linked'] == 'yes':
                print(interface)
    
        return "正常"
                
    def time_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/webui/api/sysParam/getTime"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Cookie": f"SESSION={cookie}; SESSION={session}",
            "Referer": f"https://{self.ip}/webui/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "sec-ch-ua-mobile": "?0"
        }
    
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    
        timestamp = response.json()['timestamp']
        dt_object = datetime.datetime.fromtimestamp(int(timestamp) / 1000)
    
        return dt_object
    
    
    def license_deadline_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/webui/api/authorize/fetch"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Cookie": f"SESSION={cookie}; SESSION={session}",
            "Referer": f"https://{self.ip}/webui/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "sec-ch-ua-mobile": "?0"
        }
    
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    
        license_json = response.json()
        license_start_time = license_json['date1']
        license_end_time = license_json['date2']
    
        license_str = "授权开始时间:" + license_start_time + "\n授权结束时间:" + license_end_time
    
        return license_str
    
    def license_status_inspection(self, cookie, session) -> str:
        return "根据授权时间判断"
    
    def engine_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/webui/api/cluster/monitorInfo"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Cookie": f"SESSION={cookie}; SESSION={session}",
            "Referer": f"https://{self.ip}/webui/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "sec-ch-ua-mobile": "?0"
        }
    
        response = requests.get(url, headers=headers, verify=False)
    
        # 存在故障未启动的服务
        failedServices = response.json()[0]['status']['failedServices']
        # 已停止的服务
        stoppedServices = response.json()[0]['status']['stoppedServices'] 
        
        if len(failedServices) > 1 or len(stoppedServices) > 1:
            return "引擎异常"
        
        return "引擎正常"
        
    
    def signatures_inspection(self, cookie, session) -> str:
        return "不适用"
    
    def memory_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/webui/api/cluster/monitorInfo"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Cookie": f"SESSION={cookie}; SESSION={session}",
            "Referer": f"https://{self.ip}/webui/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "sec-ch-ua-mobile": "?0"
        }
    
        response = requests.get(url, headers=headers, verify=False)
    
        # 从f12 js代码观察到内存使用率为一下计算方法 ,找起来挺麻烦
        # memoryUsedStr=Math.round((host.status.totalPhysicalMemorySize-host.status.availablePhysicalMemorySize-host.status.cacheMemorySize-host.status.bufferMemorySize)*100/(1024*1024*1024))/100
        # memoryTotalStr=Math.round(host.status.totalPhysicalMemorySize*100/(1024*1024*1024))/100;
        totalPhysicalMemorySize = float(response.json()[0]['status']['totalPhysicalMemorySize'])
        availablePhysicalMemorySize = float(response.json()[0]['status']['availablePhysicalMemorySize'])
        cacheMemorySize = float(response.json()[0]['status']['cacheMemorySize'])
        bufferMemorySize = float(response.json()[0]['status']['bufferMemorySize'])
        
        memoryUsed = round(totalPhysicalMemorySize - availablePhysicalMemorySize - cacheMemorySize - bufferMemorySize, 4)
        memoryTotal = round(totalPhysicalMemorySize, 4)
        mem_str = "内存使用率:" + str(round(memoryUsed / memoryTotal * 100, 4)) + "%"
    
        return mem_str
    
    def storage_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/webui/api/cluster/monitorInfo"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Cookie": f"SESSION={cookie}; SESSION={session}",
            "Referer": f"https://{self.ip}/webui/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "sec-ch-ua-mobile": "?0"
        }
    
        response = requests.get(url, headers=headers, verify=False)
        disk_info = "挂载点\t占用百分比\n"
    
        disk_usage = response.json()[0]['status']['diskUsage']
        disk_usage = response.json()[0]['status']['diskUsage']

        for mount_point, space_values in disk_usage.items():
            used_space = space_values[0]
            left_space = space_values[1]
            
            disk_info += mount_point + "\t" + str(round(used_space / (used_space + left_space) * 100, 4)) + "%\n"
            
        return disk_info
    
    def cpu_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/webui/api/cluster/monitorInfo"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Cookie": f"SESSION={cookie}; SESSION={session}",
            "Referer": f"https://{self.ip}/webui/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "sec-ch-ua-mobile": "?0"
        }
    
        response = requests.get(url, headers=headers, verify=False)
    
        cpu_stats = float(response.json()[0]['status']['cpuLoad'])
        cpu_count = int(response.json()[0]['status']['cpuCount'])
        cpu_status_str = "已使用CPU: " + str(round(cpu_stats * 100, 4)) + "%"
    
        return cpu_status_str
    
    
class LogAuditInspection(DeviceInspectionable, DeviceAuthentication):
    
    def __init__(self, nodename:str, ip: str, username: str, password: str) -> None:
        self.ip = ip
        self.nodename = nodename
        self.username = username
        self.password = password
        self.dev_name = "LogAudit"
        self.need_captcha = True
        
        DeviceAuthentication.__init__(self, nodename, True, ip, username, password)
        
    def get_captcha_str(self) -> str:
        try:
            ocr = ddddocr.DdddOcr(show_ad=False)
            with open('captcha.jpeg', 'rb') as f:
                image_bytes = f.read()

            res = ocr.classification(image_bytes)
            print(res)
            return res
        except Exception as e:
            print(e)
            print("ddddocr识别出错")
            exit(-3)

    def get_session_cookie(self):
        
        options = webdriver.ChromeOptions()

        # ignore unsafe https
        options.add_argument('ignore-certificate-errors')
        # options.add_argument('--headless')
        driver = webdriver.Chrome(options=options, executable_path=r'C:\Users\hushanglai\Desktop\inspection\chromedriver.exe')
        self.driver = driver
        
        # 尝试不停登录
        while True:
            # ? need?
            time.sleep(3)
            url = "https://{}/toLogin".format(self.ip)
            driver.get(url)
            
            if self.need_captcha:
                # 下载验证码
                driver.find_element("id", "codetxt").screenshot("captcha.jpeg")
                # 识别验证码
                captcha_str = self.get_captcha_str()
                
            time.sleep(2)
            driver.find_element("id", "username").send_keys(self.username)
            time.sleep(2)
            driver.find_element("id", "password").send_keys(self.password)
            login_btn = driver.find_element("id", "loginBtn")
            
            if self.need_captcha:
                # 发送验证码
                time.sleep(2)
                driver.find_element("id", "codeinput").send_keys(captcha_str)
                
            login_btn.click()
        
            # 验证码通过，退出
            try:
                driver.find_element("id", "inputUserName")
                print("验证码识别输出，刷新页面")
                # driver.refresh()
            except Exception as e:
                print("登陆成功")
                break

        sessions = driver.get_cookies()
        json_sessions = json.dumps(sessions)

        print(sessions, driver.session_id)

        # 通过观察cookie在第一个位置
        return json.loads(json_sessions)[2]['value'], driver.session_id
        
    def do_all_inspection(self) -> str:
        cookie, session = self.get_session_cookie()
        # do inspection on items
        try:
            cpu_info = self.cpu_inspection(cookie, session)
        except Exception as e:
            cpu_info = "巡检出错"
            print(e)
            
        try:
            memory_info = self.memory_inspection(cookie, session)
        except Exception as e:
            memory_info = "巡检出错"
            print(e)
            
        try:
            interface_info = self.interface_inspection(cookie, session)
        except Exception as e:
            interface_info = "巡检出错"
            print(e)
            
        try:
            engine_info = self.engine_inspection(cookie, session)
        except Exception as e:
            engine_info = "巡检出错"
            print(e)
            
        try:
            license_info = self.license_deadline_inspection(cookie, session)
        except Exception as e:
            license_info = "巡检出错"
            print(e)
            
        try:
            license_status = self.license_status_inspection(cookie, session)
        except Exception as e:
            license_status = "巡检出错"
            print(e)
            
        try:
            time_info = self.time_inspection(cookie, session)
        except Exception as e:
            time_info = "巡检出错"
            print(e)
            
        try:
            signature_info = self.signatures_inspection(cookie, session)
        except Exception as e:
            signature_info = "巡检出错"
            print(e)
            
        try:
            storage_info = self.storage_inspection(cookie, session)
        except Exception as e:
            storage_info = "巡检出错"
            print(e)
            
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("节点信息", no_wrap=True)
        table.add_column("设备名称", no_wrap=True)
        table.add_column("设备型号", no_wrap=True)
        table.add_column("CPU信息", no_wrap=True)
        table.add_column("内存信息", no_wrap=True)
        table.add_column("接口信息", no_wrap=True)
        table.add_column("特征库版本", no_wrap=True)
        table.add_column("授权状态", no_wrap=True)
        table.add_column("引擎状态", no_wrap=True)
        table.add_column("授权信息", no_wrap=True)
        table.add_column("时间信息", no_wrap=True)
        table.add_row(
            str(self.nodename), str(self.dev_name), str(self.dev_type), str(cpu_info), str(memory_info), str(interface_info), str(signature_info), 
            str(license_status), str(engine_info), str(license_info), str(time_info)
        )
        console.print(table)
        
        print("==============================")
        print("节点信息:" + self.nodename)
        print("设备信息:" + self.dev_name)
        print("设备型号:" + self.dev_type)
        print("CPU信息:" + cpu_info)
        print("内存信息:" + memory_info)
        print("磁盘信息:" + storage_info)
        print("接口信息:\n" + interface_info)
        print("特征库版本:\n" + signature_info)
        print("授权状态:\n" + license_status)
        print("引擎状态:" + engine_info)
        print("授权信息:" + license_info)
        print("时间信息:" + time_info)
        print("==============================")
        
        return "正常"
   

    def interface_inspection(self, cookie, session):
        cookies = {
            'server-session-id': f'{cookie}',
            'themeId': '0',
            'themeaddress': 'technology.css',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            # 'Cookie': 'server-session-id=4dd8c78b-426e-4841-a6e2-2df6ee3e1fa0; themeId=0; themeaddress=technology.css',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        json_data = {
            'order': 'asc',
            'offset': 0,
            'limit': 15,
        }

        response = requests.post(
            f'https://{self.ip}/netSetting/getNetSetting',
            cookies=cookies,
            headers=headers,
            json=json_data,
            verify=False,
        )

        json_data = response.json()
        interfaces = json_data['rows']
        
        # 从js代码来看status字段为1为up，其他为down
        # function statusType (value, row, index) {
        #     return value === 1 ? '<nobr class="label label_online">up</nobr>' : '<nobr class="label label_offline">down</nobr>'
        # }
        
        interface_info = "网卡名称\t网卡ip\t网卡状态\n"
        for i in interfaces:
            interface_info += (i['name'] + '\t' + i['ipv4'] + '\t' + ("up\n" if i['status'] == 1 else "down\n"))

        return interface_info
                
    def time_inspection(self, cookie, session) -> str:
        
        cookies = {
            'server-session-id': cookie,
            'themeId': '0',
            'themeaddress': 'technology.css',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'server-session-id=1b23515d-d224-416d-bc48-627e9ef93ec3; themeId=0; themeaddress=technology.css',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/timeSetting/searchSystemTime', cookies=cookies, headers=headers, verify=False)
        json_data = json.loads(json.dumps(response.json()))
        local_time = datetime.datetime.fromtimestamp(int(json_data['data']['time'])/1000)
        local_time_string = local_time.strftime('%Y-%m-%d %H:%M:%S')
        
        return local_time_string
    
    def license_deadline_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/license/permissions"
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Cookie": f"themeId=0; themeaddress=technology.css; server-session-id={session}",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        }
        data = {
            "sort": "created_time",
            "order": "desc",
            "offset": 0,
            "limit": 10
        }
    
        response = requests.post(url, headers=headers, json=data, verify=False)
        response.raise_for_status()
    
        license_end_time = response.json()['data']['CSAP-SA-Platform']['msg']
    
        license_str = "授权时间:" + license_end_time
    
        return license_str 
    
    def license_status_inspection(self, cookie, session) -> str:
        return "根据授权时间判断"
    
    def engine_inspection(self, cookie, session) -> str:
        cookies = {
             'server-session-id': f'{cookie}',
             'themeId': '0',
             'themeaddress': 'technology.css',
         }
        headers = {
             'Accept': 'application/json, text/javascript, */*; q=0.01',
             'Accept-Language': 'zh-CN,zh;q=0.9',
             'Connection': 'keep-alive',
             # Already added when you pass json=
             # 'Content-Type': 'application/json',
             # 'Cookie': 'server-session-id=969706d4-7b73-46c9-bcfe-32530152d665; themeId=0; themeaddress=technology.css',
             'Origin': f'https://{self.ip}',
             'Referer': f'https://{self.ip}/',
             'Sec-Fetch-Dest': 'empty',
             'Sec-Fetch-Mode': 'cors',
             'Sec-Fetch-Site': 'same-origin',
             'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
             'X-Requested-With': 'XMLHttpRequest',
             'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
             'sec-ch-ua-mobile': '?0',
             'sec-ch-ua-platform': '"Windows"',
         }

        json_data = {}

        response = requests.post(
            f'https://{self.ip}/serviceMonitor/apps',
            cookies=cookies,
            headers=headers,
            json=json_data,
            verify=False,
        ) 
        engine_json = response.json()
        print(engine_json)
        engine_msg = ''
        for i in engine_json['data']:
            if i['status'] != 'healthy':
                engine_msg += i['cn_name'] + "不健康" + '\n'

        if len(engine_msg) == 0:
            engine_msg = "正常"
        return engine_msg
    
    def signatures_inspection(self, cookie, session) -> str:
        return "不适用"
    
    def memory_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/allriskinfo/systemInfo"
        headers = {
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Content-Length": "0",
            "Cookie": f"themeId=0; themeaddress=technology.css; server-session-id={session}",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        }
    
        response = requests.post(url, headers=headers, verify=False)
        response.raise_for_status()
    
        mem_stats = response.json()['data'][0]['MemPercent']
        mem_status_str = "已使用内存: " + str(mem_stats) + "%"
    
        return mem_status_str 
    
    # 不是巡检项
    def storage_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/allriskinfo/systemInfo"
        headers = {
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Content-Length": "0",
            "Cookie": f"themeId=0; themeaddress=technology.css; server-session-id={cookie}",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        }
        response = requests.post(url, headers=headers, verify=False)

        disk_stats = response.json()['data'][0]['DataDiskPercent']
        disk_status_str = "已使用硬盘: " + str(disk_stats) + "%"

        return disk_status_str 
    
    def cpu_inspection(self, cookie, session) -> str:
        url = f"https://{self.ip}/allriskinfo/systemInfo"
        headers = {
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Content-Length": "0",
            "Cookie": f"themeId=0; themeaddress=technology.css; server-session-id={cookie}",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        }
        response = requests.post(url, headers=headers, verify=False)
        response.raise_for_status()

        cpu_stats = response.json()['data'][0]['CPUPercent']
        cpu_status_str = "已使用CPU: " + str(cpu_stats) + "%"

        return cpu_status_str 
    
# 数据库库审计
class DatabaseAuditInspection(DeviceInspectionable, DeviceAuthentication):
    
    def __init__(self, nodename:str, ip: str, username: str, password: str) -> None:
        self.ip = ip
        self.nodename = nodename
        self.username = username
        self.password = password
        self.dev_name = "DatabaseAudit"
        # e.g. D2000
        self.dev_type = ""
        
        DeviceAuthentication.__init__(self, self.dev_name, True, ip, username, password)
        
    def get_captcha_str(self) -> str:
        try:
            ocr = ddddocr.DdddOcr(show_ad=False)
            with open('captcha.jpeg', 'rb') as f:
                image_bytes = f.read()

            res = ocr.classification(image_bytes)
            return res
        except Exception as e:
            print(e)
            print("ddddocr识别出错")
            exit(-3)

    def get_session_cookie(self):
        
        options = webdriver.ChromeOptions()
        
        self.need_captcha_user_input = False

        # ignore unsafe https
        options.add_argument('ignore-certificate-errors')
        # options.add_argument('--headless')
        self.driver = webdriver.Chrome(options=options, executable_path=r'C:\Users\hushanglai\Desktop\inspection\chromedriver.exe')
        driver = self.driver
        
        # 尝试不停登录, 数据库审计比较特殊，验证码比较复杂，ddddocr可能识别很多次识别不出来
        # ? 为了防止账号被锁定，这里只尝试4次, 为什么用Selenium会有验证码，直接登录没有
        max_cnt = 4
        cnt = 1
        while True:
            
            if cnt > max_cnt:
                print("错误次数过多，稍后再来，不然要被锁定50min")
                break
            
            
            # 不睡眠会导致页面不能及时刷新，找不到相应元素
            time.sleep(3)
            url = "https://{}/".format(self.ip)
            driver.get(url)
            
            
            
            if self.need_captcha and not self.need_captcha_user_input:
                # 下载验证码, find_element方法有问题，找到的图片weith为0
                img_base64 = driver.execute_script("""
                                                   var ele = arguments[0];
                                                   var cnv = document.createElement('canvas');
                                                   cnv.width = ele.width; 
                                                   cnv.height = ele.height; 
                                                   cnv.getContext('2d').drawImage(ele, 0, 0); 
                                                   return cnv.toDataURL('image/jpeg').substring(22);  
                                                   """, driver.find_element_by_xpath('//*[@id="vcode"]'))
            
                with open(r"captcha.jpeg", 'wb') as f:
                    f.write(base64.b64decode(img_base64))

                    #driver.find_element("id", "vcode").screenshot("captcha.jpeg")
                    #element = driver.find_element(By.XPATH, '//*[@id="vcode"]')
                    #print(type(element))
                    #element.screenshot("captcha.jpeg")
                    #print("size:", element.size['width'], element.size['height'])

                # 识别验证码
                captcha_str = self.get_captcha_str()
                
            time.sleep(2)
            driver.find_element("id", "username").send_keys(self.username)
            time.sleep(2)
            driver.find_element("id", "password").send_keys(self.password)
            login_btn = driver.find_element("id", "login")
            
            if cnt == 4:
                self.need_captcha_user_input = True
                print("需要用户在10秒内输入验证码，确保验证码正确，否则账户将会被会锁定!!!")
                time.sleep(10)
                
            if self.need_captcha and not self.need_captcha_user_input:
                time.sleep(2)
                driver.find_element("id", "yzm").send_keys(captcha_str)
                
            login_btn.click()
            cnt += 1
            
            # 找不到登录按钮表示验证码通过，退出
            try:
                time.sleep(3)
                driver.find_element("id", "login")
                print("验证码识别出错，正在刷新页面重新登陆")
                # driver.refresh()
            except Exception as e:
                print("登陆成功")
                break

        sessions = driver.get_cookies()
        json_sessions = json.dumps(sessions)

        
        all_cookies=self.driver.get_cookies();
        cookies_dict = {}
        for cookie in all_cookies:
            print(cookie)
            cookies_dict[cookie['name']] = cookie['value']
            
        return json_sessions, cookies_dict['sessionid']
        
    def do_all_inspection(self) -> str:
        cookie, session = self.get_session_cookie()
        # do inspection on items
        cpu_info = self.cpu_inspection(cookie, session)
        memory_info = self.memory_inspection(cookie, session)
        interface_info = self.interface_inspection(cookie, session)
        signatures_info = self.signatures_inspection(cookie, session)
        engine_info = self.engine_inspection(cookie, session)
        license_info = self.license_deadline_inspection(cookie, session)
        license_status = self.license_status_inspection(cookie, session)
        time_info = self.time_inspection(cookie, session)
        storage_info = self.storage_inspection(cookie, session)
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("节点信息", style="dim")
        table.add_column("设备名称", style="dim")
        table.add_column("设备型号", style="dim")
        table.add_column("CPU信息", style="dim")
        table.add_column("内存信息")
        table.add_column("接口信息")
        table.add_column("特征库版本")
        table.add_column("授权状态")
        table.add_column("引擎状态")
        table.add_column("授权信息")
        table.add_column("时间信息")
        table.add_column("磁盘信息")
        table.add_row(
            str(self.nodename), str(self.dev_name), str(self.dev_type), str(cpu_info), str(memory_info), str(interface_info), str(signatures_info), 
            str(license_status), str(engine_info), str(license_info), str(time_info), str(storage_info)
        )
        console.print(table)
        
        print("==============================")
        print("节点信息:" + self.nodename)
        print("设备信息:" + self.dev_name)
        print("设备型号:" + self.dev_type)
        print("CPU信息:" + cpu_info)
        
        # 应该同时检测CPU占用不超过80%
        if "异常" not in cpu_info:
            console.print("CPU信息:" + cpu_info, style="green")
        else:
            console.print("CPU信息:" + cpu_info, style="red")
            
            
        print("内存信息:" + memory_info)
        print("磁盘信息:" + storage_info)
        print("接口信息:\n" + interface_info)
        print("特征库版本:\n" + signatures_info)
        print("授权状态:\n" + license_status)
        print("引擎状态:" + engine_info)
        print("授权信息:" + license_info)
        print("时间信息:" + time_info)
        print("==============================")
        
    def signatures_inspection(self, cookie, session):
        return "不适用"

    def interface_inspection(self, cookie, session):
        cookies = {
            'think_language': 'zh-cn',
            'userid': '106',
            'username': 'zgyCloudgxlz',
            'usergroup': 'system',
            'headeventview': 'headeventview',
            'sessionid': session,
        }

        headers = {
            'Accept': 'application/xml, text/xml, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Authorization': 'Bearer null 1689408459 9c5060cd072a5d14e6b2955530cd4aca d8d4ba8bbba687e34f10bb8e0539dd88',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'think_language=zh-cn; userid=106; username=zgyCloudgxlz; usergroup=system; headeventview=headeventview; sessionid=-H4%2CciQrdBtC71TL81grJOKkqaMO-6YdzK3xhG4FF-NfQFBWpyHlZkOzqBcdXUR%2C5oUV1swvTSewZHuf2V-CA6UszVl9iqXCI5agOoG9N6jC-QPxQ9qbJh9QYpZqBrbHIUJU%2CGlNvPeeRX4SGYKeOe8YV71-6RdRxW%2CMvhHPX6Cs33P8XjcEL6RJwqpFm4E7UoW',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/views/network.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/admin/staterouter/getNetworkName', cookies=cookies, headers=headers, verify=False)
        
        if response.status_code == 200:
            root = ET.fromstring(response.text)

            # Find the datetime element
            interface_element = root.find(".//rows")
            interface_msg = "网卡名称\t网卡ip\t网卡网关\n"
            for i in interface_element:
                status = i.find('eth_status')
                if status is not None and status.text == '1':
                    netname = (i.find('netname').text)
                    ipaddr = (i.find('IPADDR').text)
                    netmask = (i.find('NETMASK').text)
                    gateway = (i.find('GATEWAY').text)
                    interface_msg += netname + "\t" + ipaddr + "\t" + netmask + "\t" + gateway + "\n"
        else:
            return "获取端口信息异常"
        return interface_msg
                
    def time_inspection(self, cookie, session) -> str:
        cookies = {
            'think_language': 'zh-cn',
            'userid': '106',
            'username': 'zgyCloudgxlz',
            'usergroup': 'system',
            'headeventview': 'headeventview',
            'sessionid': session,
        }

        headers = {
            'Accept': 'application/xml, text/xml, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Authorization': 'Bearer null 1689406488 6422c7f0607dc48ef251f76c26696340 02095fd39f884d28fb4def7297c97980',
            'Connection': 'keep-alive',
            # 'Cookie': 'think_language=zh-cn; userid=106; username=zgyCloudgxlz; usergroup=system; headeventview=headeventview; sessionid=-H4%2CciQrdBtC71TL81grJOKkqaMO-6YdzK3xhG4FF-NfQFBWpyHlZkOzqBcdXUR%2C5oUV1swvTSewZHuf2V-CA6UszVl9iqXCI5agOoG9N6jC-QPxQ9qbJh9QYpZqBrbHIUJU%2CGlNvPeeRX4SGYKeOe8YV71-6RdRxW%2CMvhHPX6Cs33P8XjcEL6RJwqpFm4E7UoW',
            'Referer': f'https://{self.ip}/views/version.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        params = {
            'format': 'int',
        }

        response = requests.get(
            f'https://{self.ip}/admin/paramsconfig/servertime',
            params=params,
            cookies=cookies,
            headers=headers,
            verify=False,
        ) 
        
        if response.status_code == 200:
            xml_datetime = response.text
        else:
            print("获取时间失败")
            return "获取时间失败"
        
        root = ET.fromstring(xml_datetime)

        # Find the datetime element
        datetime_element = root.find(".//datetime")

        # Get the datetime value
        datetime_value = datetime_element.text

        # Convert the datetime value to a Python datetime object
        datetime_object = datetime.datetime.fromtimestamp(int(datetime_value))
        
        datetime_msg = datetime_object.strftime("%Y-%m-%d")
        
        return datetime_msg
    
    def license_deadline_inspection(self, cookie, session) -> str:
        cookies = {
            'think_language': 'zh-cn',
            'sessionid': session,
            'userid': '106',
            'username': 'zgyCloudgxlz',
            'usergroup': 'system',
            'headeventview': 'headeventview',
        }

        headers = {
            'Accept': 'application/xml, text/xml, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Authorization': 'Bearer null 1689415478 66a2d45355c268790bc1760d329782dd fb1da3270c206f2227521983a604b20f',
            'Connection': 'keep-alive',
            # 'Cookie': 'think_language=zh-cn; sessionid=7wLWkgHomSF8AuXl%2C3yIVVQMd6xr1HTGYEgdRmry1plnu%2CsBvQoeq19Txh6tkiK5kcSvAWXPSBYmps6li2pbWrm5f2g4khe5X9P9E8lERE-dqZ2BjqAj5lLanDngDs1xvQcZL3O8pE4sw2euJL%2Crw2bfHAQhMPqVff-YlPWb-AtKR8ga-iR5nwaIZTO6d8Vl5Ad; userid=106; username=zgyCloudgxlz; usergroup=system; headeventview=headeventview',
            'Referer': f'https://{self.ip}/views/version.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.get(f'https://{self.ip}/admin/version/register', cookies=cookies, headers=headers, verify=False)
        if response.status_code == 200:
            root = ET.fromstring(response.text)
            xml_issue_time = root.find(".//issuetime").text
            # Decode the URL-encoded string
            issue_time_str = unquote(xml_issue_time)
            
            xml_expired_time = root.find(".//expired").text
            # Decode the URL-encoded string
            expired_time_str = unquote(xml_expired_time)
            
        return "授权时间:{}\n授权到期时间:{}\n".format(issue_time_str, expired_time_str)
    
    def license_status_inspection(self, cookie, session) -> str:
        return "根据授权按时间判断"
    
    def engine_inspection(self, cookie, session) -> str:
        cookies = {
            'think_language': 'zh-cn',
            'sessionid': f'{cookie}',
            'userid': '106',
            'username': f'{self.username}',
            'usergroup': 'system',
            'headeventview': 'headeventview',
        }

        headers = {
            'Accept': 'application/xml, text/xml, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Authorization': 'Bearer null 1701671484 dae5d19d7ffef1fb16ec1787b951257c 0d36908305d624849d5a810c7b67151e',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'think_language=zh-cn; sessionid=KzZNSEQSwqE3hAGpH3TjAQrtTYwgZd5RInrvSndU4Ol2LNccYU9%2CA6oeB0NRHxcnZpoIzoNLKvOWZwvYQ6oghmBhCKkB6TVd0UExWT4u8YhkBc%2CZktiYI7l6Q1bGKFvZQvRV-A%2Cy9yX3dAlxXZOXvH2OYKqduusaNeQSGV2LMlcmlOmyNrSlOTVlAhlgJ4i0iC9; userid=106; username=zgyCloudgxlz; usergroup=system; headeventview=headeventview',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/views/process.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = {
            'page': '1',
            'limit': '50',
            'sortname': 'undefined',
            'sortorder': 'undefined',
            'query': '',
            'qtype': '',
            'qop': 'Eq',
        }

        response = requests.post(
            f'https://{self.ip}/admin/process/processlist',
            cookies=cookies,
            headers=headers,
            data=data,
            verify=False,
        )
        
        # 解析XML数据
        root = ET.fromstring(response.content)
        
        failed_service_msg = ""

        # 获取process->data->row字段
        for row in root.findall('.//process/data/rows/row'):
            pid = row.find('pid').text
            ppid = row.find('ppid').text
            size = row.find('size').text
            etime = row.find('etime').text
            stat = row.find('stat').text
            command = row.find('command').text
            act = row.find('act').text
            namestr = row.find('namestr').text

            if stat != '运行中':
                failed_service_msg +=  (f'PID: {pid}, PPID: {ppid}, Size: {size}, Etime: {etime}, Stat: {stat}, Command: {command}, Act: {act}, Namestr: {namestr}')
                failed_service_msg += '\n'
        
        return failed_service_msg if len(failed_service_msg) > 0 else "引擎正常"
    
    def signatures_inspection(self, cookie, session) -> str:
        return "不适用"
    
    def memory_inspection(self, cookie, session):
        cookies = {
            'think_language': 'zh-cn',
            'sessionid': session,
            'userid': '106',
            'username': 'zgyCloudgxlz',
            'usergroup': 'system',
            'headeventview': 'headeventview',
        }

        headers = {
            'Accept': 'application/xml, text/xml, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Authorization': 'Bearer null 1689413384 d28898c6b270320b1bef19faf7732284 c2ddc615b3868f946d9629dcceac47f0',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'think_language=zh-cn; sessionid=7wLWkgHomSF8AuXl%2C3yIVVQMd6xr1HTGYEgdRmry1plnu%2CsBvQoeq19Txh6tkiK5kcSvAWXPSBYmps6li2pbWrm5f2g4khe5X9P9E8lERE-dqZ2BjqAj5lLanDngDs1xvQcZL3O8pE4sw2euJL%2Crw2bfHAQhMPqVff-YlPWb-AtKR8ga-iR5nwaIZTO6d8Vl5Ad; userid=106; username=zgyCloudgxlz; usergroup=system; headeventview=headeventview',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/views/healthstate.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = '&dataTime=7t&timegap=4&memory=1'

        response = requests.post(f'https://{self.ip}/admin/healthstate/index', cookies=cookies, headers=headers, data=data, verify=False)
        
        if response.status_code == 200:
            root = ET.fromstring(response.text)

            # Find the memory element
            # 数据库审计的内存信息比较特特殊，他是每8个小时统计一次，我们取最新时间的cpu状态就行
            mem_status = root.findall(".//row")[-1].find('memory').text
            print("mem Status" + mem_status)
            return f"已使用%s%%内存" % mem_status
            
        else:
            return "获取端口信息异常"
    
    # 不是巡检项
    def storage_inspection(self, cookie, session) -> str:
        cookies = {
            'think_language': 'zh-cn',
            'sessionid': f'{cookie}',
            'userid': '106',
            'username': f'{self.username}',
            'usergroup': 'system',
            'headeventview': 'headeventview',
        }

        headers = {
            'Accept': 'application/xml, text/xml, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Authorization': 'Bearer null 1701672432 7da720ca229c489c2845508fec6824d4 da88d32e63c5c0d9bb238ed5af6a72d5',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'think_language=zh-cn; sessionid=K2TPAeaLvEHO65VBzDE7wyvhP9T9-ODZSa-9QnjFMryGIkNF2JZ1A7WFGMU1GQm0TKfrZa-xHsfBN9yd0P4tMk04AdvkHO61jfdHwgO6DD%2Cr2UC%2CAyA0Rak9NXTkD%2CuagiAqTOkFFPg1YCxHZN9I2zqaXS46sapTAoZdzYH4PJU-FZeTyVH5vaaqU00CyH5qIUL; userid=106; username=zgyCloudgxlz; usergroup=system; headeventview=headeventview',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/views/healthstate.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/admin/healthstate/getdisk', cookies=cookies, headers=headers, verify=False)
        root = ET.fromstring(response.content)

        healthmsg = root.find('.//healthmsg').text
        
        return "正常" if healthmsg == "OK" else "异常"
    
    def cpu_inspection(self, cookie, session):
        cookies = {
            'think_language': 'zh-cn',
            'sessionid': session,
            'userid': '106',
            'username': 'zgyCloudgxlz',
            'usergroup': 'system',
            'headeventview': 'headeventview',
        }

        headers = {
            'Accept': 'application/xml, text/xml, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Authorization': 'Bearer null 1689413384 d28898c6b270320b1bef19faf7732284 c2ddc615b3868f946d9629dcceac47f0',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'think_language=zh-cn; sessionid=7wLWkgHomSF8AuXl%2C3yIVVQMd6xr1HTGYEgdRmry1plnu%2CsBvQoeq19Txh6tkiK5kcSvAWXPSBYmps6li2pbWrm5f2g4khe5X9P9E8lERE-dqZ2BjqAj5lLanDngDs1xvQcZL3O8pE4sw2euJL%2Crw2bfHAQhMPqVff-YlPWb-AtKR8ga-iR5nwaIZTO6d8Vl5Ad; userid=106; username=zgyCloudgxlz; usergroup=system; headeventview=headeventview',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/views/healthstate.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = '&dataTime=7t&timegap=4&memory=1'

        response = requests.post(f'https://{self.ip}/admin/healthstate/index', cookies=cookies, headers=headers, data=data, verify=False)
        
        if response.status_code == 200:
            root = ET.fromstring(response.text)

            # Find the cpu element
            # 数据库审计的CPU信息比较特特殊，他是每8个小时统计一次，我们取最新时间的cpu状态就行
            cpu_status = root.findall(".//row")[-1].find('cpu').text
            print("CPU Status" + cpu_status)
            return f"已使用%s%%CPU" % cpu_status
            
        else:
            return "获取端口信息异常"
        
# IPS 可以复用NTA的class
class IPSInspection(DeviceInspectionable, DeviceAuthentication):
    
    def __init__(self, nodename: str, ip: str, username: str, password: str) -> None:
        self.ip = ip
        self.nodename = nodename
        self.username = username
        self.password = password
        self.dev_name = "IPS"
        # e.g. A2000
        self.dev_type = "T5XXX"
        self.need_captcha = True
        self.need_captcha_user_input = False
        
        DeviceAuthentication.__init__(self, self.dev_name, False, ip, username, password)
        
    def get_captcha(self) -> str:
        pass
        
    def get_captcha_str(self) -> str:
        try:
            ocr = ddddocr.DdddOcr(show_ad=False)
            with open('captcha.jpeg', 'rb') as f:
                image_bytes = f.read()

            res = ocr.classification(image_bytes)
            print(res)
            return res
        except Exception as e:
            print(e)
            print("ddddocr识别出错")
            exit(-3)
            
    def get_session_cookie(self):
        
        options = webdriver.ChromeOptions()

        # ignore unsafe https
        options.add_argument('ignore-certificate-errors')
        # options.add_argument('--headless')
        self.driver = webdriver.Chrome(options=options, executable_path=r'C:\Users\hushanglai\Desktop\inspection\chromedriver.exe')
        driver = self.driver
        
        # 尝试不停登录, 数据库审计比较特殊，验证码比较复杂，ddddocr可能识别很多次识别不出来
        # ? 为了防止账号被锁定，这里只尝试4次, 为什么用Selenium会有验证码，直接登录没有
        max_cnt = 4
        cnt = 1
        while True:
            
            # 尝试用find_element去找验证码的id，无论页面是有还是没有都会找到该元素，所以该方法不管用
            # 如果第一次登陆默认没有验证码，后续就会弹出验证码
            if cnt == 1:
                self.need_captcha = False
            else:
                self.need_captcha = True
            
            # if cnt > max_cnt:
            #     print("错误次数过多，稍后再来，不然要被锁定50min")
            #     break
            
            if cnt == 4:
                print("最有一次输入验证码，确保输入正确，否则将会被锁定，输入完验证码别点登录!!!")
                # 需要用户手动输入验证码
                self.need_captcha_user_input = True
                time.sleep(10)
            
            # 不睡眠会导致页面不能及时刷新，找不到相应元素
            url = "https://{}/web/frame/login.html".format(self.ip)
            driver.get(url)
            time.sleep(3)
            
            if self.need_captcha and not self.need_captcha_user_input:
                # 下载验证码
                img_vcode = driver.find_element("id", "img_vcode")
                
                WebDriverWait(driver, 0).until(EC.visibility_of_element_located((By.CSS_SELECTOR, "#img_vcode")))
                driver.find_element_by_css_selector("#img_vcode").screenshot("captcha.jpeg")
                # 识别验证码
                captcha_str = self.get_captcha_str()
                
            time.sleep(2)
            driver.find_element("id", "user_name").send_keys(self.username)
            time.sleep(2)
            driver.find_element("id", "password").send_keys(self.password)
            login_btn = driver.find_element("id", "login_button")
            
            if self.need_captcha and not self.need_captcha_user_input:
                time.sleep(2)
                driver.find_element("id", "vldcode").send_keys(captcha_str)
                
            login_btn.click()
            cnt += 1
            
            # 找不到登录按钮表示验证码通过，退出
            try:
                time.sleep(3)
                driver.find_element("id", "login_button")
                print("验证码识别出错，正在刷新页面重新登陆")
                # driver.refresh()
            except Exception as e:
                print("登陆成功")
                break

        sessions = driver.get_cookies()
        json_sessions = json.dumps(sessions)
        
        print("Cookielit:----------------")
        all_cookies=self.driver.get_cookies();
        cookies_dict = {}
        for cookie in all_cookies:
            print(cookie)
            cookies_dict[cookie['name']] = cookie['value']
            
            
        return cookies_dict

        
    def do_all_inspection(self) -> str:
        cookie_dict = self.get_session_cookie()
        
        # do inspection on items
        cpu_info = self.cpu_inspection(cookie_dict, 'need to delete')
        memory_info = self.memory_inspection(cookie_dict, '1')
        interface_info = self.interface_inspection(cookie_dict, '1')
        engine_info = self.engine_inspection(cookie_dict, '1')
        license_info = self.license_status_inspection(cookie_dict, '1')
        license_status = self.license_deadline_inspection(cookie_dict, '1')
        time_info = self.time_inspection(cookie_dict, '1')
        signature_info = self.signatures_inspection(cookie_dict, '1')
        disk_info = self.storage_inspection(cookie_dict, '1')
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("节点信息" )
        table.add_column("设备名称" )
        table.add_column("设备型号" )
        table.add_column("CPU信息")
        table.add_column("内存信息")
        table.add_column("存储信息")
        table.add_column("接口信息")
        table.add_column("特征库版本")
        table.add_column("授权状态")
        table.add_column("引擎状态")
        table.add_column("授权信息")
        table.add_column("时间信息")
        table.add_row(
            str(self.nodename), str(self.dev_name), str(self.dev_type), str(cpu_info), str(memory_info), str(disk_info), str(interface_info), str(signature_info), 
            str(license_status), str(engine_info), str(license_info), str(time_info)
        )
        console.print(table)
        
        print("==============================")
        print("节点信息:" + self.nodename)
        print("设备信息:" + self.dev_name)
        print("设备型号:" + self.dev_type)
        print("CPU信息:" + cpu_info)
        print("内存信息:" + memory_info)
        print("磁盘信息:" + disk_info)
        print("接口信息:\n" + interface_info)
        print("特征库版本:\n" + signature_info)
        print("授权状态:\n" + license_status)
        print("引擎状态:" + engine_info)
        print("授权信息:" + license_info)
        print("时间信息:" + time_info)
        print("==============================")

        return "正常"
   
    def interface_inspection(self, cookie_dict, session):
        # 前端JS逻辑如下
        # if(aq.AdminState==4&&aq.OperState==3)
        #  {o=ak.portEnable}
        #  else{
        #     if(aq.AdminState==4&&aq.OperState==2)
        #     {o=ak.portDown}
        #     else{
        #         if(aq.AdminState==2&&aq.OperState==2)
        #         {
        #           o=ak.portADM
        #         }
        #         else{
        #           if(aq.isSharePort){
        #             if(aq.SharePortOperStatus==2&&aq.SharePortAdminStatus==2) {
        #               o=ak.portADM
        #             }
        #             else{
        #               if(aq.SharePortOperStatus==1){
        #                 o=ak.portEnable
        #               }else{
        #                 o=ak.portDown
        #               }
        #             }}else{o=ak.portUseless}}}}

        cookies = {
            'vindex': '=26=01=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'abcd1234': 'true',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==26=01=0AB00=0R; supportLang=cn%2Cen; lang=cn; abcd1234=true; sessionid=20000116d19363f49703cc1e3413041fe160; loginid=d28f8ccad054d34efab4ea32fb425409; 20000116d19363f49703cc1e3413041fe160=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CDevice%3E%3CBase%3E%3CMinChassisNum%2F%3E%3CMaxChassisNum%2F%3E%3CMinSlotNum%2F%3E%3CMaxSlotNum%2F%3E%3C%2FBase%3E%3CBoards%3E%3CBoard%3E%3CDeviceNode%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CCPUID%2F%3E%3C%2FDeviceNode%3E%3CPhysicalIndex%2F%3E%3CRole%2F%3E%3C%2FBoard%3E%3C%2FBoards%3E%3CPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%2F%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CSubSlot%2F%3E%3CDescription%2F%3E%3CVendorType%2F%3E%3CContainedIn%2F%3E%3CClass%2F%3E%3CName%2F%3E%3C%2FEntity%3E%3C%2FPhysicalEntities%3E%3CExtPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%2F%3E%3CAdminState%2F%3E%3COperState%2F%3E%3C%2FEntity%3E%3C%2FExtPhysicalEntities%3E%3C%2FDevice%3E%3CIfmgr%3E%3CInterfaces%3E%3CInterface%3E%3CIfIndex%2F%3E%3CName%2F%3E%3CifTypeExt%2F%3E%3CifType%2F%3E%3CDescription%2F%3E%3CAdminStatus%2F%3E%3COperStatus%2F%3E%3CActualSpeed%2F%3E%3CLinkType%2F%3E%3CInetAddressIPV4%2F%3E%3CInetAddressIPV4Mask%2F%3E%3CPhysicalIndex%2F%3E%3CMAC%2F%3E%3CPortLayer%2F%3E%3CSubPort%2F%3E%3C%2FInterface%3E%3C%2FInterfaces%3E%3CEthInterfaces%3E%3CInterface%3E%3CIfIndex%2F%3E%3CCombo%2F%3E%3C%2FInterface%3E%3C%2FEthInterfaces%3E%3CStatistics%3E%3CInterface%3E%3CIfIndex%2F%3E%3CName%2F%3E%3CAbbreviatedName%2F%3E%3CInOctets%2F%3E%3CInUcastPkts%2F%3E%3CInNUcastPkts%2F%3E%3CInDiscards%2F%3E%3CInErrors%2F%3E%3CInUnknownProtos%2F%3E%3CInRate%2F%3E%3COutOctets%2F%3E%3COutUcastPkts%2F%3E%3COutNUcastPkts%2F%3E%3COutDiscards%2F%3E%3COutErrors%2F%3E%3COutRate%2F%3E%3CLastClear%2F%3E%3C%2FInterface%3E%3C%2FStatistics%3E%3CEthInterfaceCapabilities%3E%3CInterface%3E%3CIfIndex%2F%3E%3CCombo%2F%3E%3C%2FInterface%3E%3C%2FEthInterfaceCapabilities%3E%3C%2FIfmgr%3E%3CSecurityZone%3E%3CInterfaces%3E%3CInterface%3E%3CZoneName%2F%3E%3CIfIndex%2F%3E%3CVlanList%2F%3E%3C%2FInterface%3E%3C%2FInterfaces%3E%3C%2FSecurityZone%3E%3CIPV6ADDRESS%3E%3CIpv6Addresses%3E%3CAddressEntry%3E%3CIfIndex%2F%3E%3CIpv6Address%2F%3E%3CAddressOrigin+web%3AregExp%3D%221%7C2%22%2F%3E%3CIpv6PrefixLength%2F%3E%3CAnycastFlag%2F%3E%3C%2FAddressEntry%3E%3C%2FIpv6Addresses%3E%3C%2FIPV6ADDRESS%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=Dashboard%2FM_IfInfoPanel"

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        json_data = json.loads(response.text)
        
        interface_msg = "端口名称\t端口状态\n"
        for i in json_data['Ifmgr']['Interfaces']:
            interface_name = i['Name']
            admin_status = int(i['AdminStatus'])
            oper_status = int(i['OperStatus'])
            port_status = ""
            
            # 正常端口
            # if admin_status == 4 and oper_status == 3:
            #     port_status = "链路正常"
            # elif admin_status == 4 and oper_status == 2:
            #     port_status = "链路故障"
            # elif admin_status == 2 and oper_status == 2:
            #     port_status = "手动关闭"
            # else:
            #     port_status = "未知"
            
            # isSharePort == True, 这里默认所有端口都是shareport，如何判断shareport,
            # 具体逻辑没分析出来
            if admin_status == 2 and oper_status == 2:
                port_status = "ADM"
            else:
                if oper_status == 1:
                    port_status = "链路正常"
                else:
                    port_status = "链路故障"
            
            interface_msg += interface_name + '\t' + port_status + "\n"
            
        return interface_msg
                
    def time_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'vindex': '=10=05=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'abcd1234': 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==10=05=0AB00=0R; supportLang=cn%2Cen; lang=cn; sessionid=20000188e940aa9226c627fd02c0b358cfee; loginid=7bf0860bbbac54efb4688d8b919b0027; 20000188e940aa9226c627fd02c0b358cfee=true; abcd1234=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CFundamentals%3E%3CNetconfResXPath%3E%3CXPath%3E%3CPath%3EMDC%2FContexts%2FContext%2FMDCID%3C%2FPath%3E%3C%2FXPath%3E%3CXPath%3E%3CPath%3EContext%2FContextInformations%2FContextInformation%2FContextID%3C%2FPath%3E%3C%2FXPath%3E%3C%2FNetconfResXPath%3E%3C%2FFundamentals%3E%3CDevice%3E%3CBase%3E%3CLocalTime%2F%3E%3CClockProtocol%3E%3CMDCID%2F%3E%3CProtocol%2F%3E%3C%2FClockProtocol%3E%3CTimeZone%3E%3CZone%2F%3E%3CZoneName%2F%3E%3C%2FTimeZone%3E%3CHostName%2F%3E%3C%2FBase%3E%3CSummerTime%3E%3CName%2F%3E%3CAddTime%2F%3E%3CDateBased%3E%3CBeginMonth%2F%3E%3CBeginDay%2F%3E%3CBeginHour%2F%3E%3CBeginMinute%2F%3E%3CBeginSecond%2F%3E%3CEndMonth%2F%3E%3CEndDay%2F%3E%3CEndHour%2F%3E%3CEndMinute%2F%3E%3CEndSecond%2F%3E%3C%2FDateBased%3E%3CWeekBased%3E%3CBeginMonth%2F%3E%3CBeginWeek%2F%3E%3CBeginWeekDay%2F%3E%3CBeginHour%2F%3E%3CBeginMinute%2F%3E%3CBeginSecond%2F%3E%3CEndMonth%2F%3E%3CEndWeek%2F%3E%3CEndWeekDay%2F%3E%3CEndHour%2F%3E%3CEndMinute%2F%3E%3CEndSecond%2F%3E%3C%2FWeekBased%3E%3C%2FSummerTime%3E%3C%2FDevice%3E%3CIfmgr%3E%3CInterfaces%3E%3CInterface%3E%3CIfIndex%2F%3E%3CAbbreviatedName%2F%3E%3CifTypeExt%2F%3E%3C%2FInterface%3E%3C%2FInterfaces%3E%3C%2FIfmgr%3E%3CL3vpn%3E%3CL3vpnVRF%3E%3CVRF%3E%3CVRF%2F%3E%3CVrfIndex%2F%3E%3CDescription%2F%3E%3CAssociatedInterfaceCount%2F%3E%3C%2FVRF%3E%3C%2FL3vpnVRF%3E%3C%2FL3vpn%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=M_Device%2FM_Maintenance%2FM_DeviceSettings%2FM_BasicDatetime"

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        
        if response.status_code != 200:
            return "获取时间出错"
        else:
            time_str = json.loads(response.content)['Device']['Base'][0]['LocalTime']
            return time_str
        
    
    def license_deadline_inspection(self, cookie_dict, session) -> str:

        cookies = {
            'vindex': '=0f=0d=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'abcd1234': 'true',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==0f=0d=0AB00=0R; supportLang=cn%2Cen; lang=cn; abcd1234=true; sessionid=2000011758b6944ddbce8fe357115abae6b9; loginid=8138d6c438a8cee6c019536190989509; 2000011758b6944ddbce8fe357115abae6b9=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CLicense%3E%3CFeatures%3E%3CFeature%3E%3CDeviceNode%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CCPUID%2F%3E%3C%2FDeviceNode%3E%3CName%2F%3E%3CState%2F%3E%3C%2FFeature%3E%3C%2FFeatures%3E%3CFeatureSummaries%3E%3CSummary%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CCPUID%2F%3E%3CIndex%2F%3E%3CFeatureIndex%2F%3E%3CFeature%2F%3E%3CProductDescr%2F%3E%3CFileDescr%2F%3E%3CState%2F%3E%3CInstalled%3E%3CActivationFile%2F%3E%3C%2FInstalled%3E%3CUninstalled%3E%3CUninstActivationFile%2F%3E%3CUninstActivationKey%2F%3E%3C%2FUninstalled%3E%3CType%2F%3E%3CInstalledTime%2F%3E%3CUninstalledTime%2F%3E%3CDaysLeft%2F%3E%3CDaysLeftWarning%2F%3E%3CValidityStart%2F%3E%3CValidityEnd%2F%3E%3CExpiredDays%2F%3E%3CCount%2F%3E%3C%2FSummary%3E%3C%2FFeatureSummaries%3E%3CSystems%3E%3CSystem%3E%3CDeviceNode%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CCPUID%2F%3E%3C%2FDeviceNode%3E%3CSerialNumber%2F%3E%3CDeviceIDType%2F%3E%3CDeviceID%2F%3E%3CHardwareInfo%2F%3E%3CMax%2F%3E%3CUsed%2F%3E%3CRecyclable%2F%3E%3CInstallType%2F%3E%3CActivationFileStoragePath%2F%3E%3CSystemType%2F%3E%3C%2FSystem%3E%3C%2FSystems%3E%3C%2FLicense%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=M_Device%2FM_License"
        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        
        lic_str = ""
        if response.status_code == 200:
            lic_info = json.loads(response.text)
            for i in lic_info['License']['FeatureSummaries']:
                # print(i['Feature'], i['ValidityStart'], i['ValidityEnd'])
                lic_str += "%s\t%s\t%s\n" % (i['Feature'], i['ValidityStart'], i['ValidityEnd'])
        else:
            return "获取授权时间出错"
        
        return lic_str
    
    def license_status_inspection(self, cookie_dict, session) -> str:
        return "根据授权时间判断"
    
    def engine_inspection(self, cookie_dict, session) -> str:
        return "正常"
    
    def signatures_inspection(self, cookie_dict, session) -> str:
        return "不适用"
    
    def memory_inspection(self, cookie_dict, session) -> str:
        cookies = {
            'vindex': '=0e=02=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'abcd1234': 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==0e=02=0AB00=0R; supportLang=cn%2Cen; lang=cn; sessionid=200001df735d122d0baffd187e1278dc9eb6; loginid=b2d27ed010f2981beec7b7036b63cfdd; 200001df735d122d0baffd187e1278dc9eb6=true; abcd1234=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CDevice%3E%3CExtPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%3E4%3C%2FPhysicalIndex%3E%3CCpuUsage%2F%3E%3CMemUsage%2F%3E%3C%2FEntity%3E%3C%2FExtPhysicalEntities%3E%3C%2FDevice%3E%3CFileSystem%3E%3CPartitions%3E%3CPartition%3E%3CName%2F%3E%3CTotal%2F%3E%3CUsed%2F%3E%3CFree%2F%3E%3CBootable%2F%3E%3C%2FPartition%3E%3C%2FPartitions%3E%3C%2FFileSystem%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=Dashboard%2FM_Dashboard"
        
        print(cookies, headers)

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        
        if response.status_code == 200:
            data = json.loads(response.text)
            mem_usage = data['Device']['ExtPhysicalEntities'][0]['MemUsage']
            return "Mem使用率%s%%" % mem_usage
        else:
            return "获取内存信息失败"
        
    # 磁盘巡检
    def storage_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'vindex': '=0e=02=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'abcd1234': 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==28=09=0AB00=0R; supportLang=cn%2Cen; lang=cn; sessionid=200001e00304884c64d3dab406b84aa83242; loginid=f41a2c7672d9ebe3060b321437f88ba6; 200001e00304884c64d3dab406b84aa83242=true; abcd1234=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CDevice%3E%3CExtPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%3E4%3C%2FPhysicalIndex%3E%3CCpuUsage%2F%3E%3CMemUsage%2F%3E%3C%2FEntity%3E%3C%2FExtPhysicalEntities%3E%3C%2FDevice%3E%3CFileSystem%3E%3CPartitions%3E%3CPartition%3E%3CName%2F%3E%3CTotal%2F%3E%3CUsed%2F%3E%3CFree%2F%3E%3CBootable%2F%3E%3C%2FPartition%3E%3C%2FPartitions%3E%3C%2FFileSystem%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=Dashboard%2FM_Dashboard"

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        print(response.text)
        
        json_storage = json.loads(response.text)
        
        disk_msg = "存储名称\t使用率\n"
        for i in json_storage['FileSystem']['Partitions']:
            name = i['Name']
            percent = int(i['Used']) / int(i['Total'])
            disk_msg += f"f{name}\t{percent}%\n"
            
        return disk_msg
    
    def cpu_inspection(self, cookie_dict, session) -> str:
        cookies = {
            'vindex': '=0e=02=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'abcd1234': 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==0e=02=0AB00=0R; supportLang=cn%2Cen; lang=cn; sessionid=200001df735d122d0baffd187e1278dc9eb6; loginid=b2d27ed010f2981beec7b7036b63cfdd; 200001df735d122d0baffd187e1278dc9eb6=true; abcd1234=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CDevice%3E%3CExtPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%3E4%3C%2FPhysicalIndex%3E%3CCpuUsage%2F%3E%3CMemUsage%2F%3E%3C%2FEntity%3E%3C%2FExtPhysicalEntities%3E%3C%2FDevice%3E%3CFileSystem%3E%3CPartitions%3E%3CPartition%3E%3CName%2F%3E%3CTotal%2F%3E%3CUsed%2F%3E%3CFree%2F%3E%3CBootable%2F%3E%3C%2FPartition%3E%3C%2FPartitions%3E%3C%2FFileSystem%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=Dashboard%2FM_Dashboard"

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        
        if response.status_code == 200:
            data = json.loads(response.text)
            cpu_usage = data['Device']['ExtPhysicalEntities'][0]['CpuUsage']
            return "CPU使用率%s%%" % cpu_usage
        else:
            return "获取CPU信息失败"
            
class NTAInspection(DeviceInspectionable, DeviceAuthentication):
    
    def __init__(self, nodename: str, ip: str, username: str, password: str) -> None:
        self.ip = ip
        self.nodename = nodename
        self.username = username
        self.password = password
        self.dev_name = "NTA"
        # e.g. A2000
        self.dev_type = "XXX"
        self.need_captcha = True
        self.need_captcha_user_input = False
        
        DeviceAuthentication.__init__(self, self.dev_name, False, ip, username, password)
        
    def get_captcha(self) -> str:
        pass
        
    def get_captcha_str(self) -> str:
        try:
            ocr = ddddocr.DdddOcr(show_ad=False)
            with open('captcha.jpeg', 'rb') as f:
                image_bytes = f.read()

            res = ocr.classification(image_bytes)
            print(res)
            return res
        except Exception as e:
            print(e)
            print("ddddocr识别出错")
            exit(-3)
            
    def get_session_cookie(self):
        
        options = webdriver.ChromeOptions()

        # ignore unsafe https
        options.add_argument('ignore-certificate-errors')
        # options.add_argument('--headless')
        self.driver = webdriver.Chrome(options=options, executable_path=r'C:\Users\hushanglai\Desktop\inspection\chromedriver.exe')
        driver = self.driver
        
        # 尝试不停登录, 数据库审计比较特殊，验证码比较复杂，ddddocr可能识别很多次识别不出来
        # ? 为了防止账号被锁定，这里只尝试4次, 为什么用Selenium会有验证码，直接登录没有
        max_cnt = 4
        cnt = 1
        while True:
            
            # 尝试用find_element去找验证码的id，无论页面是有还是没有都会找到该元素，所以该方法不管用
            # 如果第一次登陆默认没有验证码，后续就会弹出验证码
            if cnt == 1:
                self.need_captcha = False
            else:
                self.need_captcha = True
            
            # if cnt > max_cnt:
            #     print("错误次数过多，稍后再来，不然要被锁定50min")
            #     break
            
            if cnt == 4:
                print("最有一次输入验证码，确保输入正确，否则将会被锁定，输入完验证码别点登录!!!")
                # 需要用户手动输入验证码
                self.need_captcha_user_input = True
                time.sleep(10)
            
            # 不睡眠会导致页面不能及时刷新，找不到相应元素
            url = "https://{}/web/frame/login.html".format(self.ip)
            driver.get(url)
            time.sleep(3)
            
            if self.need_captcha and not self.need_captcha_user_input:
                # 下载验证码
                img_vcode = driver.find_element("id", "img_vcode")
                
                WebDriverWait(driver, 0).until(EC.visibility_of_element_located((By.CSS_SELECTOR, "#img_vcode")))
                driver.find_element_by_css_selector("#img_vcode").screenshot("captcha.jpeg")
                # 识别验证码
                captcha_str = self.get_captcha_str()
                
            time.sleep(2)
            driver.find_element("id", "user_name").send_keys(self.username)
            time.sleep(2)
            driver.find_element("id", "password").send_keys(self.password)
            login_btn = driver.find_element("id", "login_button")
            
            if self.need_captcha and not self.need_captcha_user_input:
                time.sleep(2)
                driver.find_element("id", "vldcode").send_keys(captcha_str)
                
            login_btn.click()
            cnt += 1
            
            # 找不到登录按钮表示验证码通过，退出
            try:
                time.sleep(3)
                driver.find_element("id", "login_button")
                print("验证码识别出错，正在刷新页面重新登陆")
                # driver.refresh()
            except Exception as e:
                print("登陆成功")
                break

        sessions = driver.get_cookies()
        json_sessions = json.dumps(sessions)
        
        print("Cookielit:----------------")
        all_cookies=self.driver.get_cookies();
        cookies_dict = {}
        for cookie in all_cookies:
            print(cookie)
            cookies_dict[cookie['name']] = cookie['value']
            
            
        return cookies_dict

        
    def do_all_inspection(self) -> str:
        cookie_dict = self.get_session_cookie()
        
        # do inspection on items
        cpu_info = self.cpu_inspection(cookie_dict, 'need to delete')
        memory_info = self.memory_inspection(cookie_dict, '1')
        interface_info = self.interface_inspection(cookie_dict, '1')
        engine_info = self.engine_inspection(cookie_dict, '1')
        license_info = self.license_status_inspection(cookie_dict, '1')
        license_status = self.license_deadline_inspection(cookie_dict, '1')
        time_info = self.time_inspection(cookie_dict, '1')
        signature_info = self.signatures_inspection(cookie_dict, '1')
        disk_info = self.storage_inspection(cookie_dict, '1')
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("节点信息" )
        table.add_column("设备名称" )
        table.add_column("设备型号" )
        table.add_column("CPU信息")
        table.add_column("内存信息")
        table.add_column("存储信息")
        table.add_column("接口信息")
        table.add_column("特征库版本")
        table.add_column("授权状态")
        table.add_column("引擎状态")
        table.add_column("授权信息")
        table.add_column("时间信息")
        table.add_row(
            str(self.nodename), str(self.dev_name), str(self.dev_type), str(cpu_info), str(memory_info), str(disk_info), str(interface_info), str(signature_info), 
            str(license_status), str(engine_info), str(license_info), str(time_info)
        )
        console.print(table)
        
        print("==============================")
        print("节点信息:" + self.nodename)
        print("设备信息:" + self.dev_name)
        print("设备型号:" + self.dev_type)
        print("CPU信息:" + cpu_info)
        print("内存信息:" + memory_info)
        print("磁盘信息:" + disk_info)
        print("接口信息:\n" + interface_info)
        print("特征库版本:\n" + signature_info)
        print("授权状态:\n" + license_status)
        print("引擎状态:" + engine_info)
        print("授权信息:" + license_info)
        print("时间信息:" + time_info)
        print("==============================")

        return "正常"
   
    def interface_inspection(self, cookie_dict, session):
        # 前端JS逻辑如下
        # if(aq.AdminState==4&&aq.OperState==3)
        #  {o=ak.portEnable}
        #  else{
        #     if(aq.AdminState==4&&aq.OperState==2)
        #     {o=ak.portDown}
        #     else{
        #         if(aq.AdminState==2&&aq.OperState==2)
        #         {
        #           o=ak.portADM
        #         }
        #         else{
        #           if(aq.isSharePort){
        #             if(aq.SharePortOperStatus==2&&aq.SharePortAdminStatus==2) {
        #               o=ak.portADM
        #             }
        #             else{
        #               if(aq.SharePortOperStatus==1){
        #                 o=ak.portEnable
        #               }else{
        #                 o=ak.portDown
        #               }
        #             }}else{o=ak.portUseless}}}}

        cookies = {
            'vindex': '=26=01=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'abcd1234': 'true',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==26=01=0AB00=0R; supportLang=cn%2Cen; lang=cn; abcd1234=true; sessionid=20000116d19363f49703cc1e3413041fe160; loginid=d28f8ccad054d34efab4ea32fb425409; 20000116d19363f49703cc1e3413041fe160=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CDevice%3E%3CBase%3E%3CMinChassisNum%2F%3E%3CMaxChassisNum%2F%3E%3CMinSlotNum%2F%3E%3CMaxSlotNum%2F%3E%3C%2FBase%3E%3CBoards%3E%3CBoard%3E%3CDeviceNode%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CCPUID%2F%3E%3C%2FDeviceNode%3E%3CPhysicalIndex%2F%3E%3CRole%2F%3E%3C%2FBoard%3E%3C%2FBoards%3E%3CPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%2F%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CSubSlot%2F%3E%3CDescription%2F%3E%3CVendorType%2F%3E%3CContainedIn%2F%3E%3CClass%2F%3E%3CName%2F%3E%3C%2FEntity%3E%3C%2FPhysicalEntities%3E%3CExtPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%2F%3E%3CAdminState%2F%3E%3COperState%2F%3E%3C%2FEntity%3E%3C%2FExtPhysicalEntities%3E%3C%2FDevice%3E%3CIfmgr%3E%3CInterfaces%3E%3CInterface%3E%3CIfIndex%2F%3E%3CName%2F%3E%3CifTypeExt%2F%3E%3CifType%2F%3E%3CDescription%2F%3E%3CAdminStatus%2F%3E%3COperStatus%2F%3E%3CActualSpeed%2F%3E%3CLinkType%2F%3E%3CInetAddressIPV4%2F%3E%3CInetAddressIPV4Mask%2F%3E%3CPhysicalIndex%2F%3E%3CMAC%2F%3E%3CPortLayer%2F%3E%3CSubPort%2F%3E%3C%2FInterface%3E%3C%2FInterfaces%3E%3CEthInterfaces%3E%3CInterface%3E%3CIfIndex%2F%3E%3CCombo%2F%3E%3C%2FInterface%3E%3C%2FEthInterfaces%3E%3CStatistics%3E%3CInterface%3E%3CIfIndex%2F%3E%3CName%2F%3E%3CAbbreviatedName%2F%3E%3CInOctets%2F%3E%3CInUcastPkts%2F%3E%3CInNUcastPkts%2F%3E%3CInDiscards%2F%3E%3CInErrors%2F%3E%3CInUnknownProtos%2F%3E%3CInRate%2F%3E%3COutOctets%2F%3E%3COutUcastPkts%2F%3E%3COutNUcastPkts%2F%3E%3COutDiscards%2F%3E%3COutErrors%2F%3E%3COutRate%2F%3E%3CLastClear%2F%3E%3C%2FInterface%3E%3C%2FStatistics%3E%3CEthInterfaceCapabilities%3E%3CInterface%3E%3CIfIndex%2F%3E%3CCombo%2F%3E%3C%2FInterface%3E%3C%2FEthInterfaceCapabilities%3E%3C%2FIfmgr%3E%3CSecurityZone%3E%3CInterfaces%3E%3CInterface%3E%3CZoneName%2F%3E%3CIfIndex%2F%3E%3CVlanList%2F%3E%3C%2FInterface%3E%3C%2FInterfaces%3E%3C%2FSecurityZone%3E%3CIPV6ADDRESS%3E%3CIpv6Addresses%3E%3CAddressEntry%3E%3CIfIndex%2F%3E%3CIpv6Address%2F%3E%3CAddressOrigin+web%3AregExp%3D%221%7C2%22%2F%3E%3CIpv6PrefixLength%2F%3E%3CAnycastFlag%2F%3E%3C%2FAddressEntry%3E%3C%2FIpv6Addresses%3E%3C%2FIPV6ADDRESS%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=Dashboard%2FM_IfInfoPanel"

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        json_data = json.loads(response.text)
        
        interface_msg = "端口名称\t端口状态\n"
        for i in json_data['Ifmgr']['Interfaces']:
            interface_name = i['Name']
            admin_status = int(i['AdminStatus'])
            oper_status = int(i['OperStatus'])
            port_status = ""
            
            # 正常端口
            # if admin_status == 4 and oper_status == 3:
            #     port_status = "链路正常"
            # elif admin_status == 4 and oper_status == 2:
            #     port_status = "链路故障"
            # elif admin_status == 2 and oper_status == 2:
            #     port_status = "手动关闭"
            # else:
            #     port_status = "未知"
            
            # isSharePort == True, 这里默认所有端口都是shareport，如何判断shareport,
            # 具体逻辑没分析出来
            if admin_status == 2 and oper_status == 2:
                port_status = "ADM"
            else:
                if oper_status == 1:
                    port_status = "链路正常"
                else:
                    port_status = "链路故障"
            
            interface_msg += interface_name + '\t' + port_status + "\n"
            
        return interface_msg
                
    def time_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'vindex': '=10=05=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'abcd1234': 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==10=05=0AB00=0R; supportLang=cn%2Cen; lang=cn; sessionid=20000188e940aa9226c627fd02c0b358cfee; loginid=7bf0860bbbac54efb4688d8b919b0027; 20000188e940aa9226c627fd02c0b358cfee=true; abcd1234=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CFundamentals%3E%3CNetconfResXPath%3E%3CXPath%3E%3CPath%3EMDC%2FContexts%2FContext%2FMDCID%3C%2FPath%3E%3C%2FXPath%3E%3CXPath%3E%3CPath%3EContext%2FContextInformations%2FContextInformation%2FContextID%3C%2FPath%3E%3C%2FXPath%3E%3C%2FNetconfResXPath%3E%3C%2FFundamentals%3E%3CDevice%3E%3CBase%3E%3CLocalTime%2F%3E%3CClockProtocol%3E%3CMDCID%2F%3E%3CProtocol%2F%3E%3C%2FClockProtocol%3E%3CTimeZone%3E%3CZone%2F%3E%3CZoneName%2F%3E%3C%2FTimeZone%3E%3CHostName%2F%3E%3C%2FBase%3E%3CSummerTime%3E%3CName%2F%3E%3CAddTime%2F%3E%3CDateBased%3E%3CBeginMonth%2F%3E%3CBeginDay%2F%3E%3CBeginHour%2F%3E%3CBeginMinute%2F%3E%3CBeginSecond%2F%3E%3CEndMonth%2F%3E%3CEndDay%2F%3E%3CEndHour%2F%3E%3CEndMinute%2F%3E%3CEndSecond%2F%3E%3C%2FDateBased%3E%3CWeekBased%3E%3CBeginMonth%2F%3E%3CBeginWeek%2F%3E%3CBeginWeekDay%2F%3E%3CBeginHour%2F%3E%3CBeginMinute%2F%3E%3CBeginSecond%2F%3E%3CEndMonth%2F%3E%3CEndWeek%2F%3E%3CEndWeekDay%2F%3E%3CEndHour%2F%3E%3CEndMinute%2F%3E%3CEndSecond%2F%3E%3C%2FWeekBased%3E%3C%2FSummerTime%3E%3C%2FDevice%3E%3CIfmgr%3E%3CInterfaces%3E%3CInterface%3E%3CIfIndex%2F%3E%3CAbbreviatedName%2F%3E%3CifTypeExt%2F%3E%3C%2FInterface%3E%3C%2FInterfaces%3E%3C%2FIfmgr%3E%3CL3vpn%3E%3CL3vpnVRF%3E%3CVRF%3E%3CVRF%2F%3E%3CVrfIndex%2F%3E%3CDescription%2F%3E%3CAssociatedInterfaceCount%2F%3E%3C%2FVRF%3E%3C%2FL3vpnVRF%3E%3C%2FL3vpn%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=M_Device%2FM_Maintenance%2FM_DeviceSettings%2FM_BasicDatetime"

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        
        if response.status_code != 200:
            return "获取时间出错"
        else:
            time_str = json.loads(response.content)['Device']['Base'][0]['LocalTime']
            return time_str
        
    
    def license_deadline_inspection(self, cookie_dict, session) -> str:

        cookies = {
            'vindex': '=0f=0d=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'abcd1234': 'true',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==0f=0d=0AB00=0R; supportLang=cn%2Cen; lang=cn; abcd1234=true; sessionid=2000011758b6944ddbce8fe357115abae6b9; loginid=8138d6c438a8cee6c019536190989509; 2000011758b6944ddbce8fe357115abae6b9=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CLicense%3E%3CFeatures%3E%3CFeature%3E%3CDeviceNode%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CCPUID%2F%3E%3C%2FDeviceNode%3E%3CName%2F%3E%3CState%2F%3E%3C%2FFeature%3E%3C%2FFeatures%3E%3CFeatureSummaries%3E%3CSummary%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CCPUID%2F%3E%3CIndex%2F%3E%3CFeatureIndex%2F%3E%3CFeature%2F%3E%3CProductDescr%2F%3E%3CFileDescr%2F%3E%3CState%2F%3E%3CInstalled%3E%3CActivationFile%2F%3E%3C%2FInstalled%3E%3CUninstalled%3E%3CUninstActivationFile%2F%3E%3CUninstActivationKey%2F%3E%3C%2FUninstalled%3E%3CType%2F%3E%3CInstalledTime%2F%3E%3CUninstalledTime%2F%3E%3CDaysLeft%2F%3E%3CDaysLeftWarning%2F%3E%3CValidityStart%2F%3E%3CValidityEnd%2F%3E%3CExpiredDays%2F%3E%3CCount%2F%3E%3C%2FSummary%3E%3C%2FFeatureSummaries%3E%3CSystems%3E%3CSystem%3E%3CDeviceNode%3E%3CChassis%2F%3E%3CSlot%2F%3E%3CCPUID%2F%3E%3C%2FDeviceNode%3E%3CSerialNumber%2F%3E%3CDeviceIDType%2F%3E%3CDeviceID%2F%3E%3CHardwareInfo%2F%3E%3CMax%2F%3E%3CUsed%2F%3E%3CRecyclable%2F%3E%3CInstallType%2F%3E%3CActivationFileStoragePath%2F%3E%3CSystemType%2F%3E%3C%2FSystem%3E%3C%2FSystems%3E%3C%2FLicense%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=M_Device%2FM_License"
        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        
        lic_str = ""
        if response.status_code == 200:
            lic_info = json.loads(response.text)
            for i in lic_info['License']['FeatureSummaries']:
                # print(i['Feature'], i['ValidityStart'], i['ValidityEnd'])
                lic_str += "%s\t%s\t%s\n" % (i['Feature'], i['ValidityStart'], i['ValidityEnd'])
        else:
            return "获取授权时间出错"
        
        return lic_str
    
    def license_status_inspection(self, cookie_dict, session) -> str:
        return "根据授权时间判断"
    
    def engine_inspection(self, cookie_dict, session) -> str:
        return "正常"
    
    def signatures_inspection(self, cookie_dict, session) -> str:
        return "不适用"
    
    def memory_inspection(self, cookie_dict, session) -> str:
        cookies = {
            'vindex': '=0e=02=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'abcd1234': 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==0e=02=0AB00=0R; supportLang=cn%2Cen; lang=cn; sessionid=200001df735d122d0baffd187e1278dc9eb6; loginid=b2d27ed010f2981beec7b7036b63cfdd; 200001df735d122d0baffd187e1278dc9eb6=true; abcd1234=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CDevice%3E%3CExtPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%3E4%3C%2FPhysicalIndex%3E%3CCpuUsage%2F%3E%3CMemUsage%2F%3E%3C%2FEntity%3E%3C%2FExtPhysicalEntities%3E%3C%2FDevice%3E%3CFileSystem%3E%3CPartitions%3E%3CPartition%3E%3CName%2F%3E%3CTotal%2F%3E%3CUsed%2F%3E%3CFree%2F%3E%3CBootable%2F%3E%3C%2FPartition%3E%3C%2FPartitions%3E%3C%2FFileSystem%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=Dashboard%2FM_Dashboard"
        
        print(cookies, headers)

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        
        if response.status_code == 200:
            data = json.loads(response.text)
            mem_usage = data['Device']['ExtPhysicalEntities'][0]['MemUsage']
            return "Mem使用率%s%%" % mem_usage
        else:
            return "获取内存信息失败"
        
    # 磁盘巡检
    def storage_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'vindex': '=0e=02=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'abcd1234': 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==28=09=0AB00=0R; supportLang=cn%2Cen; lang=cn; sessionid=200001e00304884c64d3dab406b84aa83242; loginid=f41a2c7672d9ebe3060b321437f88ba6; 200001e00304884c64d3dab406b84aa83242=true; abcd1234=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CDevice%3E%3CExtPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%3E4%3C%2FPhysicalIndex%3E%3CCpuUsage%2F%3E%3CMemUsage%2F%3E%3C%2FEntity%3E%3C%2FExtPhysicalEntities%3E%3C%2FDevice%3E%3CFileSystem%3E%3CPartitions%3E%3CPartition%3E%3CName%2F%3E%3CTotal%2F%3E%3CUsed%2F%3E%3CFree%2F%3E%3CBootable%2F%3E%3C%2FPartition%3E%3C%2FPartitions%3E%3C%2FFileSystem%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=Dashboard%2FM_Dashboard"

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        print(response.text)
        
        json_storage = json.loads(response.text)
        
        disk_msg = "存储名称\t使用率\n"
        for i in json_storage['FileSystem']['Partitions']:
            name = i['Name']
            percent = int(i['Used']) / int(i['Total'])
            disk_msg += f"f{name}\t{percent}%\n"
            
        return disk_msg
    
    def cpu_inspection(self, cookie_dict, session) -> str:
        cookies = {
            'vindex': '=0e=02=0AB00=0R',
            'supportLang': 'cn%2Cen',
            'lang': 'cn',
            'sessionid': cookie_dict['sessionid'],
            'loginid': cookie_dict['loginid'],
            cookie_dict['sessionid']: 'true',
            'abcd1234': 'true',
            'login': 'false',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            # 'Cookie': 'vindex==0e=02=0AB00=0R; supportLang=cn%2Cen; lang=cn; sessionid=200001df735d122d0baffd187e1278dc9eb6; loginid=b2d27ed010f2981beec7b7036b63cfdd; 200001df735d122d0baffd187e1278dc9eb6=true; abcd1234=true; login=false',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/wnm/frame/index.php',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = "xml=%3Crpc+message-id%3D'101'+xmlns%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'++xmlns%3Aweb%3D'urn%3Aietf%3Aparams%3Axml%3Ans%3Anetconf%3Abase%3A1.0'%3E%3Cget%3E%3Cfilter+type%3D'subtree'%3E%3Ctop+xmlns%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'+xmlns%3Aweb%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fbase%3A1.0'+xmlns%3Adata%3D'http%3A%2F%2Fwww.h3c.com%2Fnetconf%2Fdata%3A1.0'%3E%3CDevice%3E%3CExtPhysicalEntities%3E%3CEntity%3E%3CPhysicalIndex%3E4%3C%2FPhysicalIndex%3E%3CCpuUsage%2F%3E%3CMemUsage%2F%3E%3C%2FEntity%3E%3C%2FExtPhysicalEntities%3E%3C%2FDevice%3E%3CFileSystem%3E%3CPartitions%3E%3CPartition%3E%3CName%2F%3E%3CTotal%2F%3E%3CUsed%2F%3E%3CFree%2F%3E%3CBootable%2F%3E%3C%2FPartition%3E%3C%2FPartitions%3E%3C%2FFileSystem%3E%3C%2Ftop%3E%3C%2Ffilter%3E%3C%2Fget%3E%3C%2Frpc%3E&req_menu=Dashboard%2FM_Dashboard"

        response = requests.post(f'https://{self.ip}/wnm/get.j', cookies=cookies, headers=headers, data=data, verify=False)
        
        if response.status_code == 200:
            data = json.loads(response.text)
            cpu_usage = data['Device']['ExtPhysicalEntities'][0]['CpuUsage']
            return "CPU使用率%s%%" % cpu_usage
        else:
            return "获取CPU信息失败"
        
        

# situationawareness
class SitualtionAwareness(DeviceInspectionable, DeviceAuthentication):
    
    def __init__(self, nodename:str, ip: str, username: str, password: str) -> None:
        self.ip = ip
        self.nodename = nodename
        self.username = username
        self.password = password
        self.dev_type = "XXX"
        self.dev_name = "SitualtionAwareness"
        self.need_captcha = True
        
        DeviceAuthentication.__init__(self, self.dev_type, self.need_captcha, ip, username, password)
        
    def get_captcha_str(self) -> str:
        try:
            ocr = ddddocr.DdddOcr(show_ad=False)
            with open('captcha.jpeg', 'rb') as f:
                image_bytes = f.read()

            res = ocr.classification(image_bytes)
            print(res)
            return res
        except Exception as e:
            print(e)
            print("ddddocr识别出错")
            exit(-3)
            
    def get_session_cookie(self):
        options = webdriver.ChromeOptions()

        # ignore unsafe https
        options.add_argument('ignore-certificate-errors')
        # options.add_argument('--headless')
        driver = webdriver.Chrome(options=options, executable_path=r'C:\Users\hushanglai\Desktop\inspection\chromedriver.exe')
        self.driver = driver
        
        
        # 尝试不停登录
        while True:
            # need to sleep
            time.sleep(3)
            url = f"https://{self.ip}/toLogin".format(self.ip)
            driver.get(url)
            
            # 点击已阅读同意
            already_read = driver.find_element_by_xpath('//*[@id="theForm"]/div[5]/div/label')
            print(already_read.is_selected())
            if not already_read.is_selected():
                # already_read = driver.find_element_by_xpath('//*[@id="theForm"]/div[5]/div/label')
                already_read.click()

            # If the CAPTCHA element is present in the webpage's HTML 
            # source code but not visible on the page, 
            # it might be hidden using CSS styles or JavaScript. 
            # In such cases, you can use Selenium's is_displayed() 
            # method to check if the element is visible or not.
            
            try:
                time.sleep(3)
                ele = driver.find_element_by_xpath('//*[@id="codetxt"]')
                if ele.is_displayed():
                    print("找到验证码")
                else:
                    print("未找到验证码")
                    self.need_captcha = False
            except Exception as e:
                print("验证码元素不存在")
            
            if self.need_captcha:
                time.sleep(3)
                try:
                    captcha_element = driver.find_element_by_xpath('//*[@id="codetxt"]')

                    # Take a screenshot of the CAPTCHA element
                    screenshot_path = 'captcha.jpeg'
                    captcha_element.screenshot(screenshot_path)
            
                except Exception as e:
                    print(e)
                    print("获取验证码出错")
                    self.need_captcha = False
                    
                try:
                    # 识别验证码
                    captcha_str = self.get_captcha_str()
                except Exception as e:
                    print(e)
                    print("识别验证码出错")
                
            time.sleep(2)
            driver.find_element("id", "username").send_keys(self.username)
            driver.find_element("id", "password").send_keys(self.password)
            login_btn = driver.find_element("id", "loginBtn")
            
            if self.need_captcha:
                # 发送验证码
                time.sleep(2)
                driver.find_element("id", "codeinput").send_keys(captcha_str)
                
            login_btn.click()
        
            # 验证码通过，退出
            try:
                time.sleep(3)
                # 如果还能找到用户名，证明登陆失败
                driver.find_element("id", "username")
                print("验证码识别出错，刷新页面")
            except Exception as e:
                print("登陆成功")
                break

        time.sleep(3)
        sessions = driver.get_cookies()
        
        json_data = json.dumps(sessions)
        print(json_data)
        json_data = json.loads(json_data)
        
        # 通过浏览器f12观察
        auth_info = {}
        for i in json_data:
            if i['name'] == 'server-session-id':
                auth_info['server-session-id'] = i['value']
                
            if i['name'] == 'JSESSIONID':
                auth_info['JSESSIONID'] = i['value']
                
        return auth_info, ""
    
        
    def do_all_inspection(self) -> str:
   
        cookie, session = self.get_session_cookie()

        # do inspection on items
        cpu_info = self.cpu_inspection(cookie, session)
        memory_info = self.memory_inspection(cookie, session)
        disk_info = self.storage_inspection(cookie, session)
        
        interface_info = self.interface_inspection(cookie, session)
        signature_info = self.signature_inspection(cookie, session)
        
        engine_info = self.engine_inspection(cookie, session)
        license_info = self.license_deadline_inspection(cookie, session)
        
        license_status = self.license_status_inspection(cookie, session)
        time_info = self.time_inspection(cookie, session)
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("CPU信息", style="dim")
        table.add_column("内存信息")
        table.add_column("磁盘信息")
        table.add_column("接口信息")
        table.add_column("特征库版本")
        table.add_column("授权状态")
        table.add_column("引擎状态")
        table.add_column("授权信息")
        table.add_column("时间信息")
        table.add_row(
            str(cpu_info), str(memory_info), str(disk_info), str(interface_info), str(signature_info), 
            str(license_status), str(engine_info), str(license_info), str(time_info)
        )
        console.print(table)
        
        print("==============================")
        print("节点信息:" + self.nodename)
        print("设备信息:" + self.dev_name)
        print("设备型号:" + self.dev_type)
        print("CPU信息:" + cpu_info)
        print("内存信息:" + memory_info)
        print("磁盘信息:" + disk_info)
        print("接口信息:" + interface_info)
        print("特征库版本:" + signature_info)
        print("授权状态:" + license_status)
        print("引擎状态:" + engine_info)
        print("授权信息:" + license_info)
        print("时间信息:" + time_info)
        print("==============================")

        return "正常"
        
    def engine_inspection(self, cookie, session):
        return "正常"
    
    def signature_inspection(self, cookie, session):
        
        cookies = {
            'server-session-id': cookie['server-session-id'],
            'tipFlag': 'true',
            'licFlag': 'false',
            'JSESSIONID': cookie['JSESSIONID'],
            'userAgreementAndPrivacyPolicyFlag': 'checked',
            'themeId': '1',
            'themeaddress': 'sea.css',
            'passwordReminder': '',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            'Content-Type': 'application/json;charset=utf-8',
            # 'Cookie': 'server-session-id=88e60a47-5eee-4294-bf08-cccc5ff36f9d; tipFlag=true; licFlag=false; JSESSIONID=4DFA268323FF3D38476521489AB6645E; userAgreementAndPrivacyPolicyFlag=checked; themeId=1; themeaddress=sea.css; passwordReminder=',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/libUpgrade/page',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/libUpgrade/getLibUpgradeInfo', cookies=cookies, headers=headers, verify=False)
        json_data = json.loads(json.dumps(response.json()))
        
        info = "特征库名称\t特征库版本\n"
        for i in json_data:
            info += i['libName'] + "\t" + i['version'] + '\n'

        return info
        
    def license_status_inspection(self, cookie, session):
        return "根据授权时间判断"
        
        
    def interface_inspection(self, cookie, session):
        
        return "正常"
                
    def time_inspection(self, cookie, session) -> str:
        
        cookies = {
            'server-session-id': cookie['server-session-id'],
            'tipFlag': 'true',
            'licFlag': 'false',
            'JSESSIONID': cookie['JSESSIONID'],
            'userAgreementAndPrivacyPolicyFlag': 'checked',
            'themeId': '1',
            'themeaddress': 'sea.css',
            'passwordReminder': '',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json;charset=UTF-8',
            # 'Cookie': 'server-session-id=87a5f112-539e-4b90-be7b-d45c73fd59d0; tipFlag=true; licFlag=false; JSESSIONID=CB02672F0567D37D46315C168C155EEB; userAgreementAndPrivacyPolicyFlag=checked; themeId=1; themeaddress=sea.css; passwordReminder=',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/timeSetting/page',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        json_data = {
            'flag': 0,
        }

        response = requests.post(
            f'https://{self.ip}/timeSetting/getCurrentSysDate',
            cookies=cookies,
            headers=headers,
            json=json_data,
            verify=False,
        )
        
        json_data = json.loads(json.dumps(response.json()))
        
        return json_data['data']

    def license_deadline_inspection(self, cookie, session) -> str:

        cookies = {
            'server-session-id': cookie['server-session-id'],
            'tipFlag': 'true',
            'licFlag': 'false',
            'JSESSIONID': cookie['JSESSIONID'],
            'userAgreementAndPrivacyPolicyFlag': 'checked',
            'themeId': '1',
            'themeaddress': 'sea.css',
            'passwordReminder': '',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Cookie': 'server-session-id=05f2024f-ef0c-4096-96e6-07795185a9fb; tipFlag=true; licFlag=false; JSESSIONID=8AD20A4F25EF771F8D1D48EE11010961; userAgreementAndPrivacyPolicyFlag=checked; themeId=1; themeaddress=sea.css; passwordReminder=',
            'Referer': f'https://{self.ip}/license/licenseManagePage',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.get(f'https://{self.ip}/license/get/permissions', cookies=cookies, headers=headers, verify=False)
        json_data = json.loads(json.dumps(response.json()))
        
        info = "授权名称\t授权到期时间\n"
        for i in json_data['data'].values():
            # info += (i['name'] + '\t' + i['endDate'] if i['endDate'] != '' else '永久有效' + '\n')
            if i['endDate'] == '':
                info += i['name'] + '\t' + "永久有效" + '\n'
            else:
                info += i['name'] + '\t' + i['endDate'] + '\n'
                
            
        return info
    
    def engine_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'server-session-id': cookie_dict['server-session-id'],
            'tipFlag': 'true',
            'licFlag': 'false',
            'JSESSIONID': cookie_dict['JSESSIONID'],
            'userAgreementAndPrivacyPolicyFlag': 'checked',
            'themeId': '1',
            'themeaddress': 'sea.css',
            'passwordReminder': '',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # Already added when you pass json=
            # 'Content-Type': 'application/json',
            # 'Cookie': 'server-session-id=5d237ee8-0d2f-4712-a5dd-32d782561914; tipFlag=true; licFlag=false; JSESSIONID=286075333D0A3DF676E77285AFB35E7C; userAgreementAndPrivacyPolicyFlag=checked; themeId=1; themeaddress=sea.css; passwordReminder=',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/sysMonitor/page',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        json_data = {}

        response = requests.post(f'https://{self.ip}/sysMonitor/apps', cookies=cookies, headers=headers, json=json_data, verify=False)
        
        app_msg = "应用名称\t应用状态\n"
        json_apps = json.loads(response.text)
        for app in json_apps:
            name = app['cn_name']
            status = app['status']
            
            app_msg += name + "\t" + status + "\n"
        
        return app_msg
    
    def signatures_inspection(self, cookie, session) -> str:
        return "不适用"
    
    def memory_inspection(self, cookie, session) -> str:

        cookies = {
            'server-session-id': cookie['server-session-id'],
            'tipFlag': 'true',
            'licFlag': 'false',
            'JSESSIONID': cookie['JSESSIONID'],
            'userAgreementAndPrivacyPolicyFlag': 'checked',
            'themeId': '1',
            'themeaddress': 'sea.css',
            'passwordReminder': '',
            'menuStatus': '1',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'server-session-id=598298e6-e0c2-4e3a-915f-dc06e956e25b; tipFlag=true; licFlag=false; JSESSIONID=973D7BBF5F88A27D70419227FC1DDB9E; userAgreementAndPrivacyPolicyFlag=checked; themeId=1; themeaddress=sea.css; passwordReminder=; menuStatus=1',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/sysMonitor/page',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/sysMonitor/cluster/info', cookies=cookies, headers=headers, verify=False)
        
        mem_info = str(json.loads(json.dumps(response.json()))[0]['MemPercent']) + "%"

        return mem_info
    
    # 存储巡检
    def storage_inspection(self, cookie, session) -> str:
        
        cookies = {
            'server-session-id': cookie['server-session-id'],
            'tipFlag': 'true',
            'licFlag': 'false',
            'JSESSIONID': cookie['JSESSIONID'],
            'userAgreementAndPrivacyPolicyFlag': 'checked',
            'themeId': '1',
            'themeaddress': 'sea.css',
            'passwordReminder': '',
            'menuStatus': '1',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'server-session-id=598298e6-e0c2-4e3a-915f-dc06e956e25b; tipFlag=true; licFlag=false; JSESSIONID=973D7BBF5F88A27D70419227FC1DDB9E; userAgreementAndPrivacyPolicyFlag=checked; themeId=1; themeaddress=sea.css; passwordReminder=; menuStatus=1',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/sysMonitor/page',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/sysMonitor/cluster/info', cookies=cookies, headers=headers, verify=False)
        system_disk_info = str(json.loads(json.dumps(response.json()))[0]['SystemDiskPercent']) + "%"
        data_disk_info = str(json.loads(json.dumps(response.json()))[0]['DataDiskPercent']) + "%"
        disk_msg = "系统盘使用率\t数据盘使用率\n" + system_disk_info + "\t" + data_disk_info + "\n"

        return disk_msg
    
    def cpu_inspection(self, cookie, session) -> str:
        
        cookies = {
            'server-session-id': cookie['server-session-id'],
            'tipFlag': 'true',
            'licFlag': 'false',
            'JSESSIONID': cookie['JSESSIONID'],
            'userAgreementAndPrivacyPolicyFlag': 'checked',
            'themeId': '1',
            'themeaddress': 'sea.css',
            'passwordReminder': '',
            'menuStatus': '1',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'server-session-id=598298e6-e0c2-4e3a-915f-dc06e956e25b; tipFlag=true; licFlag=false; JSESSIONID=973D7BBF5F88A27D70419227FC1DDB9E; userAgreementAndPrivacyPolicyFlag=checked; themeId=1; themeaddress=sea.css; passwordReminder=; menuStatus=1',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/sysMonitor/page',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/sysMonitor/cluster/info', cookies=cookies, headers=headers, verify=False)
        
        cpu_info = str(json.loads(json.dumps(response.json()))[0]['CPUPercent']) + "%"

        return cpu_info
    
# 青藤云主机安全
class HostSecurity(DeviceInspectionable, DeviceAuthentication):
    
    def __init__(self, nodename: str, ip: str, username: str, password: str) -> None:
        self.ip = ip
        self.nodename = nodename
        self.username = username
        self.password = password
        self.dev_name = "主机安全"
        # e.g. A2000
        self.dev_type = "主机安全"
        self.need_captcha = False
        self.need_captcha_user_input = False
        
        DeviceAuthentication.__init__(self, self.dev_name, False, ip, username, password)
        
    def get_captcha(self) -> str:
        pass
        
    def get_captcha_str(self) -> str:
        try:
            ocr = ddddocr.DdddOcr(show_ad=False)
            with open('captcha.jpeg', 'rb') as f:
                image_bytes = f.read()

            res = ocr.classification(image_bytes)
            print(res)
            return res
        except Exception as e:
            print(e)
            print("ddddocr识别出错")
            exit(-3)
            
    def get_session_cookie(self):
        
        options = webdriver.ChromeOptions()

        # ignore unsafe https
        options.add_argument('ignore-certificate-errors')
        # options.add_argument('--headless')
        self.driver = webdriver.Chrome(options=options, executable_path=r'C:\Users\hushanglai\Desktop\inspection\chromedriver.exe')
        driver = self.driver
        
        # 尝试不停登录, 数据库审计比较特殊，验证码比较复杂，ddddocr可能识别很多次识别不出来
        # ? 为了防止账号被锁定，这里只尝试4次, 为什么用Selenium会有验证码，直接登录没有
        max_cnt = 4
        cnt = 1
        while True:
            
            # 尝试用find_element去找验证码的id，无论页面是有还是没有都会找到该元素，所以该方法不管用
            # 如果第一次登陆默认没有验证码，后续就会弹出验证码
            if cnt == 1:
                self.need_captcha = False
            else:
                self.need_captcha = True
            
            # if cnt > max_cnt:
            #     print("错误次数过多，稍后再来，不然要被锁定50min")
            #     break
            
            if cnt == 4:
                print("最有一次输入验证码，确保输入正确，否则将会被锁定，输入完验证码别点登录!!!")
                # 需要用户手动输入验证码
                self.need_captcha_user_input = True
                time.sleep(10)
            
            # 不睡眠会导致页面不能及时刷新，找不到相应元素
            url = f"http://{self.ip}/#/login"
            driver.get(url)
            time.sleep(3)
            
            if self.need_captcha and not self.need_captcha_user_input:
                # 下载验证码
                img_vcode = driver.find_element("id", "img_vcode")
                
                WebDriverWait(driver, 0).until(EC.visibility_of_element_located((By.CSS_SELECTOR, "#img_vcode")))
                driver.find_element_by_css_selector("#img_vcode").screenshot("captcha.jpeg")
                # 识别验证码
                captcha_str = self.get_captcha_str()
                
            time.sleep(2)
            driver.find_element("xpath", r'//*[@id="app"]/div/div/div/div/div[2]/div[1]/input').send_keys(self.username)
            time.sleep(2)
            driver.find_element("xpath", r'//*[@id="app"]/div/div/div/div/div[2]/div[2]/input').send_keys(self.password)
            login_btn = driver.find_element("xpath", r'//*[@id="app"]/div/div/div/div/div[2]/button')
            
            if self.need_captcha and not self.need_captcha_user_input:
                time.sleep(2)
                driver.find_element("id", "vldcode").send_keys(captcha_str)
                
            login_btn.click()
            cnt += 1
            
            # 找不到登录按钮表示验证码通过，退出
            try:
                time.sleep(3)
                driver.find_element("id", "login_button")
                print("验证码识别出错，正在刷新页面重新登陆")
                # driver.refresh()
            except Exception as e:
                print("登陆成功")
                break

        sessions = driver.get_cookies()
        json_sessions = json.dumps(sessions)
        
        print("Cookielit:----------------")
        all_cookies=self.driver.get_cookies();
        cookies_dict = {}
        for cookie in all_cookies:
            cookies_dict[cookie['name']] = cookie['value']
            print("cookie name: ", cookie['name'], " cookie value: ", cookie['value'])
            
            
        return cookies_dict

        
    def do_all_inspection(self) -> str:
        cookie_dict = self.get_session_cookie()
        
        # do inspection on items
        cpu_info = self.cpu_inspection(cookie_dict, 'need to delete')
        memory_info = self.memory_inspection(cookie_dict, '1')
        interface_info = self.interface_inspection(cookie_dict, '1')
        engine_info = self.engine_inspection(cookie_dict, '1')
        license_info = self.license_status_inspection(cookie_dict, '1')
        license_status = self.license_deadline_inspection(cookie_dict, '1')
        time_info = self.time_inspection(cookie_dict, '1')
        signature_info = self.signatures_inspection(cookie_dict, '1')
        disk_info = self.storage_inspection(cookie_dict, '1')
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("节点信息" )
        table.add_column("设备名称" )
        table.add_column("设备型号" )
        table.add_column("CPU信息")
        table.add_column("内存信息")
        table.add_column("存储信息")
        table.add_column("接口信息")
        table.add_column("特征库版本")
        table.add_column("授权状态")
        table.add_column("引擎状态")
        table.add_column("授权信息")
        table.add_column("时间信息")
        table.add_row(
            str(self.nodename), str(self.dev_name), str(self.dev_type), str(cpu_info), str(memory_info), str(disk_info), str(interface_info), str(signature_info), 
            str(license_status), str(engine_info), str(license_info), str(time_info)
        )
        console.print(table)
        
        print("==============================")
        print("节点信息:" + self.nodename)
        print("设备信息:" + self.dev_name)
        print("设备型号:" + self.dev_type)
        print("CPU信息:" + cpu_info)
        print("内存信息:" + memory_info)
        print("磁盘信息:" + disk_info)
        print("接口信息:\n" + interface_info)
        print("特征库版本:\n" + signature_info)
        print("授权状态:\n" + license_status)
        print("引擎状态:" + engine_info)
        print("授权信息:" + license_info)
        print("时间信息:" + time_info)
        print("==============================")

        return "正常"
   
    def interface_inspection(self, cookie_dict, session):
        return "不适用"
                
    def time_inspection(self, cookie_dict, session) -> str:
        return "不适用"
        
    def license_deadline_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'PATROL_SESSION_ID': cookie_dict['PATROL_SESSION_ID'],
        }

        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Cookie': 'PATROL_SESSION_ID=4b31df1e-acf1-48ff-9cd2-a6a6fc2edc47',
            'Referer': f'http://{self.ip}/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        }

        params = {
            '_': '1702264729409',
        }

        response = requests.get(
            f'http://{self.ip}/v1/patrol/license/multi',
            params=params,
            cookies=cookies,
            headers=headers,
            verify=False,
        )
        license_msg = "授权服务器\t授权状态\t到期时间\n"
    
        json_data = response.json()['multi']
        
        for i in json_data:
            license_msg += f"{i}\t{json_data[i]['status']}\t{json_data[i]['expiredDate']}\n"
    
        return license_msg
    
    def license_status_inspection(self, cookie_dict, session) -> str:
        return "根据授权时间判断"
    
    def engine_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'PATROL_SESSION_ID': cookie_dict['PATROL_SESSION_ID'],
        }

        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Cookie': 'PATROL_SESSION_ID=4b31df1e-acf1-48ff-9cd2-a6a6fc2edc47',
            'Referer': f'http://{self.ip}/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        }

        params = {
            '_': '1702264729409',
        }

        response = requests.get(
            f'http://{self.ip}/v1/patrol/server',
            params=params,
            cookies=cookies,
            headers=headers,
            verify=False,
        )
        engine_msg = "\n主机IP\t主机状态\tCPU占用\t内存大小(使用率)\t磁盘主分区(使用率)\t磁盘数据分区(使用率)\n"
    
        json_data = response.json()['data']
        for i in json_data:
            engine_msg += f"{i['ip']}\t{i['status']}\t{i['cpu_usage']}%\t{i['memory_usage']}%\t{i['disk_usage_root']}%\t{i['disk_usage_data']}%\n"
            
        engine_msg += "\n服务名称\t检测结果\n"
        
        response1 = requests.get(
            f'http://{self.ip}/v1/patrol/bizservice',
            params=params,
            cookies=cookies,
            headers=headers,
            verify=False,
        )
        json_data1 = response1.json()['data']
        print(json_data1)
        for i in json_data1:
            engine_msg += i['comment'] + '\t'
            engine_msg += "正常\n" if int(i['status']) == 0 else "异常\n"
        
        return engine_msg
    
    def signatures_inspection(self, cookie_dict, session) -> str:

        cookies = {
            'PATROL_SESSION_ID': cookie_dict['PATROL_SESSION_ID'],
        }

        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Cookie': 'PATROL_SESSION_ID=4864db8e-1ea3-4f66-bc0c-53047379627c',
            'Referer': f'http://{self.ip}/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        }

        params = {
            '_': '1702266663570',
        }

        response = requests.get(
            f'http://{self.ip}/v1/patrol/config/rule/updatelist',
            params=params,
            cookies=cookies,
            headers=headers,
            verify=False,
        )
        
        json_data = response.json()
        signature_msg = "特征库规则版本\t上次更新时间\n"
        rule_version = json_data['ruleVersion']
        modify_time = datetime.datetime.fromtimestamp(int(json_data['modifyTime']))
        signature_msg += f"{rule_version}\t{modify_time}\n"
        
        return signature_msg
    
    def memory_inspection(self, cookie_dict, session) -> str:
        return "不适用"
        
        
    # 磁盘巡检
    def storage_inspection(self, cookie_dict, session) -> str:
        return "不适用"
    
    def cpu_inspection(self, cookie_dict, session) -> str:
        return "不适用"
    

class VulScanInspection(DeviceInspectionable, DeviceAuthentication):
    
    def __init__(self, nodename: str, ip: str, username: str, password: str) -> None:
        self.ip = ip
        self.nodename = nodename
        self.username = username
        self.password = password
        self.dev_name = "vul scan"
        # e.g. A2000
        self.dev_type = "h3c漏扫"
        self.need_captcha = False
        self.need_captcha_user_input = False
        
        DeviceAuthentication.__init__(self, self.dev_name, False, ip, username, password)
        
    def get_captcha(self) -> str:
        pass
        
    def get_captcha_str(self) -> str:
        try:
            ocr = ddddocr.DdddOcr(show_ad=False)
            with open('captcha.jpeg', 'rb') as f:
                image_bytes = f.read()

            res = ocr.classification(image_bytes)
            print(res)
            return res
        except Exception as e:
            print(e)
            print("ddddocr识别出错")
            exit(-3)
            
    def get_session_cookie(self):
        
        options = webdriver.ChromeOptions()

        # ignore unsafe https
        options.add_argument('ignore-certificate-errors')
        # options.add_argument('--headless')
        self.driver = webdriver.Chrome(options=options, executable_path=r'C:\Users\hushanglai\Desktop\inspection\chromedriver.exe')
        driver = self.driver
        
        # 尝试不停登录, 数据库审计比较特殊，验证码比较复杂，ddddocr可能识别很多次识别不出来
        # ? 为了防止账号被锁定，这里只尝试4次, 为什么用Selenium会有验证码，直接登录没有
        max_cnt = 4
        cnt = 1
        while True:
            
            # 尝试用find_element去找验证码的id，无论页面是有还是没有都会找到该元素，所以该方法不管用
            # 如果第一次登陆默认没有验证码，后续就会弹出验证码
            if cnt == 1:
                self.need_captcha = False
            else:
                self.need_captcha = True
            
            # if cnt > max_cnt:
            #     print("错误次数过多，稍后再来，不然要被锁定50min")
            #     break
            
            if cnt == 4:
                print("最有一次输入验证码，确保输入正确，否则将会被锁定，输入完验证码别点登录!!!")
                # 需要用户手动输入验证码
                self.need_captcha_user_input = True
                time.sleep(10)
            
            # 不睡眠会导致页面不能及时刷新，找不到相应元素
            url = f"https://{self.ip}/"
            driver.get(url)
            # 漏扫需要刷新一次,第一次会失败
            driver.get(url)
            time.sleep(3)
            
            if self.need_captcha and not self.need_captcha_user_input:
                # 下载验证码
                img_vcode = driver.find_element("id", "img_vcode")
                
                WebDriverWait(driver, 0).until(EC.visibility_of_element_located((By.CSS_SELECTOR, "#img_vcode")))
                driver.find_element_by_css_selector("#img_vcode").screenshot("captcha.jpeg")
                # 识别验证码
                captcha_str = self.get_captcha_str()
                
            time.sleep(2)
            driver.find_element("xpath", '//*[@id="login_form"]/div[2]/div/input[2]').send_keys(self.username)
            time.sleep(2)
            driver.find_element("xpath", '//*[@id="login_form"]/div[3]/div/input').send_keys(self.password)
            login_btn = driver.find_element("xpath", '//*[@id="login_form"]/div[5]/div/button')
            
            if self.need_captcha and not self.need_captcha_user_input:
                time.sleep(2)
                driver.find_element("id", "vldcode").send_keys(captcha_str)
                
            login_btn.click()
            cnt += 1
            
            # 找不到登录按钮表示验证码通过，退出
            try:
                time.sleep(3)
                driver.find_element("xpath", '//*[@id="login_form"]/div[5]/div/button')
                print("验证码识别出错，正在刷新页面重新登陆")
                # driver.refresh()
            except Exception as e:
                print("登陆成功")
                break

        sessions = driver.get_cookies()
        json_sessions = json.dumps(sessions)
        
        print("Cookielit:----------------")
        all_cookies=self.driver.get_cookies();
        cookies_dict = {}
        for cookie in all_cookies:
            print(cookie)
            cookies_dict[cookie['name']] = cookie['value']
            
            
        return cookies_dict

        
    def do_all_inspection(self) -> str:
        cookie_dict = self.get_session_cookie()
        
        # do inspection on items
        cpu_info = self.cpu_inspection(cookie_dict, 'need to delete')
        memory_info = self.memory_inspection(cookie_dict, '1')
        interface_info = self.interface_inspection(cookie_dict, '1')
        engine_info = self.engine_inspection(cookie_dict, '1')
        license_info = self.license_status_inspection(cookie_dict, '1')
        license_status = self.license_deadline_inspection(cookie_dict, '1')
        time_info = self.time_inspection(cookie_dict, '1')
        signature_info = self.signatures_inspection(cookie_dict, '1')
        disk_info = self.storage_inspection(cookie_dict, '1')
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("节点信息" )
        table.add_column("设备名称" )
        table.add_column("设备型号" )
        table.add_column("CPU信息")
        table.add_column("内存信息")
        table.add_column("存储信息")
        table.add_column("接口信息")
        table.add_column("特征库版本")
        table.add_column("授权状态")
        table.add_column("引擎状态")
        table.add_column("授权信息")
        table.add_column("时间信息")
        table.add_row(
            str(self.nodename), str(self.dev_name), str(self.dev_type), str(cpu_info), str(memory_info), str(disk_info), str(interface_info), str(signature_info), 
            str(license_status), str(engine_info), str(license_info), str(time_info)
        )
        console.print(table)
        
        print("==============================")
        print("节点信息:" + self.nodename)
        print("设备信息:" + self.dev_name)
        print("设备型号:" + self.dev_type)
        print("CPU信息:" + cpu_info)
        print("内存信息:" + memory_info)
        print("磁盘信息:" + disk_info)
        print("接口信息:\n" + interface_info)
        print("特征库版本:\n" + signature_info)
        print("授权状态:\n" + license_status)
        print("引擎状态:" + engine_info)
        print("授权信息:" + license_info)
        print("时间信息:" + time_info)
        print("==============================")

        return "正常"
   
    def interface_inspection(self, cookie_dict, session):
        return "不适用"
                
    def time_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'recount': '0',
            'style_color': 'deepblue',
            'adminid': '1',
            'adminname': 'admin',
            'admintype': '0',
            'random': cookie_dict['random'],
            'SYS_TIMEOUT': '30',
            'threshold': '80',
            'hwtype': 'box',
            'tb': '',
            'p_len': '8',
            'p_level': '2',
            'em': 'em',
            'bsc': 'new',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'recount=0; style_color=deepblue; adminid=1; adminname=admin; admintype=0; random=tuy9wdfgd7cpk84rembv5qabex3j2ca6; SYS_TIMEOUT=30; threshold=80; hwtype=box; tb=; p_len=8; p_level=2; em=em; bsc=new',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/main/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/system/date/query/', cookies=cookies, headers=headers, verify=False)        
        json_data = response.json()
        
        return json_data['aData']['date'] + '\t' + json_data['aData']['time']
    
    def license_deadline_inspection(self, cookie_dict, session) -> str:
        return "不适用"

    
    def license_status_inspection(self, cookie_dict, session) -> str:
        return "根据授权时间判断"
    
    def engine_inspection(self, cookie_dict, session) -> str:
        return "不适用"
    
    def signatures_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'recount': '0',
            'style_color': 'deepblue',
            'adminid': '1',
            'adminname': 'admin',
            'admintype': '0',
            'random': cookie_dict['random'],
            'SYS_TIMEOUT': '30',
            'threshold': '80',
            'hwtype': 'box',
            'tb': '',
            'p_len': '8',
            'p_level': '2',
            'em': 'em',
            'bsc': 'new',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'recount=0; style_color=deepblue; adminid=1; adminname=admin; admintype=0; random=tuy9wdfgd7cpk84rembv5qabex3j2ca6; SYS_TIMEOUT=30; threshold=80; hwtype=box; tb=; p_len=8; p_level=2; em=em; bsc=new',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/main/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/system/upsys/query/', cookies=cookies, headers=headers, verify=False)        
        signature_msg = ""
        # 奇怪的字段
        json_data = response.json()['aaData']
        
        for i in json_data:
            for j in i:
                signature_msg += j + '\t'
            signature_msg += '\n'
            
        print(signature_msg)
                        
        return signature_msg
    
    def memory_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'recount': '0',
            'style_color': 'deepblue',
            'adminid': '1',
            'adminname': 'admin',
            'admintype': '0',
            'random': cookie_dict['random'],
            'SYS_TIMEOUT': '30',
            'threshold': '80',
            'hwtype': 'box',
            'tb': '',
            'p_len': '8',
            'p_level': '2',
            'em': 'em',
            'bsc': 'new',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'recount=0; style_color=deepblue; adminid=1; adminname=admin; admintype=0; random=tuy9wdfgd7cpk84rembv5qabex3j2ca6; SYS_TIMEOUT=30; threshold=80; hwtype=box; tb=; p_len=8; p_level=2; em=em; bsc=new',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/main/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/system/sysinfo/', cookies=cookies, headers=headers, verify=False)        
        json_data = response.json()
        
        return json_data['mem']
        
    # 磁盘巡检
    def storage_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'recount': '0',
            'style_color': 'deepblue',
            'adminid': '1',
            'adminname': 'admin',
            'admintype': '0',
            'random': cookie_dict['random'],
            'SYS_TIMEOUT': '30',
            'threshold': '80',
            'hwtype': 'box',
            'tb': '',
            'p_len': '8',
            'p_level': '2',
            'em': 'em',
            'bsc': 'new',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'recount=0; style_color=deepblue; adminid=1; adminname=admin; admintype=0; random=tuy9wdfgd7cpk84rembv5qabex3j2ca6; SYS_TIMEOUT=30; threshold=80; hwtype=box; tb=; p_len=8; p_level=2; em=em; bsc=new',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/main/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/system/sysinfo/', cookies=cookies, headers=headers, verify=False)        
        json_data = response.json()
        
        return json_data['mem']
    
    def cpu_inspection(self, cookie_dict, session) -> str:
        
        cookies = {
            'recount': '0',
            'style_color': 'deepblue',
            'adminid': '1',
            'adminname': 'admin',
            'admintype': '0',
            'random': cookie_dict['random'],
            'SYS_TIMEOUT': '30',
            'threshold': '80',
            'hwtype': 'box',
            'tb': '',
            'p_len': '8',
            'p_level': '2',
            'em': 'em',
            'bsc': 'new',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'recount=0; style_color=deepblue; adminid=1; adminname=admin; admintype=0; random=tuy9wdfgd7cpk84rembv5qabex3j2ca6; SYS_TIMEOUT=30; threshold=80; hwtype=box; tb=; p_len=8; p_level=2; em=em; bsc=new',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/main/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/system/sysinfo/', cookies=cookies, headers=headers, verify=False)        
        json_data = response.json()
        
        return json_data['cpu']
        
class WAFInspection(DeviceInspectionable, DeviceAuthentication):
    
    def __init__(self, nodename:str, ip: str, username: str, password: str) -> None:
        self.ip = ip
        self.nodename = nodename
        self.username = username
        self.password = password
        self.dev_name = "waf"
        # e.g. D2000
        self.dev_type = "waf"
        
        DeviceAuthentication.__init__(self, self.dev_name, False, ip, username, password)
        
    def get_captcha_str(self) -> str:
        try:
            ocr = ddddocr.DdddOcr(show_ad=False)
            with open('captcha.jpeg', 'rb') as f:
                image_bytes = f.read()

            res = ocr.classification(image_bytes)
            return res
        except Exception as e:
            print(e)
            print("ddddocr识别出错")
            exit(-3)

    def get_session_cookie(self):
        
        options = webdriver.ChromeOptions()
        
        self.need_captcha_user_input = False

        # ignore unsafe https
        options.add_argument('ignore-certificate-errors')
        # options.add_argument('--headless')
        self.driver = webdriver.Chrome(options=options, executable_path=r'C:\Users\hushanglai\Desktop\inspection\chromedriver.exe')
        driver = self.driver
        
        # 尝试不停登录, 数据库审计比较特殊，验证码比较复杂，ddddocr可能识别很多次识别不出来
        # ? 为了防止账号被锁定，这里只尝试4次, 为什么用Selenium会有验证码，直接登录没有（反爬虫）
        max_cnt = 4
        cnt = 1
        while True:
            
            if cnt > max_cnt:
                print("错误次数过多，稍后再来，不然要被锁定50min")
                break
            
            # 不睡眠会导致页面不能及时刷新，找不到相应元素
            time.sleep(3)
            url = "https://{}/login/".format(self.ip)
            driver.get(url)
            
            # check if captcha
            try:
                time.sleep(3)
                ele = driver.find_element_by_xpath('//*[@id="code"]')
                if ele.is_displayed():
                    print("找到验证码")
                    self.need_captcha = True
                else:
                    print("未找到验证码")
                    self.need_captcha = False
            except Exception as e:
                print("未找到验证码")
                self.need_captcha = False
                
            
            if self.need_captcha and not self.need_captcha_user_input:
                # 下载验证码, find_element方法有问题，找到的图片weith为0
                img_base64 = driver.execute_script("""
                                                   var ele = arguments[0];
                                                   var cnv = document.createElement('canvas');
                                                   cnv.width = ele.width; 
                                                   cnv.height = ele.height; 
                                                   cnv.getContext('2d').drawImage(ele, 0, 0); 
                                                   return cnv.toDataURL('image/jpeg').substring(22);  
                                                   """, driver.find_element_by_xpath('//*[@id="code"]'))
            
                with open(r"captcha.jpeg", 'wb') as f:
                    f.write(base64.b64decode(img_base64))

                    #driver.find_element("id", "vcode").screenshot("captcha.jpeg")
                    #element = driver.find_element(By.XPATH, '//*[@id="vcode"]')
                    #print(type(element))
                    #element.screenshot("captcha.jpeg")
                    #print("size:", element.size['width'], element.size['height'])

                # 识别验证码
                captcha_str = self.get_captcha_str()
                
            time.sleep(2)
            driver.find_element("xpath", '//*[@id="username_text"]').send_keys(self.username)
            time.sleep(2)
            driver.find_element("xpath", '//*[@id="password_text"]').send_keys(self.password)
            login_btn = driver.find_element("xpath", '//*[@id="login_btn"]')
            
            if cnt == 4:
                self.need_captcha_user_input = True
                print("需要用户在10秒内输入验证码，确保验证码正确，否则账户将会被会锁定!!!")
                time.sleep(10)
                
            if self.need_captcha and not self.need_captcha_user_input:
                time.sleep(2)
                driver.find_element("xpath", '//*[@id="J_codetext"]').send_keys(captcha_str)
                
            login_btn.click()
            cnt += 1
            
            # 找不到登录按钮表示验证码通过，退出
            try:
                time.sleep(3)
                driver.find_element("xpath", '//*[@id="login_btn"]')
                print("验证码识别出错，正在刷新页面重新登陆")
                # driver.refresh()
            except Exception as e:
                print("登陆成功")
                break

        all_cookies=self.driver.get_cookies();
        # waf比较特殊，需要csrf_token
        session_storage = driver.execute_script("return window.sessionStorage;")
        cookies_dict = {}
        for cookie in all_cookies:
            cookies_dict[cookie['name']] = cookie['value']
            
        cookies_dict['csrf_token'] = session_storage['csrf_token']
            
        return cookies_dict
        
    def do_all_inspection(self) -> str:
        cookie = self.get_session_cookie()
        # do inspection on items
        cpu_info = self.cpu_inspection(cookie, 1)
        memory_info = self.memory_inspection(cookie, 1)
        interface_info = self.interface_inspection(cookie, 1)
        signatures_info = self.signatures_inspection(cookie, 1)
        engine_info = self.engine_inspection(cookie, 1)
        license_info = self.license_deadline_inspection(cookie, 1)
        license_status = self.license_status_inspection(cookie, 1)
        time_info = self.time_inspection(cookie, 1)
        storage_info = self.storage_inspection(cookie, 1)
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("节点信息", style="dim")
        table.add_column("设备名称", style="dim")
        table.add_column("设备型号", style="dim")
        table.add_column("CPU信息", style="dim")
        table.add_column("内存信息")
        table.add_column("接口信息")
        table.add_column("特征库版本")
        table.add_column("授权状态")
        table.add_column("引擎状态")
        table.add_column("授权信息")
        table.add_column("时间信息")
        table.add_column("磁盘信息")
        table.add_row(
            str(self.nodename), str(self.dev_name), str(self.dev_type), str(cpu_info), str(memory_info), str(interface_info), str(signatures_info), 
            str(license_status), str(engine_info), str(license_info), str(time_info), str(storage_info)
        )
        console.print(table)
        
        print("==============================")
        print("节点信息:" + self.nodename)
        print("设备信息:" + self.dev_name)
        print("设备型号:" + self.dev_type)
        print("CPU信息:" + cpu_info)
        
        # 应该同时检测CPU占用不超过80%
        if "异常" not in cpu_info:
            console.print("CPU信息:" + cpu_info, style="green")
        else:
            console.print("CPU信息:" + cpu_info, style="red")
            
            
        print("内存信息:" + memory_info)
        print("磁盘信息:" + storage_info)
        print("接口信息:\n" + interface_info)
        print("特征库版本:\n" + signatures_info)
        print("授权状态:\n" + license_status)
        print("引擎状态:" + engine_info)
        print("授权信息:" + license_info)
        print("时间信息:" + time_info)
        print("==============================")

    def interface_inspection(self, cookie, session):
        
        cookies = {
            'session': cookie['session'],
            'pwd_len': '10',
            'pwd_comp': '1',
            'webseclogin_random': cookie['webseclogin_random'],
            'webseclogin_adminid': '1',
            'webray_lang': 'zh_CN',
            'SYS_TIMEOUT': '10',
            'webseclogin_adminname': 'admin',
            'product_type': 'waf',
            'pattern_tips': '1',
            'check_due': '1702310400',
            'style_color': 'deepblue',
            'product_category': 'WAF',
        }

        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Cookie': 'session=a63edb79-1721-4543-bd5e-ae6c9cd3cd20.jytIxyzqdfudKLo1aYgATONIhJs; pwd_len=10; pwd_comp=1; webseclogin_random=u615h773hkc570djlyn2j1ssmyq9giia; webseclogin_adminid=1; webray_lang=zh_CN; SYS_TIMEOUT=10; webseclogin_adminname=admin; product_type=waf; pattern_tips=1; check_due=1702310400; style_color=deepblue; product_category=WAF',
            'Referer': f'https://{self.ip}/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        params = {
            'sEcho': '1',
            'iColumns': '6',
            'sColumns': '',
            'iDisplayStart': '0',
            'iDisplayLength': '10',
            'mDataProp_0': '0',
            'mDataProp_1': '1',
            'mDataProp_2': '2',
            'mDataProp_3': '3',
            'mDataProp_4': '4',
            'mDataProp_5': '5',
            'sSearch': '',
            'bRegex': 'false',
            'sSearch_0': '',
            'bRegex_0': 'false',
            'bSearchable_0': 'true',
            'sSearch_1': '',
            'bRegex_1': 'false',
            'bSearchable_1': 'true',
            'sSearch_2': '',
            'bRegex_2': 'false',
            'bSearchable_2': 'true',
            'sSearch_3': '',
            'bRegex_3': 'false',
            'bSearchable_3': 'true',
            'sSearch_4': '',
            'bRegex_4': 'false',
            'bSearchable_4': 'true',
            'sSearch_5': '',
            'bRegex_5': 'false',
            'bSearchable_5': 'true',
            'iSortCol_0': '0',
            'sSortDir_0': 'asc',
            'iSortingCols': '1',
            'bSortable_0': 'false',
            'bSortable_1': 'false',
            'bSortable_2': 'false',
            'bSortable_3': 'false',
            'bSortable_4': 'false',
            'bSortable_5': 'false',
            '_': '1702286898321',
        }

        response = requests.get(
            f'https://{self.ip}/dashboard/interface/query/',
            params=params,
            cookies=cookies,
            headers=headers,
            verify=False,
        )
        
        json_data = response.json()['aaData']
        interface_msg = "网卡名称\t网卡状态\n"
        for interface in json_data:
            name = interface[0]
            status = int(interface[1])
            interface_msg += name + "\t" + ("正常\n" if status == 1 else "异常\n")
        
        return interface_msg
                
    def time_inspection(self, cookie, session) -> str:
        
        cookies = {
            'session': cookie['session'],
            'pwd_len': '10',
            'pwd_comp': '1',
            'webseclogin_random': cookie['webseclogin_random'],
            'webseclogin_adminid': '1',
            'webray_lang': 'zh_CN',
            'SYS_TIMEOUT': '10',
            'webseclogin_adminname': 'admin',
            'product_type': 'waf',
            'pattern_tips': '1',
            'check_due': '1702310400',
            'style_color': 'deepblue',
            'product_category': 'WAF',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'session=1b8e67f1-b15a-4f3e-8614-f408e2675715.-VEcs2xbZ1m0eo7uWl2RXDEKGRA; pwd_len=10; pwd_comp=1; webseclogin_random=rdovug9ynjtdb89vlva9d8s6z2j7x3uu; webseclogin_adminid=1; webray_lang=zh_CN; SYS_TIMEOUT=10; webseclogin_adminname=admin; product_type=waf; pattern_tips=1; check_due=1702310400; style_color=deepblue; product_category=WAF',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-CSRFToken': cookie['csrf_token'],
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/dashboard/sysinfo/query/', cookies=cookies, headers=headers, verify=False)
        json_data = response.json()
        
        # donnot touch it
        return json_data['aaData'][10][1]
    
    def license_deadline_inspection(self, cookie, session) -> str:
        # JS逻辑        
        #        // license limit time 
        # function license_limit_tips (){
        # 	$.post("/system/license/limittime/",function(json) {	
        # 	var limit_time = parseInt(json['limittime'][1].toString().split("days_left_pre")[1].split("days_left_post")[0].replace('[','').replace(']',''))	
        # 	var pattern_auto_update_limit_time = parseInt(json['limittime'][0].toString().split("days_left_pre")[1].split("days_left_post")[0].replace('[','').replace(']',''))	
        # 		if(typeof(limit_time) == 'number'&&limit_time <= 30){
        # 			infotips(r_lang_get('Your validity period of license is left')
        # +'<b style="color:#F88E88">'+limit_time+'</b>'+
        # r_lang_get('days')+','+
        # r_lang_get('so in order to ensure system normal supply and apply,
        # please upgrade the license as soon as possible'))
        # 			  }	
        #    //   if(typeof(pattern_auto_update_limit_time) == 'number'&&pattern_auto_update_limit_time <= 30){
        #    //     infotips(r_lang_get('Your validity period of pattern is left')+'<b style="color:#F88E88">'+pattern_auto_update_limit_time+'</b>'+r_lang_get('days')+','+r_lang_get('so in order to ensure system normal supply and apply,please upgrade the license as soon as possible'))
        #    //   } 
        # 		});
        # 	}
        
        cookies = {
            'session': cookie['session'],
            'pwd_len': '10',
            'pwd_comp': '1',
            'webseclogin_adminid': '1',
            'webray_lang': 'zh_CN',
            'SYS_TIMEOUT': '10',
            'webseclogin_adminname': 'admin',
            'product_type': 'waf',
            'pattern_tips': '1',
            'style_color': 'deepblue',
            'product_category': 'WAF',
            'webseclogin_random': cookie['webseclogin_random'],
            'check_due': '0',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'session=066dc0b4-7bfa-42e9-8e01-8efd261596cf.3RC2UVFspmm0PY4h0y5FfHh1NDc; pwd_len=10; pwd_comp=1; webseclogin_adminid=1; webray_lang=zh_CN; SYS_TIMEOUT=10; webseclogin_adminname=admin; product_type=waf; pattern_tips=1; style_color=deepblue; product_category=WAF; webseclogin_random=nast3xxcosrgjbg8d4ogexrox9az9h8e; check_due=0',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-CSRFToken': cookie['csrf_token'],
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/system/license/limittime/', cookies=cookies, headers=headers, verify=False)
        json_data = response.json()
        
        license_msg = f"许可有效期(天):{json_data['limittime'][1]}\n"
        license_msg += f"特征库升级剩余时间(天):{json_data['limittime'][0]}\n"
        
        return license_msg
    
    def license_status_inspection(self, cookie, session) -> str:

        return "根据授权按时间判断"
    
    def engine_inspection(self, cookie, session) -> str:
        return "未知，不知道那里检查"
    
    def signatures_inspection(self, cookie, session) -> str:
        
        cookies = {
            'session': cookie['session'],
            'pwd_len': '10',
            'pwd_comp': '1',
            'webseclogin_random': cookie['webseclogin_random'],
            'webseclogin_adminid': '1',
            'webray_lang': 'zh_CN',
            'SYS_TIMEOUT': '10',
            'webseclogin_adminname': 'admin',
            'product_type': 'waf',
            'pattern_tips': '1',
            'check_due': '1702310400',
            'style_color': 'deepblue',
            'product_category': 'WAF',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'session=c1f11fb2-019c-46f6-9e89-2731b152dc51.e-MYcysR_oHtRZd9OZs2Sn-SHjo; pwd_len=10; pwd_comp=1; webseclogin_random=7qdf8j6amjxx65um7eips70zn9tptlts; webseclogin_adminid=1; webray_lang=zh_CN; SYS_TIMEOUT=10; webseclogin_adminname=admin; product_type=waf; pattern_tips=1; check_due=1702310400; style_color=deepblue; product_category=WAF',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-CSRFToken': cookie['csrf_token'],
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/dashboard/sysinfo/query/', cookies=cookies, headers=headers, verify=False)
        json_data = response.json()['aaData']
        
        # fixed donnot touch it
        return json_data[8][1]
    
    def memory_inspection(self, cookie, session):
        
        cookies = {
            'session': cookie['session'],
            'pwd_len': '10',
            'pwd_comp': '1',
            'webseclogin_random': cookie['webseclogin_random'],
            'webseclogin_adminid': '1',
            'webray_lang': 'zh_CN',
            'SYS_TIMEOUT': '10',
            'webseclogin_adminname': 'admin',
            'product_type': 'waf',
            'pattern_tips': '1',
            'check_due': '1702310400',
            'style_color': 'deepblue',
            'product_category': 'WAF',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'session=1b8e67f1-b15a-4f3e-8614-f408e2675715.-VEcs2xbZ1m0eo7uWl2RXDEKGRA; pwd_len=10; pwd_comp=1; webseclogin_random=rdovug9ynjtdb89vlva9d8s6z2j7x3uu; webseclogin_adminid=1; webray_lang=zh_CN; SYS_TIMEOUT=10; webseclogin_adminname=admin; product_type=waf; pattern_tips=1; check_due=1702310400; style_color=deepblue; product_category=WAF',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-CSRFToken': cookie['csrf_token'],
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/dashboard/info/query/', cookies=cookies, headers=headers, verify=False)
        json_data = response.json()
        
        # fixed don't touch
        return json_data['aaData'][1]
    
    # 不是巡检项
    def storage_inspection(self, cookie, session) -> str:
        
        cookies = {
            'session': cookie['session'],
            'pwd_len': '10',
            'pwd_comp': '1',
            'webseclogin_random': cookie['webseclogin_random'],
            'webseclogin_adminid': '1',
            'webray_lang': 'zh_CN',
            'SYS_TIMEOUT': '10',
            'webseclogin_adminname': 'admin',
            'product_type': 'waf',
            'pattern_tips': '1',
            'check_due': '1702310400',
            'style_color': 'deepblue',
            'product_category': 'WAF',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'session=1b8e67f1-b15a-4f3e-8614-f408e2675715.-VEcs2xbZ1m0eo7uWl2RXDEKGRA; pwd_len=10; pwd_comp=1; webseclogin_random=rdovug9ynjtdb89vlva9d8s6z2j7x3uu; webseclogin_adminid=1; webray_lang=zh_CN; SYS_TIMEOUT=10; webseclogin_adminname=admin; product_type=waf; pattern_tips=1; check_due=1702310400; style_color=deepblue; product_category=WAF',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-CSRFToken': cookie['csrf_token'],
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/dashboard/info/query/', cookies=cookies, headers=headers, verify=False)
        json_data = response.json()
        
        return json_data['aaData'][2]
    
    def cpu_inspection(self, cookie, session):
        
        cookies = {
            'session': cookie['session'],
            'pwd_len': '10',
            'pwd_comp': '1',
            'webseclogin_random': cookie['webseclogin_random'],
            'webseclogin_adminid': '1',
            'webray_lang': 'zh_CN',
            'SYS_TIMEOUT': '10',
            'webseclogin_adminname': 'admin',
            'product_type': 'waf',
            'pattern_tips': '1',
            'check_due': '1702310400',
            'style_color': 'deepblue',
            'product_category': 'WAF',
        }

        headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            # 'Content-Length': '0',
            # 'Cookie': 'session=1b8e67f1-b15a-4f3e-8614-f408e2675715.-VEcs2xbZ1m0eo7uWl2RXDEKGRA; pwd_len=10; pwd_comp=1; webseclogin_random=rdovug9ynjtdb89vlva9d8s6z2j7x3uu; webseclogin_adminid=1; webray_lang=zh_CN; SYS_TIMEOUT=10; webseclogin_adminname=admin; product_type=waf; pattern_tips=1; check_due=1702310400; style_color=deepblue; product_category=WAF',
            'Origin': f'https://{self.ip}',
            'Referer': f'https://{self.ip}/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'X-CSRFToken': cookie['csrf_token'],
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = requests.post(f'https://{self.ip}/dashboard/info/query/', cookies=cookies, headers=headers, verify=False)
        json_data = response.json()
        
        return json_data['aaData'][0]
    
if __name__ == "__main__":
    bastion_inspection = BastionhostInspection("XXX", "1.1.1.1", "username", "password")
    logaudit_inspection = LogAuditInspection("XXX", "your ip", "username", "password")
    database_audit = DatabaseAuditInspection("XXX", "your ip", "username", "pass")
    nta_inspection = NTAInspection("where", "your ip", "username", "pass")
    a_inspection = AInspection("where", "your ip", "username", "pass")
    ips_inspection = IPSAuditInspection("where", "your ip", "username", "passwd")
    ips_inspection = NTAInspection("where", "your ip", "user", "pass")
    situaltion_awareness_inspection = SitualtionAwareness("where", "2.2.2.2", "user", "pass")
    hostsecurity_inspection = HostSecurity("where", "your ip", "username", "pass")
    vulscan_inspection = VulScanInspection("where", "ip", "user", "pass")
    waf_inspection = WAFInspection("where", "ip", "user", "passwd")
    
    inspection_obj_list = []
    inspection_obj_list.append(bastion_inspection)
    inspection_obj_list.append(logaudit_inspection)
    inspection_obj_list.append(database_audit)
    inspection_obj_list.append(nta_inspection)
    inspection_obj_list.append(a_inspection)
    inspection_obj_list.append(ips_inspection)
    inspection_obj_list.append(situaltion_awareness_inspection)
    inspection_obj_list.append(hostsecurity_inspection)
    inspection_obj_list.append(vulscan_inspection)
    inspection_obj_list.append(waf_inspection)
    
    # Create multiple threads
    threads = []
    for i in inspection_obj_list:
        if i is None:
            continue
        
        t = threading.Thread(target=i.do_all_inspection)
        threads.append(t)
        t.start()

