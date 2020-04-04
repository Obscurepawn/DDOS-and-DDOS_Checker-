from scapy.all import *
import math
import dos

packetsNum = 5000
#Qualcomm Atheros QCA61x4A Wireless Network Adapter 为被攻击主机的使用的网卡名称，
#请自行更换成自己的网卡名称，更换方法详见“补充说明.docx”
dpkt = sniff(
    iface="Qualcomm Atheros QCA61x4A Wireless Network Adapter", count=packetsNum)
srcList = []
destList = []
dportList = []

#ddos攻击情况下的4维信息熵
ddosMeasure = [3.7042427792511807, 3.101864313987882, 0.6873200389350417, 24.31558837425727]
#正常情况下的4维信息熵
normalMeasure = [0.8384563842561118, 0.0, 1.3653685644648292, 3.616327702776094]
#以上数据为我对自身电脑在遭受ddos攻击和正常上网的情况下收集的多次4维信息熵的平均向量
#建议使用者在自身电脑上重新测试设置该常数向量，具体方法可见 补充说明.docx

#测试用的函数，显示收集的数据
def showList():
    global srcList, destList, dportList
    for i in range(len(srcList)):
        print(srcList[i], destList[i], dportList[i])

#将收集的数据按照必要的方式组合成元组，方便使用
def makeTuple() -> (tuple, tuple, tuple):
    global srcList, destList, dportList
    sipDip = tuple([(srcList[i], destList[i]) for i in range(len(srcList))])
    sipDport = tuple([(srcList[i], dportList[i]) for i in range(len(srcList))])
    dportDip = tuple([(dportList[i], destList[i])
                      for i in range(len(dportList))])
    return sipDip, sipDport, dportDip

#将收集的数据做成集合，即去除重复的元素，计算条件熵和样本差异熵的时候需要用到
def makeSet() -> (list, list, list):
    global srcList, destList, dportList
    srcSet = []
    destSet = []
    dportSet = []
    for i in srcList:
        if i not in srcSet:
            srcSet.append(i)
    for i in destList:
        if i not in destSet:
            destSet.append(i)
    for i in dportList:
        if i not in dportSet:
            dportSet.append(i)
    return srcSet, destSet, dportSet

#数据的收集
#由于此处使用的DDOS攻击是DNS放大反射攻击和SYN-FLOOD攻击，故此处采集数据为了采集速度，则只采集TCP和DNS协议的数据包
def makeList(dpkt: scapy.all.PacketList):
    global srcList, destList, dportList
    src = ""
    dst = ""
    dport = 0
    for p in dpkt:
        isIpExist = False
        isProtoExist = False
        if 'IP' in p: #判断这个数据包是否含有IP层
            isIpExist = True
            src = p[IP].src
            dst = p[IP].dst
        if 'TCP' in p: #判断数据包是否含有TCP层
            isProtoExist = True
            dport = p[TCP].dport
        elif 'DNS' in p: #判断数据包是否含有DNS层
            isProtoExist = True
            if 'UDP' in p: #判断数据包是否含有UDP层
                dport = p[UDP].dport
        if isIpExist and isProtoExist: #若此处为TCP协议和DNS协议，则将源Ip，目的Ip，目的端口存储起来
            srcList.append(src)
            destList.append(dst)
            dportList.append(dport)

#计算概率和条件概率，原理详见参考论文(pdf文件)
def getNum(data1, data2, data: tuple) -> (float, float):
    condNum = 0
    data2Num = 0
    for i in data:
        if i[1] == data2:
            data2Num += 1
            if i[0] == data1:
                condNum += 1
    #print(data2Num,condNum)
    if data2Num != 0:
        return condNum/len(data), condNum/data2Num
    else:
        return 0, 0

#计算ip熵，原理详见参考论文(pdf文件)
def calCondEntropy(Set_1: list, Set_2: list, data: tuple):
    ret = 0
    for i in Set_1:
        for j in Set_2:
            p1, p2 = getNum(i, j, data)
            if p2 != 0:
                ret += p1*math.log(p2)
    return -ret

#计算样本差异熵，原理详见参考论文(pdf文件)
def calDifferenceEntropy(srcSet: list) -> float:
    global srcList
    n = int(len(srcList)/2)
    retDict = {'all': 0}
    #print(srcList)
    for i in srcList[n+1:]:
        if i not in srcList[:n+1]:
            retDict[i] = 1 if i not in retDict.keys() else retDict[i]+1
            retDict['all'] += 1
    #print(retDict)
    retValue = 0
    for i in srcSet:
        if i in retDict.keys():
            retValue += retDict[i]/retDict['all'] * \
                math.log(retDict[i]/retDict['all'])
    return -retValue

#主要函数，计算多维信息熵
def main()->list:
    makeList(dpkt)
    sipDip, sipDport, dportDip = makeTuple()
    srcSet, destSet, dportSet = makeSet()
    entropyList = [calCondEntropy(srcSet, destSet, sipDip), calCondEntropy(
        srcSet, dportSet, sipDport), calCondEntropy(dportSet, destSet, dportDip), calDifferenceEntropy(srcList)]
    return entropyList

#计算当前的多围信息熵更接近于正常状态的多维信息熵还是ddos攻击时的状态的多维信息熵
def calDistance(measureData:list)->(float,float):
    global normalMeasure,ddosMeasure
    normalDistance = 0
    ddosDistance = 0
    for i in range(len(measureData)):
        normalDistance += (measureData[i]-normalMeasure[i])**2
        ddosDistance += (measureData[i]-ddosMeasure[i])**2
    return normalDistance,ddosDistance


if __name__ == "__main__":
    measureData = main()
    normalDistance,ddosDistance = calDistance(measureData)
    #输出相关信息
    message = "NO DDOS ATTACK" if normalDistance<ddosDistance else "ENCOUNTED DDOS ATTACK"
    print("mearsure data: ",measureData)
    print("normalDistance: ",normalDistance)
    print("ddosDistance: ",ddosDistance)
    print(message)
    
