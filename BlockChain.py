import hashlib  #实现SHA256需要用到的库
import ecdsa     #实现密钥
import time
from random import choice
import string
import random
import subprocess

# 食品信息存储
chains = dict()

# 随机字符串生成
def randomGenerate():
    value = ''.join(random.sample(string.ascii_letters + string.digits, 8))
    return value

# 用户类
class user:
    def __init__(self):
        self.list = str(string.ascii_lowercase)
        self.pa = str(self.password())
        #生成密钥对
        self.privateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.publicKey = self.privateKey.get_verifying_key()
    def password(self):
        result = ''
        for i in range(8):
            ch = choice(self.list)
            result += ch
        return result

    def checkTheFile(self, username):
        with open('user.txt') as file_object:
            lines = file_object.readlines()
        for line in lines:
            usr = ''
            for w in line:
                if w != '\t':
                    usr += w
                else:
                    break
            if username == usr:
                return True
        return False

    #用户注册
    def register(self):
        while True:  # 循环为了防止输出已有用户名
            user_name = input('请输入要创建的用户名:')
            if len(user_name) > 8:
                print("用户名长度不超过8！")
                continue
            if self.checkTheFile(user_name):
                print("用户名已存在！请重新输入")
                continue
            else:
                self.name = user_name
                self.wfile(user_name, self.pa, 'user.txt')
                break
        print('你的账号如下，请牢记账号密码！\n'+'账号：'+user_name+'\t密码：'+self.pa)

    def wfile(self, username, password, fname):  # 用户名密码写入文件
        with open(fname, 'a') as f:  # 打开文件,赋予追加权限
            data = username + '\t' + password + '\n'
            f.write(data)

    # 用户登录        
    def login(self):  
        user_name = input("请输入用户名：")
        self.name = user_name
        with open('user.txt') as file_object:
            lines = file_object.readlines()
        for line in lines:
            usr = ''
            pa = ''
            t=1
            for w in line:
                if w =='\t':
                    t=2
                if t == 1:
                    usr += w
                if t == 2:
                    pa += w
            if user_name == usr:
                password = input("请输入密码：")
                if password == pa.strip():
                    return True
                else:
                    print("密码错误!")
                    return False
        print("找不到用户名！")
        return False

# sha256函数
def sha256(value):
    #对输入的数据进行解码
    #返回计算后得出的16进制摘要
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


#食品事件类
class eventInfo:
    def __init__(self , director, uploader , location, descrption, info=''):
        self.director = director
        self.uploadr = uploader
        self.description = descrption
        self.location = location
        self.info = info
        self.time = time.localtime()
    
    # 返回食品加工信息的哈希值
    def getHash(self):
        return str(sha256(str(self.director) + str(self.description) + str(self.location)+str(self.time)+str(self.info))).encode()

    #用上传人的私钥进行数字签名
    def sign(self):
        self.signature = self.uploader.privateKey.sign(self.getHash())

    #验证数字签名
    def isValid(self , key):
        try:
            key.verify(self.signature, self.getHash())
        except ecdsa.keys.BadSignatureError:
            return False
        return True


#区块类
class Block:
    #构造函数
    def __init__(self, event, prehash=''):
        #区块中存储的数据->食品信息对象
        self.event = event
        # 时间戳
        self.timestamp = time.time()
        #用于得到符合PoW难度的哈希值的随机数
        self.nonce = 0 
        #上一个区块的哈希值，用于将区块连接起来
        self.prehash = prehash
        #计算本区块的哈希值
        self.hash = self.getHash()

    #计算本区块哈希值
    def getHash(self):
        #需要计算的值包括存储的数据、前一区块的哈希值、随机数
        return sha256(str(self.event) + self.prehash + str(self.nonce)) + str(self.timestamp)

    #挖矿函数：修改随机数直至满足区块链难度
    def mine(self , difficulty):
        #获取哈希值需要满足的条件，即长度为defficulty的全0字符串
        condition = '0' * difficulty
        self.hash = self.getHash()
        while(1):
            if(self.hash[0 : difficulty] != condition):
                self.nonce += 1
                self.hash = self.getHash()
            else:
                break

    # 显示当前食品加工区块的信息
    def getTheBlock(self):
        print("●"+str(self.event.time.tm_year)+"年"+str(self.event.time.tm_mon)+"月"+str(self.event.time.tm_mday)+"日"+str(self.event.time.tm_hour)+"时"
        +str(self.event.time.tm_min)+"分"+str(self.event.time.tm_sec)+"秒\n"+"\t"+"事件："+self.event.description+"  "
        +"厂商："+self.event.location+"  "+"负责人："+self.event.director+"  "+"信息上传人："+self.event.uploader.name+"  "+"相关信息："+self.event.info+"\n")

    #验证食品信息的数字签名
    def validateInfo(self):
        if not self.event.isValid(self.event.uploader.publicKey):
            print("食品信息异常！")
            return False
        return True


#区块链类
class Chain:
    #构造函数
    def __init__(self, foodName, ID, event):
        #该区块链的锁
        self.lock = False
        #该区块链存储的食品
        self.foodName = foodName
        self.ID = ID
        #设置PoW的难度，哈希值符合前difficulty位为0的 区块才可以被加入
        self.difficulty = 3
        #存储区块的数组,初始只含有祖先区块
        self.blocks = [self.createGenesis(event)]
        
    #生成祖先区块
    def createGenesis(self , event):
        genesisBlock = Block(event)
        return genesisBlock

    #添加新区块
    def addNewBlock(self , block):
        if self.lock:
            print("该区块链已经被锁定！无法添加信息。")
        #判断区块的数字签名
        if not block.validateInfo():
            print("信息上传失败！")
            return False
        #获取区块数组中最后一个元素，即最新的区块
        latestblock = self.blocks[-1]  
        #连接区块
        block.prehash = latestblock.hash
        #对之前的区块链进行合法性验证
        self.verify()
        #挖矿
        block.mine(self.difficulty)  
        #新区块加入区块链
        self.blocks.append(block) 

    # 显示所有食品加工区块的信息
    def getTheChain(self):
        for i in range(0, len(self.blocks)) :
            self.blocks[i].getTheBlock()
        if self.lock:
            print("●区块链已锁定, 无法继续添加区块")
        else:
            print("●区块链未锁定, 可以继续添加区块.......")

    #验证当前区块链是否合法
    #数据是否被篡改？ 区块之间的链接是否断开？
    def verify(self):
        #当区块链中只包含祖先区块时
        #仅判断是否篡改数据，不存在断链情况
        if len(self.blocks) == 1:
            if self.blocks[0].hash != self.blocks[0].getHash():
                print("祖先区块数据被篡改！")
                return False
            return True
        for i in range(1 , len(self.blocks)-1) :
            block=self.blocks[i]
            pre=self.blocks[i-1]

            #若区块的哈希值与重新计算的不同，证明数据已被篡改
            if block.hash != block.getHash():
                print("数据被篡改！")
                return False
                
            #当前区块的前一块哈希值与前一块的实际哈希值不等，证明区块断裂
            if block.prehash != pre.hash:
                print("区块链断裂！")
                return False
        return True
    


#溯源系统
class system:
    def __init__(self , user):
        self.user = user
    #
    def HOME(self):
        login_state=False
        while True:
            if not login_state:
                print("————————————————*******************如需登录请登录*******************————————————————")
                switch_1 = input("请选择: \n1、登录\n2、注册\n3、查询食品信息\n4、退出系统\n"+"————————————————*************************************************————————————————")
                if switch_1 == '1':
                    login_state=self.user.login()
                    login_state = True
                if switch_1 == '2':
                    self.user.register()
                if switch_1 == '3':
                    self.searchChain()
                if switch_1 == '4':
                    break
            else:
                print("————————————————**********"+"欢迎你，"+self.user.name+"**********————————————————")
                switch = input("请选择: \n 1、添加食品\n2、添加食品加工信息\n3、查询食品信息\n4、登出\n5、退出系统\n"+"————————————————*************************************************————————————————")
                if switch == '1':
                    self.createChain()
                if switch == '2':
                    self.addEvent()
                if switch == '3':
                    self.searchChain()
                if switch == '4':
                    login_state = False
                if switch == '5':
                    break
    #
    #创建新的食品区块链
    def createChain(self):
        name = input("输入食品名称：")
        while True:
            foodID = randomGenerate()
            if chains.get(foodID):
                continue
            else:
                break
        print("已为该批次食品生成ID: "+foodID+" ,请勿忘记！")
        location = input("请输入生产或者培育地点:")
        director = input("相关负责人姓名：")

        description = "生产"
        info = input("请输入食品相关信息：")
        event = eventInfo(director,self.user ,location, description, info)
        event.sign()
        # basicInfo = foodInfo(ID , self.user , event)
        newChain = Chain(name, foodID, event)
        chains[foodID] = newChain
        
    # 查询某个食品区块链的溯源信息
    def searchChain(self):
        ID = input("输入食品ID：")
        if not chains.get(ID):
            print("食品ID不存在！")
            return False
        print("———————————————##########################————————————————\n"+"以下是食品ID为 "+ID+" 的供应链信息：")
        chains[ID].getTheChain()
        print("———————————————##########################————————————————\n")

    # 输入食品信息区块，并存入对应的区块链
    def addEvent(self):
        ID = input("输入食品ID：")
        if not chains.get(ID):
            print("食品ID不存在！")
            return False
        if chains[ID].lock:
            print("该区块链已经被锁定！无法添加信息。")
            return False

        dec = input("输入食品处理事件(生产、加工、包装、运输、批发、零售)描述：")
        loc = input("输入食品处理地点：")
        director = input("请输入相关负责人姓名：")
        info = input("请输入食品交易相关信息：")
        event = eventInfo(director , self.user , loc , dec, info)
        event.sign()
        newBlock = Block(event)
        chains[ID].addNewBlock(newBlock)
        if dec=="零售" or dec =="批发":
            chains[ID].lock = True

# 测试
usr = user()
systest = system(usr)
systest.HOME()
