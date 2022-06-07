import hashlib  #实现SHA256需要用到的库
import ecdsa     #实现密钥
import time

chains = dict()

# sha256函数
def sha256(value):
    #对输入的数据进行解码
    #返回计算后得出的16进制摘要
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

#生成密钥对，需要给出用户名参数
class genKeyPair:
    def __init__(self , name):
        self.name = name
        self.privateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.publicKey = self.privateKey.get_verifying_key()

#加工事件类
class proEvent:
    def __init__(self , descrption , location , time):
        self.description = descrption
        self.location = location
        self.time = time

#食品信息类
class foodInfo:
    def __init__(self , ID , head , event):
        self.ID = ID
        self.head = head
        self.event = event
        self.time = time.localtime()
        self.sign()

    #返回食品信息的哈希值
    def getHash(self):
        eventdata = str(self.event.description) + str(self.event.location) + str(self.event.time)
        return str(sha256(str(self.name)+str(self.head)+eventdata+str(self.time))).encode()
    
    #用负责人的私钥进行数字签名
    def sign(self):
        self.signature = self.head.privateKey.sign(self.getHash())

    #验证数字签名
    def isValid(self , key):
        try:
            key.verify(self.signature , self.getHash())
        except ecdsa.keys.BadSignaturerror:
            return False
        return True

#区块类
class Block:
    #构造函数
    def __init__(self , info , prehash=''):
        #区块中存储的数据->食品信息对象
        self.info = info
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
        return sha256(str(self.info) + self.prehash + str(self.nonce)) + str(self.timestamp)

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
        print("挖矿成功" , self.hash) 

    #验证食品信息的数字签名
    def validateInfo(self):
        if not self.info.isValid(self.info.head.publicKey):
            print("食品信息异常！")
            return False
        return True


#区块链类
class Chain:
    #构造函数
    def __init__(self , name , ID , head , info):
        #该区块链存储的食品
        self.name = name
        #设置PoW的难度，哈希值符合前difficulty位为0的 区块才可以被加入
        self.difficulty = 3
        #存储区块的数组,初始只含有祖先区块
        self.blocks = [self.createGenesis(ID , head , info)]
        
    #生成祖先区块
    def createGenesis(self , info):
        genesisBlock = Block(info)
        return genesisBlock

    #添加新区块
    def addNewBlock(self , block):
        #判断区块的数字签名
        if not block.validateInfo():
            print("信息上传失败！")
            return False
        #获取区块数组中最后一个元素，即最新的区块
        latestblock = self.blocks[-1]  
        #连接区块
        block.prehash = latestblock.hash  
        #挖矿
        block.mine(self.difficulty)  
        #新区块加入区块链
        self.blocks.append(block) 

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

    #创建新的食品区块链
    def createChain(self):
        name = input("输入食品名称：")
        ID = input("输入食品ID：")
        if chains.has_key(ID):
            print("该溯源链已存在，不能再次创建。")
            return False
        event = proEvent("创建新的食品溯源链" , "" , time.localtime())
        basicInfo = foodInfo(ID , self.user , event)
        newChain = Chain(name , basicInfo)
        chains[ID] = newChain

        

    #输入食品信息区块，并存入对应的区块链
    def inputInfo(self):
        ID = input("输入食品ID：")
        if not chains.has_key(ID):
            print("该溯源链不存在，请先创建")
            return False
        des = input("输入加工事件描述：")
        loc = input("输入加工地点：")
        time = input("输入加工时间：")
        event = proEvent(des , loc , time)
        info = foodInfo(ID , self.user , event)
        newBlock = Block(info)
        chain = chains[ID]
        chain.addNewBlock(newBlock)
