import hashlib  #实现SHA256需要用到的库
import ecdsa     #实现密钥
import time

# 食品信息存储
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

#食品事件类
class eventInfo:
    def __init__(self , director, location, descrption):
        self.director = director
        self.description = descrption
        self.location = location
        self.time = time.localtime()
    
    # 返回食品加工信息的哈希值
    def getHash(self):
        return str(sha256(str(self.director) + str(self.description) + str(self.location)+str(self.time))).encode()
    
    #用负责人的私钥进行数字签名
    def sign(self):
        self.signature = self.director.privateKey.sign(self.getHash())

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
        print("挖矿成功" , self.hash) 
    
    # 显示当前食品加工区块的信息
    def getTheBlock(self):
        print(str(self.event.time.tm_year)+"年"+str(self.event.time.tm_mon)+"月"+str(self.event.time.tm_mday)+"日"+str(self.event.time.tm_hour)+"时"
        +str(self.event.time.tm_min)+"分"+str(self.event.time.tm_sec)+"秒\n"+"事件："+self.event.description+"  "
        +"厂商："+self.event.location+"  "+"负责人："+self.event.director.name+"  "+"商业信息："+self.event.description+"\n")
    
    #验证食品信息的数字签名
    def validateInfo(self):
        if not self.event.isValid(self.event.director.publicKey):
            print("食品信息异常！")
            return False
        return True


#区块链类
class Chain:
    #构造函数
    def __init__(self, foodName, ID, event):
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
        while True:
            switch = input("请选择: \n 1、添加食品\n2、添加食品加工信息\n3、查询食品加工信息")
            if switch == '1':
                self.createChain()
            if switch == '2':
                self.addEvent()
            if switch == '3':
                self.searchChain()
    #
    #创建新的食品区块链
    def createChain(self):
        name = input("输入食品名称：")
        foodID = input("请输入食品ID:")
        if chains.get(foodID):
            print("该溯源链已存在，不能再次创建。")
            return False
        location = input("生产商:")
        head = input("负责人：")
        director = genKeyPair(head)
        description = input("描述信息:")
        event = eventInfo(director, location, description)
        event.sign()
        # basicInfo = foodInfo(ID , self.user , event)
        newChain = Chain(name, foodID, event)
        chains[foodID] = newChain
        
    # 查询某个食品区块链的溯源信息
    def searchChain(self):
        ID = input("输入食品ID：")
        if not chains.get(ID):
            print("Nonexistent")
            return False
        chains[ID].getTheChain()

    # 输入食品信息区块，并存入对应的区块链
    def addEvent(self):
        ID = input("输入食品ID：")
        if not chains.get(ID):
            print("该溯源链不存在，请先创建")
            return False
        loc = input("输入加工地点：")
        head = input("请输入负责人：")
        director = genKeyPair(head)
        dec = input("输入加工事件(生产、加工、包装、运输、批发、零售)描述：")
        event = eventInfo(director , loc , dec)
        event.sign()
        newBlock = Block(event)
        chains[ID].addNewBlock(newBlock)

# 测试

systest = system(1)
systest.HOME()