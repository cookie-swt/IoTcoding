import hashlib   #实现SHA256需要用到的库

# sha256函数
def sha256(value):
    #对输入的数据进行解码
    #返回计算后得出的16进制摘要
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

#区块类
class Block:
    #构造函数
    def __init__(self , data , prehash=''):
        #区块中存储的数据
        self.data = data 
        #用于得到符合PoW难度的哈希值的随机数
        self.nonce = 0 
        #上一个区块的哈希值，用于将区块连接起来
        self.prehash = prehash
        #计算本区块的哈希值
        self.hash = self.getHash()

    #计算本区块哈希值
    def getHash(self):
        #需要计算的值包括存储的数据、前一区块的哈希值、随机数
        return sha256(str(self.data) + self.prehash + str(self.nonce))

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

    #获取区块的内容，方便输出
    def getBlock(self):
        blockMessage = {'previousHash': self.prehash,
                        'data': self.data,
                        'hash': self.hash
                        }
        return blockMessage

#区块链类
class Chain:
    #构造函数
    def __init__(self):
        #设置PoW的难度，哈希值符合前difficulty位为0的 区块才可以被加入
        self.difficulty = 3
        #存储区块的数组,初始只含有祖先区块
        self.blocks = [self.createGenesis()]
        
    #生成祖先区块
    def createGenesis(self):
        genesisBlock = Block('我是祖先' , '')
        return genesisBlock

    #添加新区块
    def addNewBlock(self , block):
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
    
    #获取链的内容，方便输出
    def getChain(self):
        chainMessage = [i.getBlock() for i in self.blocks]
        return chainMessage


#测试————————————————————————————————————————————————————————————————————

b1 = Block('大连理工大学','')
b2 = Block('软件学院' , '')

MyChain = Chain()

MyChain.addNewBlock(b1)
MyChain.addNewBlock(b2)

print(MyChain.getChain())
print(MyChain.verify())

#尝试篡改数据
b1.data="天津大学"
print(MyChain.getChain())
print(MyChain.verify())
