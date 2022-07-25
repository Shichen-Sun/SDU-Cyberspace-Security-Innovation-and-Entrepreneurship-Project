# SDU-201900460045-Sun-Lab
## SDU-网络安全创新创业实践课实验
成员 孙洛鹏 201900460045
### 课程实验---实现ECDSA签名算法的伪造
椭圆曲线算法是基于有限域上椭圆曲线所形成的循环子群上。因此，算法需要以下几个重要参数  
• 素数p，用于确定有限域的范围  
• 椭圆曲线方程参数a和b   
• 用于生成子群的基点G  
• 子群的阶n  
• 辅助因子h  
本次实验具体实现中，采用标准化的椭圆曲线secp256k1，具体参数如下：  
p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F = $2^{256} - 2^{32} - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1$   
E = $y^2$ = $x^3 + ax + b$在有限域$Fn$上  
a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  
b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007  
G = 04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8  
n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141  
h = 01 
#### 定义相应参数，定义椭圆曲线相应运算以及签名验签操作
**模逆运算** 即采用扩展欧几里得算法的方式求模逆  
**点加** 根据曲线$E(Fp)$上的点，按照相应加法规则，构成一个交换群  
**是否在曲线上** 根据方程验证点是否在曲线$E(Fp)$上
**多倍点** 椭圆曲线上同一个点的多次加运算记为该点的多倍点运算
**公私钥生成** 私钥$d$在${1······n-1}$中任取，公钥$P=dG$
**签名算法**
```python
代码简述
  def hash_message(message):
    message_hash = hashlib.sha256(message).digest()
    e = int.from_bytes(message_hash, 'big')
    return e

def sign_message(private_key, message):
    e = hash_message(message)
    r = 0
    s = 0
    while not r or not s:
        global k_leak;k_leak = 64373566430140278131327580440284289972164712976330163913406988842791059250706
        #print('k的值:',k_leak)
        R_x, R_y = scalar_mult(k_leak, curve.g);r = R_x % curve.n;s = ((e + r * private_key) * inverse_mod(k_leak, curve.n)) % curve.n
        #k = random.randrange(1, curve.n)   
        #为保障安全性,k随机生成且不能重复使用.如果泄露k会导致泄露密钥d
    return (r, s) 
```

公式说明：   
$k\leftarrow Z_{n}^*$  
$ R=kG $  
$ r=R_{x} mod n, r≠0 $  
 $e=hash(m) $  
$ s=k^{-1}(e+dr)mod n$  
 Sig即为$(r,s)$  







### 课程实验---实现MerkleTree
#### Impl Merkle Tree following RFC6962
实现思路：采用多维数组存储以此实现Merkel树。Merkle树从上至下的每一层结点的hash值依次存储在多维列表中。  
生成Merkle树过程：  
（1）当该层节点为偶数个节点时，两两依次配对，加前缀级联生成父节点的hash值  
（2）当该层节点为奇数个节点时，最后一个节点作为父节点，其余节点两两依次配对，加前缀生成父节点的hash值  
（3）每一层结点都由靠近叶节点的底下一层生成。按照上述规律生成节点，直到生成根节点
（4）按照RFC 6962的标准要求，叶节点的其余节点的进行hash的前缀不同（其中叶节点前缀为0x00，其余为0x01）
<div align=center>
  <img src ="https://user-images.githubusercontent.com/80566951/180631091-47d2ffe9-7786-4a1d-854e-81d3167880ac.png">
  </div>
<p align="center">测试截图</p>

#### Construct a Merkle tree with 10w leaf nodes  
 按照生成方法，构造大小为10w的Merkle树。该树的深度为17，运行结果如下  
<div align=center>
  <img src ="https://user-images.githubusercontent.com/80566951/180631497-ef1c549a-f75f-4ebd-81ab-d5888f466405.png">
  <p align="center">·····</p>
  <img src = "https://user-images.githubusercontent.com/80566951/180631440-39df00ec-80a7-4276-85d8-8ab7e4637bce.png">
  <p align="center">·····</p>
  <img src ="https://user-images.githubusercontent.com/80566951/180631606-201c6c9f-d044-46fe-9ce4-ff9bc0645b63.png">
  </div>
  <p align="center">10W叶节点测试运行截图</p>

####  Build inclusion proof for specified element & Build exclusion proof for specified element
即对特定的Merkle树，指定需要查找的节点和相应序号，判断其是否在树中，并给出判断证明。
##### 1.当查找序号大于叶节点个数报错
<div align=center>
  <img src ="https://user-images.githubusercontent.com/80566951/180631849-c2f3ab6b-da81-4b56-a70a-9063432414ce.png">
  </div>
<p align="center">节点=根节点</p>

##### 2.节点=根节点
<div align=center>
  <img src ="https://user-images.githubusercontent.com/80566951/180631787-7aee5c38-d711-49a7-9031-0de13dd9070d.png">
  </div>
<p align="center">报错</p>

##### 3.节点不在MerkleTree
<div align=center>
  <img src ="https://user-images.githubusercontent.com/80566951/180631816-24198ca5-7d87-440e-a957-40ec886533aa.png">
  </div>
<p align="center">节点不在MerkleTree</p>

