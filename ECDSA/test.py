from GetECDSA import curve,inverse_mod,is_on_curve,point_neg,point_add,scalar_mult,make_keypair,hash_message,verify_signature
import random
global k_leak

def sign_message(private_key, message):
    e = hash_message(message)
    r = 0
    s = 0
    while not r or not s:
        global k_leak;k_leak = 64373566430140278131327580440284289972164712976330163913406988842791059250706
        print('k的值:',k_leak)
        R_x, R_y = scalar_mult(k_leak, curve.g);r = R_x % curve.n;s = ((e + r * private_key) * inverse_mod(k_leak, curve.n)) % curve.n
        #k = random.randrange(1, curve.n)   #为保障安全性,k随机生成且不能重复使用.如果泄露k会导致泄露密钥d
    return (r, s)

if __name__ == "__main__":
    
    print('Curve:', curve.name)

    d, P = make_keypair()
    print("Private key:", hex(d))
    print("Public key: (0x{:x}, 0x{:x})".format(*P))

    msg = b'How u doing?'
    signature = sign_message(d, msg)

    print()
    print('Message:', msg)
    print('Signature: (0x{:x}, 0x{:x})'.format(*signature))
    print('Verification:', verify_signature(P, msg, signature))

    # (1) 泄漏k导致泄漏d # 
    print('\n(1)泄漏k导致泄漏d:')
    print('泄露的k = {}'.format(hex(k_leak)))
    
    e = hash_message(msg)
    r,s = signature
    d_guess = (inverse_mod(r, curve.n)*(k_leak*s - e))%curve.n
    print('猜测密钥d = {0}'.format(hex(d_guess)))

    if d_guess == d:print('成功!')
    else:print('失败.')

    # (2) 重用 k 导致 d 泄漏 #
    print('\n(2)重用 k 导致 d 泄漏:')
    print('重复使用的k = {}'.format(hex(k_leak)))
    
    m1 = b'ShiChenSun'
    
    m2 = b'ChenYuLiu'
    signature1 = sign_message(d, m1)

    signature2 = sign_message(d, m2)

    e1 = hash_message(m1);r1 = signature1[0];s1 = signature1[1]
    e2 = hash_message(m2);r2 = signature2[0];s2 = signature2[1]
    
    #根据两条消息及对应的签名恢复私钥
    d_guess2 = ((s2*e1-s1*e2)*inverse_mod(s1*r1-s2*r1, curve.n)) %curve.n
    print('猜测密钥d = {0}'.format(hex(d_guess2)))
    
    if d_guess2 == d:print('成功!')
    else:print('失败.')

    # (3) 通过不同用户重用 k 泄露密钥
    #两个用户，使用 k 导致 d 泄露，即可以推导出对方的 d #
    print('\n(3)因为不同用户重用 k 泄露密钥:')
    
    d1, P1 = make_keypair()
    d2, P2 = make_keypair()
    signature_Alice = sign_message(d1, m1)
    e_1 = hash_message(m1)
    r_1 = signature_Alice[0]
    s_1 = signature_Alice[1]
    
    signature_Bob = sign_message(d2, m2)
    e_2 = hash_message(m2)
    r_2 = signature_Bob[0]
    s_2 = signature_Bob[1]
    
    print("Alice的私钥d1:", hex(d1))
    print("Alice的公钥P1: (0x{:x}, 0x{:x})".format(*P1))
    print("Alice签名的消息:",m1)
    print("\nBob的私钥d2:", hex(d2))
    print("Bob的公钥P2: (0x{:x}, 0x{:x})".format(*P2))
    print("Bob签名的消息m2:",m2)
    print()

    #r1=r2
    #Alice恢复Bob的密钥
    d_guess_Bob = ((s_2*e_1-s_1*e_2+s_2*r_1*d1)*inverse_mod(s_1*r_1,curve.n)) % curve.n
    print('Alice恢复Bob的私钥:',hex(d_guess_Bob))
    if d_guess_Bob == d2:print('成功!')
    else:print('失败.')
    
    #Bob恢复Alice的密钥
    d_guess_Alice = ((s_1*e_2-s_2*e_1+s_1*r_1*d2)*inverse_mod(s_2*r_1,curve.n)) % curve.n
    print('Bob恢复Alice的私钥:',hex(d_guess_Alice))
    if d_guess_Alice == d1:print('成功!')
    else:print('失败.')


    d_guess_Bob = ((s_2*e_2-s_1*e_1+s_2*r_1*d1)*inverse_mod(s_1*r_1,curve.n))%curve.n
    print('')

# (4) (r,s) 和 (r,-s) 都是有效签名
    print('(4) (r,s) 和 (r,-s) 都是有效签名:')

    d, P = make_keypair()
    msg = b'ShanDong University'
    print("消息:", msg)
    print("密钥d:", hex(d))
    print("公钥P: (0x{:x}, 0x{:x})".format(*P))
    
    signature = sign_message(d, msg);e1 = hash_message(msg)
    print('签名: (0x{:x}, 0x{:x})'.format(*signature))
    print('(r,s) 验证:', verify_signature(P, msg, signature))

    r,s = signature
    s_neg = -s%curve.n
    #(r,s)通过验证，(r,-s)同样可以
    signature_forge = (r,s_neg)
    print('(r,-s) 验证:', verify_signature(P, msg, signature_forge))
    
# (5) 如果验证不检查 m 则可以伪造签名
    print('\n(5)如果验证不检查 m 则可以伪造签名:')
    u = random.randrange(1, curve.n)
    v = random.randrange(1, curve.n)
    (x,y) = point_add(scalar_mult(u,curve.g),scalar_mult(v,P))
    r_ = x%curve.n
    e_ = r_*u*inverse_mod(v,curve.n)
    s_ = r_*inverse_mod(v,curve.n)
    
    #Check 可以伪造出哈希值为e_的消息签名
    w = inverse_mod(s_, curve.n)
    u1 = (e_ * w) % curve.n
    u2 = (r_ * w) % curve.n
    (r_forge,s_forge)=point_add(scalar_mult(u1,curve.g),
                                scalar_mult(u2,P))
    if r_forge % curve.n == r_:
        print('成功!')

# (6) ECDSA & Schnoor 签名中使用相同的 d 和 k，导致 d 泄漏
    print('\n(6) ECDSA & Schnoor 签名中使用相同的 d 和 k，导致 d 泄漏:')
    d1, P1 = make_keypair()
    k = random.randrange(1, curve.n)

    #ECDSA
    m = b'ECDSA'
    e1 = hash_message(m)
    R_x, R_y = scalar_mult(k, curve.g)#R=kG
    r1 = R_x % curve.n
    s1 = ((e1 + r1 * d1) * inverse_mod(k, curve.n)) % curve.n

    #具有相同私钥 d 的 Schnoor 签名
    R = scalar_mult(k, curve.g)
    R_x = hex(R_x)[2:]
    R_y = hex(R_y)[2:]
    R = R_x+R_y
    #print(R_x,R_y,R)
    
    e2 = hash_message(R.encode('utf-8')+m)
    s2 = (k+e2*d)%curve.n

    s1 = ((e1 + r1 * d1) * inverse_mod(s2-e2*d1, curve.n)) % curve.n
    d_guess = (s1*s2-e1)*inverse_mod(s1*e2+r1,curve.n)%curve.n
    if d_guess == d1:
        print('成功!')
