# -*- coding: utf-8 -*-
 
from array import array
 
# 加密解密因子(大小范围要选好, 然后双方协定好)
M1 = 1 << 19
IA1 = 2 << 20
IC1 = 3 << 21
 
def crypt(data, encrypt_key=1):
    """加密解密
    >>> crypt("abc", 2)
    'kde'
    >>> crypt("kde", 2)
    'abc'
    >>> 
    """
    raw_data = array("B", data)
    for i in xrange(len(raw_data)):
        encrypt_key = IA1 * (encrypt_key % M1) + IC1
        raw_data[i] ^= (encrypt_key >> 20 & 0xff)
    return raw_data.tostring()
 
 
if __name__ == "__main__":
    import doctest
    doctest.testmod()
    # 效率 1KB => 0.00099s, 1MB => 0.62099s