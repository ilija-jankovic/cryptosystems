import random
import math
import re

from numpy.lib.function_base import append

#Euclidian algorithm for the greatest common divisor of m and n.
def gcd(m, n):
    while True:
        r = m%n
        if r == 0:
            return n
        m = n
        n = r

#Checks all co-primality of all divisors up to sqrt(min(m, n)).
def co_prime(m, n):
    min_num = min(m,n)
    max_num = n if m == min_num else m
    for i in range(2, (int)(math.sqrt(min_num)) + 1):
        if min_num%i == 0 and max_num%i == 0:
            return False
    return True

#Fourier transform method for calculating the Euler Totient function.
#phi(n) = sum(gcd(k,n) * cos(2*pi*k/n))
def totient(n):
    sum = 0
    n_div_2pi = 2*math.pi/n
    for k in range(1, n+1):
        sum += gcd(k, n) * math.cos(k*n_div_2pi)
    return (int)(sum)

#Special case of the Euler Totient function where is p and q are both primes,
#phi(p*q) = (p-1)*(q-1)
def totient_primes(p, q):
    assert is_prime(p) and is_prime(q), "p and q must be prime for phi's special case phi(pq) = (p-1)(q-1)"
    return (p-1)*(q-1)

#Miller-Rabin primality test.
#"For a given odd integer n > 2, let’s write n as (2^s)⋅d + 1 where s and d are positive integers and d is odd." - Wikipedia
#n is a strong probable prime if a^d = 1 mod(n) or a^((2^r)⋅d = -1 mod(n).
#Only need to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37 for n < 2^64 for a guaranteed prime.
#This is sufficient as it is the size of an unsigned integer.
a_vals = [2,3,5,7,11,13,17,19,23,29,31]
def is_prime(n):
    if n <= 2:
        return n > 1
    if n%2 == 0:
        return False

    n_off = n - 1
    s = 1
    while True:
        d = n_off / pow(2, s)
        d_floor = (int)(d)
        if d - d_floor == 0 and d_floor%2 == 1:
            d = d_floor
            break
        s += 1

    for a in a_vals:
        if n <= a:
            return True
        if pow(a, d, n) == 1:
            return True
        for r in range(0, s):
            if pow(a, pow(2, r)*d, n) == (-1)%n:
                return True
        return False



#Extended Euclidian Algorithm for the calculation of inverse(a mod(n)) 
def inverse(a, n):
    assert n > 0, "the modulus n must be greater than 0"
    #precaution
    a %= n

    #gcd
    co_effs = []
    r_vals = []
    n_gcd = n
    while True:
        co_eff = n_gcd//a
        r = n_gcd%a
        n_gcd = a
        a = r

        r_vals.append(r)
        co_effs.append(co_eff)

        if r == 0:
            break

    #extended step
    p_vals = [0, 1]
    for i in range(2, len(co_effs)+2):
        p_i = (p_vals[i-2] - p_vals[i-1]*co_effs[i-2]) % n
        p_vals.append(p_i)
    if r_vals[len(r_vals)-2] == 1:
        return p_vals[len(r_vals)]
    return -1

#Class to hold public key cryptosystem information.
class Person:
    def __init__(self, name):
        self.name = name

    #proof of concept for random keys
    def generate_rsa_keys(self):
        print(f"{self.name} is generating rsa keys...")
        primes = []
        for i in range(5, 200):
            if(is_prime(i)):
                primes.append(i)

        p = primes[random.randrange(0, len(primes))]
        q = primes[random.randrange(0, len(primes))]
        phi = totient_primes(p, q)

        #Extremely inefficient but works.
        #The loop is in place in case d has no inverse.
        while True:
            d = random.randint(1, phi - 1)
            if(co_prime(d, phi) and inverse(d, phi) != -1):
                break

        self.create_rsa_keys(p, q, d)

    #Generate RSA keys based on p, q, d.
    #p and d are primes.
    #n = p*q
    #phi(n) = (p-1)*(q-1).
    #d is > 0 and < n, and comprime to phi(n)
    #e = inverse(d)
    def create_rsa_keys(self, p, q, d):
        print(f"{self.name} is creating rsa key values...")
        assert is_prime(p) and is_prime(q), "p and q must be prime"
        phi = totient_primes(p, q)
        assert d < phi and co_prime(d, phi), "d must be smaller than and coprime to phi(pq)"

        n = p*q
        e = inverse(d, phi)

        self.public_rsa_key = (n, e)
        self.__private_rsa_key = (p, q, d)
        print(f"Public rsa key: ", self.public_rsa_key)
        print(f"Private rsa key: ", self.__private_rsa_key, "\n")

    #Encrypts message m with RSA by c = m^e mod(n), where (n, e) is the receiver's public key.
    def encrypt_rsa(self, m, receiver):
        assert m > 0 and m < receiver.public_rsa_key[0], "message must be greater or equal to 0 less than n in the receiver's public rsa key"
        print(f"encrypting \'{m}\'...\n")
        return (int)(pow(m, receiver.public_rsa_key[1], receiver.public_rsa_key[0]))

    #Decrypts cyphertext c with RSA by m = c^d mod(n), as e and d are inverses mod(phi(n)).
    def decrypt_rsa(self, c):
        print(f"decrypting {c} ...\n")
        return (int)(pow(c, self.__private_rsa_key[2], self.public_rsa_key[0]))

    def send_rsa(self, m, receiver):
        print(f'{self.name} is sending the message \'{m}\' to {receiver.name}...')
        c = self.encrypt_rsa(m, receiver)
        receiver.receive_rsa(c)

    def receive_rsa(self, c):
        print(f'{self.name} received cyphertext \'{c}\'!')
        d = self.decrypt_rsa(c)
        print(f'the message reads \'{d}\'\n')

#Cracks RSA cyphertext using only a public key.
#Algorithm iterates p up to sqrt(n), checking if p is prime.
#If prime, if n mod(p) == 0, that means both primes making up n from the public key are found.
#This is because n = p*q, and n/p = q.
#Using this information, the cyphertext can be cracked.
def crack_rsa_with_public_key(c, public_rsa_key):
    print(f"cracking cyphertext \'{c}\' with public RSA key", public_rsa_key, "...")
    n = public_rsa_key[0]
    e = public_rsa_key[1]
    for p in range(2, (int)(math.sqrt(n)) + 1):
        if is_prime(p) and n%p==0:
            q = n//p
            phi = totient_primes(p, q)
            d = inverse(e, phi)
            return (int)(pow(c, d, n))

#Removes all text except lower-case alphabet letters.
def to_lower_alphabet_only(text):
    assert type(text) == str, "text must be a string"
    return re.sub('[^a-z]+', '', text.lower())

#Encrypts message based on permutation k.
def encrypt_vigenere(m, k):
    assert type(m) == str, "m must be a string"
    print(f"vigenere shifting message\n\'{m}\'\nwith key", k, "...")
    m = to_lower_alphabet_only(m)
    c = ""
    k_size = len(k)
    for i in range(0, len(m)):
        c += chr((ord(m[i]) - ord('a') + k[(i+1)%k_size])%26 + ord('a'))
    return c

#Decryption is the same as encryption, with -permutation mod(26)).
def decrypt_vigenere(c, k):
    assert type(c) == str, "c must be a string"
    return encrypt_vigenere(c, tuple([(-n)%26 for n in k]))
    """
    c = to_lower_alphabet_only(c)
    m = ""
    k_size = len(k)
    for i in range(0, len(c)):
        m += chr((ord(c[i]) - ord('a') - k[(i+1)%k_size])%26 + ord('a'))
    return m
    """

#Finds the frequency of individual characters in cyphertext.
def find_frequencies(c):
    assert type(c) == str, "c must be a string"
    frequencies = []
    for ch in c:
        i = frequencies.index(ch) if ch in frequencies else None
        if i != None:
            frequencies[i+1] += 1
        else:
            frequencies.append(ch)
            frequencies.append(1)
    return frequencies

#Checks the IC of a cyphertext based on the English language i.e IC = IC - 1/26
def ic_english(c):
    c = to_lower_alphabet_only(c)
    c_len = len(c)
    if(c_len <= 1):
        return 0.0
    frequencies = find_frequencies(c)
    ic = 0
    for i in range(0, len(frequencies), 2):
        ic += (frequencies[i+1] / c_len)**2
    ic -= 1.0/16.0
    return ic

#Checks the period with the highest IC in the cyphertext.
def ic_vigenere_period(c, start = 1, end = 10):
    c = to_lower_alphabet_only(c)
    assert type(c) == str, "c must be a string"
    ics = []
    for p in range(start, min(end+1, len(c))):
        ics.append(0)
        count = 0
        for i in range(0, p):
            column = ""
            row = 0
            c_i = row*p + i
            while c_i < len(c):
                column += c[c_i]
                row += 1
                c_i = row*p + i
            if column != "":
                ics[len(ics)-1] += ic_english(column)
                count += 1
            ics[len(ics)-1] /= count
    ic_max = max(ics)
    p = ics.index(ic_max) + start
    print("average IC of", ic_max, "with a period of", p, "\n")
    return p


"""
alice = Person("Alice")
bob = Person("Bob")

alice.generate_rsa_keys()
bob.generate_rsa_keys()

alice.send_rsa(12, bob)
"""



"""
m = crack_rsa_with_public_key(41802438, (58687709 , 270679))
print(f"the cracked message is \'{m}\'\n")
"""



"""
v_m = "buycryptonowbuycryptonowbuycryptonowbuycryptonowbuycryptonow"
v_key = (2,3,1,4,0)
v_c = encrypt_vigenere(v_m, v_key)
print("encrypting...\n")
print(f"cyphertext reads...\n\'{v_c.upper()}\'\n")

v_m = decrypt_vigenere(v_c.upper(), v_key)
print("decrypting...\n")
print(f"message reads...\n\'{v_m.lower()}\'\n")

v_m_ic = ic_english(v_m.lower())
print("message IC =", v_m_ic, "\n")
v_c_ic = ic_english(v_c.upper())
print("cyphertext IC =", v_c_ic, "\n")
"""



"""
v_c = "L llws, gpysoj, qvzf tubimofbwv zvdx tg ofc jc wlpjf xlzm, lj yphbztu lw yfufvihhh, \
lor cw zvh fpth uixoqkpnshky oui xbry, ry hkij bfy skwqk xbry, nk gkewm dlfbs ryctsfmkg rrnf \
oarob dfwf hi ukthro pil Zyzdro icgv, zc umof cok zvh wepfg fl kdv, lor nf uiwptws nyk ahrlds \
iw zmueyom, cw tsfidtolp lcu cpbfm, zl bhgptguie oosyf. On rtm ueef, hbrz wv asbh qv gfh kzjba \
ku huc ep ri. Know md uvy ikgrpgf cz Yog Peufgnp'y Urzpsbgvth, hzpsm grt ci xsfa. Nygh lw eis qzrz rj \
Abffzgahre bbx kns qeejch. Kns Evtuwmy Kasmcf ohu zvh Jcfbwy Xssymmww, cobnio ucavzvhv to hbvof fefts uej \
wq xsfwl eksg, atmz xvlsqh ep hbv jsdxs uvyzx bdxtws mfoz, dmojba vgqk seisl coyh kzpr wfsfdhpt hi kns \
xxxpgn fl hkits gnikbjxs. Fjye zvryri zuims wvldhm fl Sxvzqs uej adrj pzx rtr iexpim Jzowid iopv looppo \
cl dgm iewm whku hki rswj fl hki Rfgnrvc dro bzf kns rhtpim rvddvluim fl Bddt sifv, cs vllmz hfz toer pf \
zroz. Zi diofc mc rr ep hbv kbg, ap tvucr tlksu wh Wxoqgp, xs mygzo jthvn ft hki dfom rtr rgpbbm, nk gkewm \
tcxnh zmei ulfcwqk npbzzjsqgp bbx xxczmyh gnikbjxs jb nyk olv, hf gbrrz giqfbx faf Lwwbbx, nnowigff nyk qrwe \
nos sk, kh wsbzf woukx zo hbv hsdgsfg, qv yvdpw gwayz cq xsf zuejwqk rscoejg, zi diofc lwjle jb nyk tliweg \
uej wq xsf gniksww, hf gbrrz imrih ce zvh ltmzm; nk gkewm bymkf vycsshukf, dro fjye ot, zltdv C uu brx qpf \
u duahre csfzkjh, xsjg Cjroqh zs o frxuh tlsh iw oh zicf gospijeefr uej gwecwwhx, zvhr zvf Ydvwui mfmiej hki\
 dfom, rxahh lor algfgio cm nyk Pumejgb Wrshx, hpifu iouvj pb nyk gwvfhufv, abwmw, jb Afj'g jsze hcdk, hki Yfk \
 Qfxzg, atuv ucr www apkyi gbg qthvn, jzssw qpfny zc wlp ssmtas dro uvy cophvluwie ut wlp pzx."

p = ic_vigenere_period(v_c)
"""