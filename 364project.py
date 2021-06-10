import random
import math

def gcd(m, n):
    while True:
        r = m%n
        if r == 0:
            return n
        m = n
        n = r

def co_prime(m, n):
    min_num = min(m,n)
    max_num = n if m == min_num else m
    for i in range(2, abs(min_num)//2 + 1):
        if min_num%i == 0 and max_num%i == 0:
            return False
    return True

def is_perfect_power(n):
    for i in range(0, math.log2(n)):
        if n%i == 0:
            return True
    return False

def ord(a, n):
    assert n > 1, "the modulus n must be greater than 0"
    k = 1
    while True:
        if pow(a, k, n) == 1:
            return k
        k += 1

def totient(n):
    sum = 0
    n_div_2pi = 2*math.pi/n
    for i in range(1, n+1):
        sum += gcd(i, n) * math.cos(i*n_div_2pi)
    return (int)(sum)

def totient_primes(p, q):
    assert is_prime(p) and is_prime(q), "p and q must be prime for phi's special case phi(pq) = (p-1)(q-1)"
    return (p-1)*(q-1)

#Miller-Rabin primality test
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



#extended_euclidian algorithm
def inverse(a, n):
    assert n > 0, "the modulus n must be greater than 0"
    #precaution
    a %= n

    #gcd steps + 1
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

        while True:
            d = random.randint(1, phi - 1)
            if(co_prime(d, phi) and inverse(d, phi) != -1):
                break

        self.create_rsa_keys(p, q, d)


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

    def encrypt_rsa(self, m, receiver):
        assert m > 0 and m < receiver.public_rsa_key[0], "message must be greater or equal to 0 less than n in the receiver's public rsa key"
        print(f"encrypting \'{m}\'...\n")
        return (int)(pow(m, receiver.public_rsa_key[1], receiver.public_rsa_key[0]))

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

#alice = Person("Alice")
#bob = Person("Bob")

#for i in range(0, 100): print(i, is_prime(i))

#alice.generate_rsa_keys()
#bob.generate_rsa_keys()

#alice.send_rsa(12, bob)

#c = alice.encrypt_rsa(12, bob)
#m = crack_rsa_with_public_key(c, bob.public_rsa_key)
m = crack_rsa_with_public_key(41802438, (58687709 , 270679))

print(f"the cracked message is \'{m}\'\n")

#bob.create_rsa_keys(3, 7, 11)