import random
import math

#primality test from 2 + sqrt(n) (inclusive)
def is_prime(n):
    if(n <= 1):
        return False
    #int cast is significantly faster than floor
    for i in range(4, (int)(math.sqrt(n)) + 1):
        if n%i == 0:
            return False
    return True

def co_prime(m, n):
    min_num = min(m,n)
    max_num = n if m == min_num else m
    for i in range(2, abs(min_num)//2 + 1):
        if min_num%i == 0 and max_num%i == 0:
            return False
    return True

def totient_primes(p, q):
    assert is_prime(p) and is_prime(q), "p and q must be prime for phi's special case phi(pq) = (p-1)(q-1)"
    return (p-1)*(q-1)

#extended_euclidian algorithm
def inverse(a, n):
    assert n > 0, "the modulus n must be greater than 0"
    #precaution
    a %= n

    #gcd step
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
    for p in range(2, n):
        if is_prime(p):
            for q in range(2, p+1):
                if is_prime(q) and n//q == p:
                    phi = totient_primes(p, q)
                    d = inverse(e, phi)
                    return (int)(pow(c, d, n))

alice = Person("Alice")
bob = Person("Bob")

alice.generate_rsa_keys()
bob.create_rsa_keys(3, 7, 11)

c = alice.encrypt_rsa(12, bob)
#m = crack_rsa_with_public_key(c, bob.public_rsa_key)
m = crack_rsa_with_public_key(41802438, (58687709 , 270679))

print(f"the cracked message is \'{m}\'\n")


#bob.create_rsa_keys(3, 7, 11)
