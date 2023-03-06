#coding = utf-8

import hmac
import timeit
import time
import random
import itertools
import numpy as np

class server():
    def __init__(self, key = 'zhujd'):
        self.privatekey = key

    def receive(self, message):
        self.message = message
        self.h = hmac.new(bytes(self.privatekey,'utf-8'), bytes(self.message,'utf-8'), digestmod='MD5').hexdigest()

    def seth(self, h):
        self.h = h

    def verify(self, tag):
        #return self.h == tag
        if len(self.h) != len(tag):
            return False
        length = len(self.h)
        for i in range(length):
            if tag[i] != self.h[i]:
                return False
        return True

class user():
    def __init__(self, key = 'zhujd'):
        self.privatekey = key

    def generate(self,mes):
        self.message = mes

    def signal(self):
        self.tag = hmac.new(bytes(self.privatekey,'utf-8'), bytes(self.message,'utf-8'), digestmod='MD5')
        return self.tag.hexdigest()

class attacker():
    def __init__(self, key = 'unknown'):
        self.fake_message = ''
        self.fake_tag = ''
        self.key = key

    def generate(self, mes):
        self.message = mes

    def signal(self, tag='0000'):
        if self.key == 'unknown':
            self.fake_tag = tag
        else : self.fake_tag = hmac.new(bytes(self.key,'utf-8'), bytes(self.message,'utf-8'), digestmod='MD5').hexdigest()
        return self.fake_tag

def random_hex(length):
    result = hex(random.randint(0,16**length)).replace('0x','').lower()
    if(len(result)<length):
        result = '0'*(length-len(result))+result
    return result

def allow_char():
    list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    return list

def crack_length(Bob, message, max_len, verbose = False):
    Eve = attacker()
    Eve.generate(message)
    Bob.receive(Eve.message)
    trials = 10000
    times = np.empty(max_len)
    for i in range(max_len):
        i_time = timeit.repeat(stmt='Bob.verify(x)',
                               setup=f'x=random_hex({i!r})',
                               globals=globals(),
                               number=trials,
                               repeat=10)
        times[i] = min(i_time)

    if verbose:
        most_likely_n = np.argsort(times)[::-1][:5]
        print(most_likely_n, times[most_likely_n] / times[most_likely_n[0]])

    most_likely = int(np.argmax(times))
    return most_likely

def crack_tag(Bob, message, length, verbose = False):
    Eve = attacker()
    Eve.generate(message)
    Bob.receive(Eve.message)
    guess = random_hex(length)
    counter = itertools.count()
    trials = 100
    list = allow_char()
    while True:
        i = next(counter) % length
        for c in list:
            alt = guess[:i] + c + guess[i + 1:]
            print(alt)
            alt_time = timeit.repeat(stmt='Bob.verify(alt)',
                                     setup=f'alt={alt!r}',
                                     globals=globals(),
                                     number=trials,
                                     repeat=10)
            guess_time = timeit.repeat(stmt='Bob.verify(guess)',
                                       setup=f'guess={guess!r}',
                                       globals=globals(),
                                       number=trials,
                                       repeat=10)

            if Bob.verify(alt):
                return alt

            if min(alt_time) > min(guess_time):
                guess = alt
                if verbose:
                    print(guess)

privatekey = 'zhujd'
Alice = user(privatekey)
Bob = server(privatekey)
Eve = attacker()

Alice.generate('I Love You.')
Bob.receive(Alice.message)
print(Bob.verify(Alice.signal()))

Eve.generate('I Hate You.')
Bob.receive(Eve.message)
#print(Bob.h)
print(Bob.verify(Eve.signal()))
#print(Bob.verify(Eve.signal('e98308a41f5e6006b21a304c738d2e8c')))

guess_len = crack_length(Bob, 'I Hate You.', 40)
print(guess_len)
#guess_tag = crack_tag(Bob, 'I Hate You.', 32)
#print(Bob.verify(Eve.signal(guess_tag)))










