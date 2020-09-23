from random import randint

class prime:
    @staticmethod # sourced from https://github.com/bopace/generate-primes
    def isPrime(num, testCount):
        if num == 1:
            return False
        if testCount >= num:
            testCount = num - 1
        for val in range(testCount):
            val = randint(1, num - 1)
            if pow(val, num-1, num) != 1:
                return False
        return True

    @staticmethod
    def generateBigPrime(n):
        foundPrime = False
        while not foundPrime:
            p = randint(2**(n-1), 2**n)
            if prime.isPrime(p, 1000):
                return int(p)

prime = prime() # define the prime class
prime_size = 512 # size of prime in multiples of 8
counter = 1 # init the counter

while True:
    try:
        newPrime = prime.generateBigPrime(prime_size)
        print("{} | ".format(counter) + str(newPrime))
        counter = counter+1 # increase the counter by one
    except KeyboardInterrupt:
        print("\nTotal generated primes: {}".format(counter-1))
        exit()
        