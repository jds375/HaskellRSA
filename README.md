# RSA Cryptosystem in Haskell #
I first started functional programming a year ago using OCaml. I was learning a lot, but stopped once my schedule started to fill up. I decided that this winter I would take another shot at functional programming with Haskell. I made an end-goal of implementing the bare-bones RSA cryptosystem in Haskell and below is some commentary on what I came up with. Any comments/suggestions regarding my code and style with respect to Haskell would be greatly appreciated!
#### Random Number Generation ####
The first problem I had to tackle was random number generation. I decided to use Haskell's <i> System.Random </i> to generate the number. I knew that the generator wouldn't be cryptographically secure, but certainly sufficient for educational purposes. I used the simple <i> randomRIO (m, n) </i> method to generate a random number in the range <i> m </i> to <i> n </i>. 
````haskell
-- Uses System.Random to get a random Integer between m and n inclusive
randomInteger :: Integer -> Integer -> IO Integer
randomInteger m n = randomRIO (m, n)
````
#### Primality Testing ####
The basis for the security of RSA is a number <i> n=p*q </i> using random, large prime numbers <i> p </i> and <i> q </i>. This number <i> n </i> is useful since this value can be publicly transmitted without risking the identities of <i> p </i> and <i> q </i>, which are used for encryption. <i> n </i> can be transmitted publicly since it is extremely difficult to factor large numbers and thus difficult for a hacker to determine the values of <i> p </i> and <i> q </i> used in the encryption.  Therefore, it is necessary to be able to generate random, large prime numbers effectively and efficiently. A simple strategy is to repeatedly generate random numbers and stop once we find a prime one. We already have a way to generate random numbers and now need a way to check if a number is prime. There are a variety of ways to do this. One of the most efficient ways to do this is the Miller-Rabin Primality Test. The Miller-Rabin Primality Test is performed in a series of <i> k </i> loops and determines if a number is prime with probability <i> 4^(-k) </i>. This is sufficient since the probability of error decreases exponentially. Moreover, it runs in polynomial time. The implementation that I used runs in time <i>O(k*log^3(n))</i>. See the psuedocode on the Miller-Rabin Primality Test Wikipedia page for the psuedo-code. 
````haskell
-- Performs "a mod b" with support for a negative first argument, that is
-- (-3 mod 4) will evaluate to 1 instead of staying at -3 as `mod` would do
fullMod :: Integer -> Integer -> Integer
fullMod a b
    | a >= 0 = a `mod` b
    | otherwise = fullMod (a + b) b

-- Starts the series of checks in the Rabin Test and performs the first check
rabinFirstCheck :: Integer -> Integer -> Integer -> IO Bool
rabinFirstCheck n d s =
    do
        a <- randomInteger 2 (n - 1)
        if (fullMod (a^d) n == 1) || (fullMod (a^d) n == (n - 1))
            then return True
            else return (rabinSecondCheck n d s (fullMod ((a^d)^2) n))
               

-- Continues the Rabin Test and performs the second check
rabinSecondCheck :: Integer -> Integer -> Integer -> Integer -> Bool
rabinSecondCheck n d s x
    | s <= 1 = False
    | x == 1 = False
    | x == (n - 1) = True
    | otherwise = rabinSecondCheck n d (s - 1) (x^2)

-- Performs the Miller-Rabin Primality Test with probability 4^-k
rabinTest :: Integer -> Integer -> IO Bool
rabinTest n k = 
    rabinTestH n k True 
rabinTestH n k res
    | not res = return res
    | k <= 0 = return res
    | otherwise = 
        rabinFirstCheck n (fst ds) (snd ds)
        where
           ds = getRabinFactors n

-- Generates a random prime using Miller-Rabin with probability 4^-k
getRandomPrime :: Integer -> Integer -> Integer -> IO Integer
getRandomPrime m n k = 
    do
        x <- randomInteger m n
        r <- rabinTest x k
        if r 
            then return x
            else getRandomPrime m n k
````

#### Getting the Key Pairs ####
In the naive implementation of RSA generating the public key pair and the private key pair is simple. Here, I only calculate the public and private key exponents since it is easy to compute the modulus using the two prime numbers generated earlier. In order to do this I had to implement Euclid's GCD algorithm to calculate the public key exponent and Euclid's Extended Algorithm to calculate the private key exponent. I then created an encompassing method to generate the two key sets, commonly written as <i>(e,n)</i> and <i>(d,n)</i> where the former is the public key pair and the latter is the private key pair. 
````haskell
-- Computes the greatest common denominator for a and b using Euclid's algorithm
egcd :: Integer -> Integer -> Integer
egcd a b 
    | b == 0 = a
    | otherwise = gcd b (fullMod a b)

-- Gets the public exponent for RSA key pair using seed primes p,q
getPublicExponent :: Integer -> Integer -> IO Integer
getPublicExponent p q =
    do
        e <- randomInteger 2 ((p - 1) * (q - 1) - 1)
        if gcd e ((p - 1) * (q - 1)) == 1
            then return e
            else getPublicExponent p q

-- Performs Euclids Extended Algorithm on a and b
eea :: Integer -> Integer -> (Integer, Integer)
eea a b = eeaH a b 0 1 b 1 0 a
eeaH a b s t r s' t' r' 
    | r == 0 = (s', t')
    | otherwise = eeaH a b (s' - q * s) (t' - q * t) (r' - q * r) s t r
    where
        q = quot r' r

-- Gets the private exponent for RSA using public exponent e and seed primes p,q
getPrivateExponent :: Integer -> Integer -> Integer -> IO Integer
getPrivateExponent e p q = 
        return (fullMod (fst (eea e ((p - 1) * (q - 1)))) 
          ((p - 1) * (q - 1)))

-- Generates public key pair (e,n') and private pair (d,n') with primes in the
-- range of m to n (inclusive) with accuracy 4^-k
getRSAKeyPairs :: Integer -> Integer -> Integer -> IO ((Integer, Integer), (Integer, Integer))
getRSAKeyPairs m n k =
    do
        p <- getRandomPrime m n k
        q <- getRandomPrime m n k
        e <- getPublicExponent p q
        d <- getPrivateExponent e p q
        return ((e, (p * q)), (d, (p * q)))
````

#### Encryption and Decryption ####
My last step was to write a method for encryption and decryption. One can call <i>getRSAKeyPairs</i> to get the key pairs and then use the following functions.
````haskell
-- Encrypts a message m using public key pair pbk=(e, n)
encrypt :: Integer -> (Integer, Integer) -> Integer
encrypt m (e, n) = (fullMod (m^e) n)

-- Decrypts a message c using private key pair prk=(d, n)
decrypt :: Integer -> (Integer, Integer) -> Integer
decrypt c (d, n) = (fullMod (c^d) n)
````

#### Lesson's Learned and Interesting Observations ####
All-together, my code ran fast and worked consistently. I only ran into issues when Haskell would time out when dealing with exponentiation on very large integers. Given that this code isn't meant to be used in a cryptographic setting, large numbers won't be necessary and thus this isn't much of a problem. A MUCH more intersting problem was the following idea illustrated in the code below:
````haskell
import System.Random
foo _ = 
    return (p, q)
    where
        p = randomRIO (1, 10)
        q = p
````
In many languages we would expect the resulting tuple <i>(p,q)</i> to contain two identical values because <i>p</i> is assigned some random value and <i>q</i> is then assigned the value of <i>p</i>. But, in Haskell this is not the case since Haskell uses lazy evaluation. In the code above when we say <i>q = p</i>, we actually let <i>q = randomRIO (1, 10)</i> instead of <i>p</i> because at this point in the code we are still making substitutings instead of evaluating expressions. Thus, when we go to return our tuple we actually have: <i>(randomRIO (1, 10), randomRIO (1, 10))</i>. Therefore, we will get two different values. This is different from languages such as Java or OCaml that use eager evaluation and thus the expression <i>p = randomRIO (1, 10)</i> would be evaluated before substituting in <i>p</i> for <i>q</i>.

##### Comments #####
Any comments on my Haskell code (style and method) would be very helpful!
