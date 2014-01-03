import System.Random

-- TO USE: 
-- Call getRSAKeyPairs to get the public and private key pair, respectively
-- Use encrypt and decrypt accordingly

-- Performs "a mod b" with support for a negative first argument, that is
-- (-3 mod 4) will evaluate to 1 instead of staying at -3 as `mod` would do
fullMod :: Integer -> Integer -> Integer
fullMod a b
    | a >= 0 = a `mod` b
    | otherwise = fullMod (a + b) b

-- Uses System.Random to get a random Integer between m and n inclusive
randomInteger :: Integer -> Integer -> IO Integer
randomInteger m n = randomRIO (m, n)

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

-- Used to compute d*2^s=n-1 where d is odd and returns (d, s)
getRabinFactors :: Integer -> (Integer, Integer)
getRabinFactors n = getRabinFactorsH n (n - 1) 0
getRabinFactorsH n d s
    | (fullMod d 2 == 1) = (d, s)
    | otherwise = getRabinFactorsH n (quot d 2) (s + 1)

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

-- Generates a random prime using Miller-Rabin with probability 4^-k
getRandomPrime :: Integer -> Integer -> Integer -> IO Integer
getRandomPrime m n k = 
    do
        x <- randomInteger m n
        r <- rabinTest x k
        if r 
            then return x
            else getRandomPrime m n k

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

-- Encrypts a message m using public key pair pbk=(e, n)
encrypt :: Integer -> (Integer, Integer) -> Integer
encrypt m (e, n) = (fullMod (m^e) n)

-- Decrypts a message c using private key pair prk=(d, n)
decrypt :: Integer -> (Integer, Integer) -> Integer
decrypt c (d, n) = (fullMod (c^d) n)

-- Tests above encryption system for functionality
rsaTest mes m n k =
    do
        rsa <- getRSAKeyPairs m n k
        return (mes == decrypt (encrypt mes (fst rsa)) (snd rsa))