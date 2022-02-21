module Main where

import Crypto.Hash.SHA256
import Crypto.Schnorr
import Crypto.Random.DRBG
import Data.ByteString.UTF8
import Data.Maybe

main :: IO ()
main = do
    putStrLn "Your secret key is:"
    --let kp = generateKeyPair
    --putStrLn $ show $ getKeyPair kp
    --gen <- newGenIO :: IO CtrDRBG
    --let Right (randomBytes, newGen) = genBytes 32 gen
    --putStrLn $ show randomBytes

    --let seckey = secKey randomBytes
    secKey <- generateSecretKey
    putStrLn $ show secKey
    putStrLn ""

    putStrLn "Your public key is:"
    let p = derivePubKey secKey
    putStrLn $ show p
    putStrLn ""

    putStrLn "Your x only pub key is:"
    let x = deriveXOnlyPubKey p
    putStrLn $ show x
    putStrLn ""
{-
    let raw_msg = "Hello, World!"
    let hash_msg = hash $ fromString raw_msg
    putStrLn "Test String:"
    putStrLn raw_msg
    putStrLn ""


    let message = msg hash_msg
    putStrLn "Hashed:"
    putStrLn $ show message
    putStrLn ""
    
    let signature = signMsgSchnorr secKey message
    putStrLn "Signature:"
    putStrLn $ show signature
    putStrLn ""

    let verified = verifyMsgSchnorr x signature (msg hash_msg)
    putStrLn "Verified:"
    case verified of
        True -> putStrLn "YES"
        False -> putStrLn "NO"

    putStrLn ""
    putStrLn "How was that?"
-}