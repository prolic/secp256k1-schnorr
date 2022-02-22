module Main where

import Crypto.Hash.SHA256
import Crypto.Schnorr
import Crypto.Random.DRBG
import Data.ByteString.UTF8
import Data.Maybe

main :: IO ()
main = do
    --generatedKeyPair <- generateKeyPair


    let myprivatekey = "abf73d29655bfec126485900970555148b639d1662de6fa6a97c1330d09df564"
    let mypublickey  = "7b9fc46d4e24ffd256becf00cfd645bc3eeda2bfe3968cbbf29399e91d303da9"

    let mySec = fromJust $ secKey $ hexToBytes myprivatekey
    let derivedPub = derivePubKey mySec

    let myXPub = fromJust $ importXOnlyPubKey $ hexToBytes myprivatekey
    let myX = deriveXOnlyPubKey derivedPub

    putStrLn "Imported key is:"
    putStrLn $ show mySec
    putStrLn ""

    putStrLn "your derived pub key is:"
    putStrLn $ show derivedPub
    putStrLn ""

    putStrLn "your imported x only pub key is:"
    putStrLn $ show myXPub
    putStrLn ""

    putStrLn "your derived x only pub key is:"
    putStrLn $ show myX
    putStrLn ""

    putStrLn "same????"
    putStrLn $ if myX == myXPub then "YES" else "NO"
    putStrLn ""

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


    let raw_msg = "Hello, World!"
    let hash_msg = hash $ fromString raw_msg
    putStrLn "Test String:"
    putStrLn raw_msg
    putStrLn ""


    let message = msg hash_msg
    putStrLn "Hashed:"
    putStrLn $ show message
    putStrLn ""

    --let signature = signMsgSchnorr secKey message
    let signature = signMsgSchnorr mySec message
    putStrLn "Signature:"
    putStrLn $ show signature
    putStrLn ""

    let verified = verifyMsgSchnorr myXPub signature message
    let verified2 = verifyMsgSchnorr myX signature message
    putStrLn "Verified:"
    case verified of
        True -> putStrLn "YES"
        False -> putStrLn "NO"
    putStrLn "Verified2:"
    case verified of
        True -> putStrLn "YES"
        False -> putStrLn "NO"

    putStrLn ""
    putStrLn "How was that?"

