module Main where

import           Crypto.Hash.SHA256
import           Crypto.Random.DRBG
import           Crypto.Schnorr
import qualified Data.ByteString      as BS
import           Data.ByteString.UTF8
import           Data.Maybe

main :: IO ()
main = do
  let myprivatekey =
        "abf73d29655bfec126485900970555148b639d1662de6fa6a97c1330d09df564"
  let mypublickey =
        "7b9fc46d4e24ffd256becf00cfd645bc3eeda2bfe3968cbbf29399e91d303da9"
  let mySec = fromJust $ secKey $ hexToBytes myprivatekey
  let derivedPub = derivePubKey mySec
  let myXPub = fromJust $ xOnlyPubKey $ hexToBytes mypublickey
  let myX = deriveXOnlyPubKey derivedPub
  keypair <- generateKeyPair
  let secKey = deriveSecKey keypair
  let p = derivePubKey secKey
  let x = deriveXOnlyPubKey p
  let ck = combineKeyPair secKey p
  let raw_msg = "Hello, World!"
  let hash_msg = hash $ fromString raw_msg
  let message = fromJust $ msg hash_msg
  let signature = signMsgSchnorr keypair message
  let verified = verifyMsgSchnorr x signature message
  let verified2 =
        verifyMsgSchnorr x signature (fromJust $ msg $ fromString raw_msg)
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
  putStrLn $
    if myX == myXPub
      then "YES"
      else "NO"
  putStrLn ""
  putStrLn "Your key pair is:"
  putStrLn $ show keypair
  putStrLn ""
  putStrLn "Your combined keypair is:"
  putStrLn $ show ck
  putStrLn ""
  putStrLn "EQ?"
  putStrLn $ show $ ck == keypair
  putStrLn ""
  putStrLn "Your secret key is:"
  putStrLn $ show secKey
  putStrLn ""
  putStrLn "Your public key is:"
  putStrLn $ show p
  putStrLn ""
  putStrLn "Your x only pub key is:"
  putStrLn $ show x
  putStrLn ""
  putStrLn "Test String:"
  putStrLn raw_msg
  putStrLn ""
  putStrLn "Hashed:"
  putStrLn $ show message
  putStrLn ""
  putStrLn "Signature:"
  putStrLn $ show signature
  putStrLn ""
  putStrLn "Verified:"
  case verified of
    True  -> putStrLn "YES"
    False -> putStrLn "NO"
  putStrLn "Verified2:"
  case verified of
    True  -> putStrLn "YES"
    False -> putStrLn "NO"
  putStrLn "generate sec key:"
  pppp <- generateSecretKey
  putStrLn $ show pppp
  putStrLn ""
  putStrLn "generated keypair:"
  let pk = keyPairFromSecKey pppp
  putStrLn $ show pk
  putStrLn ""
  putStrLn "generated xonly pub:"
  putStrLn $ show $ deriveXOnlyPubKey $ derivePubKey pppp
  putStrLn ""
  putStrLn "How was that?"
