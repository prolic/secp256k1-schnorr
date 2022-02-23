{-# LANGUAGE CPP #-}
module Crypto.SchnorrSpec (spec) where

import           Crypto.Hash.SHA256      (hash)
import           Crypto.Schnorr
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Base16  as B16
import qualified Data.ByteString.Char8   as B8
import           Data.Either             (fromRight)
import           Data.Maybe              (fromJust, fromMaybe, isNothing)
import           Data.String             (fromString)
import           Data.String.Conversions (cs)
import           System.IO.Unsafe        (unsafePerformIO)
import           Test.HUnit              (Assertion, assertEqual)
import           Test.Hspec
import           Test.QuickCheck

spec :: Spec
spec = do
    describe "schnorr (bip-340)" $ do
    {-
        it "validates test vector 0" $
            property bip340Vector0
    -}
        it "rejects test vector 5" $
            property $
            failingVectorToAssertion InvalidPubKey
              (
                hexToBytes "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
                hexToBytes "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
                hexToBytes "667c2f778e0616e611bd0c14b8a600c5884551701a949ef0ebfd72d452d64e844160bcfc3f466ecb8facd19ade57d8699d74e7207d78c6aedc3799b52a8e0598"
              )
        it "rejects test vector 6" $
            property $
            failingVectorToAssertion InvalidSig
              (
                hexToBytes "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
                hexToBytes "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
                hexToBytes "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9935554d1aa5f0374e5cdaacb3925035c7c169b27c4426df0a6b19af3baeab138"
              )
        it "signs and verifies a message" $
            property bip340SignAndVerify

data VectorError = InvalidPubKey | InvalidSig | InvalidMsg | InvalidSigFormat
  deriving (Eq, Show)

failingVectorToAssertion :: VectorError -> (BS.ByteString, BS.ByteString, BS.ByteString) -> Assertion
failingVectorToAssertion expectedFailure (pubBytes, msgBytes, sigBytes) =
    assertEqual ("expected error " <> show expectedFailure <> " occurs") (Left expectedFailure) computed
  where
    computed :: Either VectorError ()
    computed =
        let
            pubM = xOnlyPubKey pubBytes
            sigM = schnorrSig sigBytes
            msgM = msg $ msgBytes
        in
            case (pubM, sigM, msgM) of
                (Nothing, _, _) -> Left InvalidPubKey
                (_, Nothing, _) -> Left InvalidSigFormat
                (_, _, Nothing) -> Left InvalidMsg
                (Just pub, Just sig, Just msg) ->
                    if verifyMsgSchnorr pub sig msg
                        then Right ()
                        else Left InvalidSig

bip340Vector0 :: Assertion
bip340Vector0 =
  passingVectorToAssertion 0
    (
      BS.replicate 31 0 <> B8.pack ['\x01']
      , BS.replicate 32 0
      , hexToBytes "db46b5cdc554edbd7765611b75d7bdbc639cf538fb6e9ef04a61884b765343aae148954f27eb69291a9045862f8ae4fa53436c117e9397c70275d5398066d44b"
    )

-- Integer is BIP-340 vector test number
passingVectorToAssertion :: Integer -> (BS.ByteString, BS.ByteString, BS.ByteString) -> Assertion
passingVectorToAssertion idx (secBytes, msgBytes, sigBytes) =
    assertEqual ("BIP-340 test vector " <> show idx <> " signature matches") expectedSig computedSig
  where
    expectedSig :: Maybe SchnorrSig
    expectedSig = schnorrSig $ sigBytes
    computedSig :: Maybe SchnorrSig
    computedSig = do
        let sec = fromJust $ secKey secBytes
        let kp = keyPairFromSecKey sec
        msg <- msg $ msgBytes
        pure $ signMsgSchnorr kp msg

bip340SignAndVerify :: Assertion
bip340SignAndVerify = do
    assertEqual ("BIP-340 test sign and verify") True isVerified
  where
    isVerified = unsafePerformIO $ do
        kp <- generateKeyPair
        let xo = deriveXOnlyPubKey kp
        let raw_msg = "Hello, World!"
        let hash_msg = hash $ fromString raw_msg
        let message = fromJust $ msg hash_msg
        let signature = signMsgSchnorr kp message
        pure $ verifyMsgSchnorr xo signature message
