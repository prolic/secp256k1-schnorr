{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-|
Module      : Crypto.Schnorr
License     : MIT
Maintainer  : Sascha-Oliver Prolic <saschaprolic@googlemail.com>
Stability   : experimental
Portability : POSIX

Schnorr signatures from Bitcoin’s secp256k1 library.
-}
module Crypto.Schnorr
    ( Msg
    , SecKey
    , msg
    , secKey
    , getSecKey
    , getMsg
    , XOnlyPubKey
    , SchnorrSig
    , signMsgSchnorr
    , importSchnorrSig
    , importXOnlyPubKey
    , verifyMsgSchnorr


    , generateKeyPair
    , KeyPair(..)
    , derivePubKey
    , deriveXOnlyPubKey
    , generateSecretKey
    , hexToBytes
    ) where

import           Control.DeepSeq           (NFData)
import           Control.Monad             (replicateM, unless, (<=<))
import qualified Crypto.Hash.SHA256        as SHA256
import           Crypto.Random.DRBG
import           Crypto.Schnorr.Internal
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base16    as B16
import qualified Data.ByteString.Char8     as B8
import           Data.Either               (fromRight)
import           Data.Hashable             (Hashable (..))
import           Data.Maybe                (fromJust, fromMaybe, isJust)
--import           Data.Serialize            (Serialize (..), getByteString,
--                                            putByteString)
import Data.ByteString.UTF8 as BUTF8
import           Data.String               (IsString (..))
import           Data.String.Conversions   (ConvertibleStrings, cs)
import           Foreign                   (alloca, allocaBytes, free, mallocBytes,
                                            nullFunPtr, nullPtr, peek, poke, mallocForeignPtr,
                                            withForeignPtr)
import           Foreign.C.Types           (CInt(..))
import           GHC.Generics              (Generic)
import           System.IO.Unsafe          (unsafePerformIO)
import           Test.QuickCheck           (Arbitrary (..),
                                            arbitraryBoundedRandom, suchThat)
import           Text.Read                 (Lexeme (String), lexP, parens,
                                            pfail, readPrec)

newtype XOnlyPubKey = XOnlyPubKey { getXOnlyPubKey :: ByteString }
    deriving (Generic, NFData)
newtype SchnorrSig  = SchnorrSig  { getSchnorrSig  :: ByteString }
    deriving (Eq, Generic, NFData)
newtype PubKey      = PubKey      { getPubKey      :: ByteString }
    deriving (Eq, Generic, NFData)
newtype KeyPair     = KeyPair     { getKeyPair     :: ByteString }
    deriving (Eq, Generic, NFData)
newtype Msg         = Msg         { getMsg         :: ByteString }
    deriving (Eq, Generic, NFData)
newtype SecKey      = SecKey      { getSecKey      :: ByteString }
    deriving (Eq, Generic, NFData)

instance Eq XOnlyPubKey where
    (XOnlyPubKey a) == (XOnlyPubKey b) = unsafePerformIO $
        unsafeUseByteString a $ \(a_ptr, _) ->
        unsafeUseByteString b $ \(b_ptr, _) -> do
            ret <- xOnlyPubKeyCompare ctx a_ptr b_ptr
            return $ 0 == ret
{-
instance Serialize XOnlyPubKey where
    put (XOnlyPubKey bs) = putByteString bs
    get = XOnlyPubKey <$> getByteString 64

instance Serialize PubKey where
    put (PubKey bs) = putByteString bs
    get = PubKey <$> getByteString 64

instance Serialize SchnorrSig where
    put (SchnorrSig bs) = putByteString bs
    get = SchnorrSig <$> getByteString 64

instance Serialize Msg where
     put (Msg m) = putByteString m
     get = Msg <$> getByteString 32

instance Serialize SecKey where
    put (SecKey bs) = putByteString bs
    get = SecKey <$> getByteString 32
-}
instance Show SchnorrSig where
    showsPrec _ = shows . B16.encodeBase16 . getSchnorrSig

instance Read SchnorrSig where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ importSchnorrSig =<< decodeHex str

instance IsString SchnorrSig where
    fromString = fromMaybe e . (importSchnorrSig <=< decodeHex) where
        e = error "Could not decode Schnorr signature from hex string"

--instance Hashable SchnorrSig where
--    i `hashWithSalt` s = i `hashWithSalt` getSchnorrSig s

instance Show XOnlyPubKey where
    showsPrec _ (XOnlyPubKey p) = shows . B16.encodeBase16 . unsafePerformIO $ do
         unsafeUseByteString p $ \(p_ptr, _) -> do
             serialized <- mallocBytes 32
             ret <- schnorrPubKeySerialize ctx serialized p_ptr
             unless (isSuccess ret) $ do
                 free serialized
                 error "could not serialize x-only public key"
             out <- unsafePackByteString (serialized, 32)
             return out
             --return $ BUTF8.fromString "foobar"

instance Read XOnlyPubKey where
    readPrec = do
        String str <- lexP
        maybe pfail return $ importXOnlyPubKey =<< decodeHex str

instance IsString XOnlyPubKey where
    fromString = fromMaybe e . (importXOnlyPubKey <=< decodeHex) where
        e = error "Could not decode public key from hex string"

--instance Hashable XOnlyPubKey where
--    i `hashWithSalt` k = i `hashWithSalt` getXOnlyPubKey k

instance Read Msg where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ msg32 =<< decodeHex str

--instance Hashable Msg where
--    i `hashWithSalt` m = i `hashWithSalt` getMsg m

instance IsString Msg where
    fromString = fromMaybe e . (msg32 <=< decodeHex)  where
        e = error "Could not decode message from hex string"

instance Show Msg where
    showsPrec _ = shows . B16.encodeBase16 . getMsg

instance Read SecKey where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ secKey =<< decodeHex str

--instance Hashable SecKey where
--    i `hashWithSalt` k = i `hashWithSalt` getSecKey k

instance IsString SecKey where
    fromString = fromMaybe e . (secKey <=< decodeHex) where
        e = error "Colud not decode secret key from hex string"

instance Show SecKey where
    showsPrec _ = shows . B16.encodeBase16 . getSecKey

instance Show PubKey where
    showsPrec _ = shows . B16.encodeBase16 . getPubKey

hexToBytes :: String -> BS.ByteString
hexToBytes = fromRight undefined . B16.decodeBase16 . B8.pack

signMsgSchnorr :: SecKey -> Msg -> SchnorrSig
signMsgSchnorr (SecKey sec_key) (Msg m) = unsafePerformIO $
    unsafeUseByteString sec_key $ \(sec_key_ptr, _) ->
    -- enable this line for automatic hashing
    --unsafeUseByteString (SHA256.hash m) $ \(msg_ptr, _) -> do
    unsafeUseByteString m $ \(msg_ptr, _) -> do
    sig_ptr <- mallocBytes 64
    ret <- schnorrSign ctx sig_ptr msg_ptr sec_key_ptr nullFunPtr nullPtr
    unless (isSuccess ret) $ do
        free sig_ptr
        error "could not schnorr-sign message"
    SchnorrSig <$> unsafePackByteString (sig_ptr, 64)

importXOnlyPubKey :: ByteString -> Maybe XOnlyPubKey
importXOnlyPubKey bs
    | BS.length bs == 32 = unsafePerformIO $
        unsafeUseByteString bs $ \(input, len) -> do
        pub_key <- mallocBytes 64
        ret <- schnorrXOnlyPubKeyParse ctx pub_key input
        if isSuccess ret
            then do
                out <- unsafePackByteString (pub_key, 64)
                return $ Just $ XOnlyPubKey out
            else do
                return Nothing
    | otherwise = Nothing

importSchnorrSig :: ByteString -> Maybe SchnorrSig
importSchnorrSig bs
    | BS.length bs == 64 = Just $ SchnorrSig { getSchnorrSig = bs }
    | otherwise = Nothing

verifyMsgSchnorr :: XOnlyPubKey -> SchnorrSig -> Msg -> Bool
verifyMsgSchnorr (XOnlyPubKey p) (SchnorrSig s) (Msg m) = unsafePerformIO $
    unsafeUseByteString p $ \(pp, _) ->
    unsafeUseByteString s $ \(sp, _) ->
    unsafeUseByteString m $ \(mp, _) ->
    isSuccess <$> schnorrSignatureVerify ctx sp mp (fromIntegral $ BS.length m) pp

derivePubKey :: SecKey -> PubKey
derivePubKey (SecKey sec_key) = unsafePerformIO $
    unsafeUseByteString sec_key $ \(sec_key_ptr, _) -> do
    pub_key_ptr <- mallocBytes 64
    ret <- ecPubKeyCreate ctx pub_key_ptr sec_key_ptr
    unless (isSuccess ret) $ do
        free pub_key_ptr
        error "could not compute public key"
    PubKey <$> unsafePackByteString (pub_key_ptr, 64)

{-
start
-}
deriveXOnlyPubKey :: PubKey -> XOnlyPubKey
deriveXOnlyPubKey (PubKey bs) = unsafePerformIO $
    unsafeUseByteString bs $ \(pub_key_ptr, _) -> do
    x_only_pub_key <- mallocBytes 64
    ret <- xOnlyPubKeyFromPubKey ctx x_only_pub_key nullPtr pub_key_ptr
    if isSuccess ret
        then
            XOnlyPubKey <$> unsafePackByteString (x_only_pub_key, 64)
        else do
            free x_only_pub_key
            error "could not derive xonly pub key from pub key"
{-
deriveXOnlyPubKey (PubKey fk) = unsafePerformIO $ do
    unsafeUseByteString fk $ \(k, _) -> do
        fp <- mallocForeignPtr
        key <- peek k
        poke k key
        ret <- withForeignPtr fp $ \p -> xOnlyPubKeyFromPubKey ctx p nullPtr k
        if isSuccess ret
            then return $ key
            else error "could not derive xonly pub key"
-}
generateKeyPair :: IO KeyPair
generateKeyPair = do
    keypair <- mallocBytes 96
    sec_key <- mallocBytes 32
    ret <- keyPairCreate ctx keypair sec_key
    if isSuccess ret
        then do
            free sec_key
            out <- unsafePackByteString (keypair, 96)
            return $ KeyPair out
        else do
            free keypair
            free sec_key
            error "could not generate key pair"

{-- commented out
-- int secp256k1_keypair_create(const secp256k1_context* ctx, secp256k1_keypair *keypair, const unsigned char *seckey32) {
foreign import ccall unsafe
    "secp256k1.h secp256k1_keypair_create"
    keyPairCreate
    :: Ctx
    -> Ptr KeyPair96
    -> Ptr SecKey32

-- int secp256k1_keypair_sec(const secp256k1_context* ctx, unsigned char *seckey, const secp256k1_keypair *keypair) {
foreign import ccall safe
    "secp256k1.h secp256k1_keypair_sec"
    keyPairSecKey
    :: Ctx
    -> Ptr SecKey32
    -> Ptr KeyPair96
    -> IO Ret

-- int secp256k1_keypair_pub(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const secp256k1_keypair *keypair) {
foreign import ccall safe
    "secp256k1.h secp256k1_keypair_pub"
    keyPairPubKey
    :: Ctx
    -> Ptr PubKey64
    -> Ptr KeyPair96
    -> IO Ret

-- int secp256k1_keypair_xonly_pub(const secp256k1_context* ctx, secp256k1_xonly_pubkey *pubkey, int *pk_parity, const secp256k1_keypair *keypair) {
foreign import ccall safe
    "secp256k1.h secp256k1_keypair_xonly_pub"
    keyPairXOnlyPubKey
    :: Ctx
    -> Ptr PubKey64
    -> CInt
    -> Ptr KeyPair96
    -> IO Ret
-}
{-
end
-}

instance Arbitrary Msg where
    arbitrary = gen_msg
      where
        valid_bs = bs_gen `suchThat` isJust
        bs_gen = msg32 . BS.pack <$> replicateM 32 arbitraryBoundedRandom
        gen_msg = fromJust <$> valid_bs

instance Arbitrary SecKey where
    arbitrary = gen_key where
        valid_bs = bs_gen `suchThat` isJust
        bs_gen = secKey . BS.pack <$> replicateM 32 arbitraryBoundedRandom
        gen_key = fromJust <$> valid_bs

decodeHex :: ConvertibleStrings a ByteString => a -> Maybe ByteString
decodeHex str = case B16.decodeBase16 $ cs str of
  Right bs -> Just bs
  Left _ -> Nothing

-- | Import 32-byte 'ByteString' as 'Msg'.
msg32 :: ByteString -> Maybe Msg
msg32 bs
    | BS.length bs == 32 = Just (Msg bs)
    | otherwise = Nothing

-- | Import raw 'ByteString' as 'Msg'.
msg :: ByteString -> Msg
msg bs = Msg bs

-- | Import 32-byte 'ByteString' as 'SecKey'.
secKey :: ByteString -> Maybe SecKey
secKey bs
    | BS.length bs == 32 = unsafePerformIO $
        unsafeUseByteString bs $ \(ptr, _) -> do
                ret <- ecSecKeyVerify ctx ptr
                if ret == 1 then return $ Just $ SecKey bs
                else return Nothing
    | otherwise = Nothing

generateSecretKey :: IO SecKey
generateSecretKey = do
    gen <- newGenIO :: IO CtrDRBG
    let Right (randomBytes, newGen) = genBytes 32 gen
    unsafeUseByteString randomBytes $ \(sec_key_ptr, _) -> do
        ret <- ecSecKeyVerify ctx sec_key_ptr
        if isSuccess ret then do
            putStrLn "yes, valid sec key"
            return (SecKey randomBytes)
        else do
            putStrLn "next try generating"
            generateSecretKey
