{-# LANGUAGE FlexibleContexts  #-}

{-|
Module      : Crypto.Schnorr
License     : MIT
Maintainer  : Sascha-Oliver Prolic <saschaprolic@googlemail.com>
Stability   : experimental
Portability : POSIX

Schnorr signatures from Bitcoin’s secp256k1 library.
-}
module Crypto.Schnorr
    -- * Messages
  ( Msg
  , msg
  , getMsg
  , exportMsg
  -- * Key Pairs
  , KeyPair
  , generateKeyPair
  , keypair
  , keyPairFromSecKey
  , combineKeyPair
  , getKeyPair
  , exportKeyPair
  -- * Secret Keys
  , SecKey
  , generateSecretKey
  , secKey
  , getSecKey
  , deriveSecKey
  , exportSecKey
  -- * Public Keys
  , PubKey
  , pubKey
  , XOnlyPubKey
  , xOnlyPubKey
  , getXOnlyPubKey
  , derivePubKey
  , deriveXOnlyPubKey
  , deriveXOnlyPubKeyFromPubKey
  , exportPubKey
  , exportXOnlyPubKey
  -- * Schnorr Signatures
  , SchnorrSig
  , schnorrSig
  , getSchnorrSig
  , exportSchnorrSig
  , signMsgSchnorr
  , verifyMsgSchnorr
  -- * Helpers
  , decodeHex
  , hexToBytes
  ) where

import           Control.Monad           (unless)
import qualified Crypto.Hash.SHA256      as SHA256
import           Crypto.Random.DRBG      (CtrDRBG, genBytes, newGen, newGenIO)
import           Crypto.Schnorr.Internal
import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Base16  as B16
import qualified Data.ByteString.Char8   as B8
import           Data.ByteString.UTF8    as BUTF8
import           Data.Either             (fromRight)
import           Data.String.Conversions (ConvertibleStrings, cs)
import           Data.Text               (unpack)
import           Foreign                 (free, mallocBytes, nullPtr)
import           System.IO.Unsafe        (unsafePerformIO)

newtype XOnlyPubKey =
  XOnlyPubKey
    { getXOnlyPubKey :: ByteString
    }

newtype SchnorrSig =
  SchnorrSig
    { getSchnorrSig :: ByteString
    }
  deriving (Eq)

newtype PubKey =
  PubKey
    { getPubKey :: ByteString
    }
  deriving (Eq)

newtype KeyPair =
  KeyPair
    { getKeyPair :: ByteString
    }
  deriving (Eq)

newtype Msg =
  Msg
    { getMsg :: ByteString
    }
  deriving (Eq)

newtype SecKey =
  SecKey
    { getSecKey :: ByteString
    }
  deriving (Eq)

showsEncoded = shows . B16.encodeBase16

instance Show KeyPair where
  showsPrec _ = showsEncoded . getKeyPair

instance Show Msg where
  showsPrec _ = showsEncoded . getMsg

instance Show PubKey where
  showsPrec _ = showsEncoded . getPubKey

instance Show SecKey where
  showsPrec _ = showsEncoded . getSecKey

instance Show SchnorrSig where
  showsPrec _ = showsEncoded . getSchnorrSig

instance Eq XOnlyPubKey where
  (XOnlyPubKey a) == (XOnlyPubKey b) =
    unsafePerformIO $
    unsafeUseByteString a $ \(a_ptr, _) ->
      unsafeUseByteString b $ \(b_ptr, _) -> do
        ret <- xOnlyPubKeyCompare ctx a_ptr b_ptr
        return $ 0 == ret

instance Show XOnlyPubKey where
  showsPrec _ (XOnlyPubKey p) =
    showsEncoded . unsafePerformIO $ do
      unsafeUseByteString p $ \(p_ptr, _) -> do
        serialized <- mallocBytes 32
        ret <- schnorrPubKeySerialize ctx serialized p_ptr
        unless (isSuccess ret) $ do
          free serialized
          error "could not serialize x-only public key"
        out <- unsafePackByteString (serialized, 32)
        return out

exportText :: ByteString -> String
exportText = unpack . B16.encodeBase16

exportKeyPair :: KeyPair -> String
exportKeyPair k = exportText $ getKeyPair k

exportMsg :: Msg -> String
exportMsg m = exportText $ getMsg m

exportPubKey :: PubKey -> String
exportPubKey p = exportText $ getPubKey p

exportSecKey :: SecKey -> String
exportSecKey s = exportText $ getSecKey s

exportSchnorrSig :: SchnorrSig -> String
exportSchnorrSig s = exportText $ getSchnorrSig s

exportXOnlyPubKey :: XOnlyPubKey -> String
exportXOnlyPubKey (XOnlyPubKey p) = unsafePerformIO $ do
         unsafeUseByteString p $ \(p_ptr, _) -> do
           serialized <- mallocBytes 32
           ret <- schnorrPubKeySerialize ctx serialized p_ptr
           unless (isSuccess ret) $ do
             free serialized
             error "could not serialize x-only public key"
           out <- unsafePackByteString (serialized, 32)
           return $ exportText out

-- | Signs a 32-byte 'Msg' using a 'KeyPair'
signMsgSchnorr :: KeyPair -> Msg -> SchnorrSig
signMsgSchnorr (KeyPair sec_key) (Msg m) =
  unsafePerformIO $
  unsafeUseByteString sec_key $ \(sec_key_ptr, _) ->
    unsafeUseByteString m $ \(msg_ptr, _) -> do
      sig_ptr <- mallocBytes 64
      ret <- schnorrSign ctx sig_ptr msg_ptr sec_key_ptr nullPtr
      unless (isSuccess ret) $ do
        free sig_ptr
        error "could not schnorr-sign message"
      SchnorrSig <$> unsafePackByteString (sig_ptr, 64)

-- | Verifies a schnorr signature.
verifyMsgSchnorr :: XOnlyPubKey -> SchnorrSig -> Msg -> Bool
verifyMsgSchnorr (XOnlyPubKey p) (SchnorrSig s) (Msg m) =
  unsafePerformIO $
  unsafeUseByteString p $ \(pp, _) ->
    unsafeUseByteString s $ \(sp, _) ->
      unsafeUseByteString m $ \(mp, _) ->
        isSuccess <$> schnorrSignatureVerify ctx sp mp 32 pp

-- | Generate a new 'KeyPair'.
generateKeyPair :: IO KeyPair
generateKeyPair = do
  gen <- newGenIO :: IO CtrDRBG
  let Right (randomBytes, newGen) = genBytes 32 gen
  unsafeUseByteString randomBytes $ \(sec_key, _) -> do
    keypair <- mallocBytes 96
    ret <- keyPairCreate ctx keypair sec_key
    if isSuccess ret
      then do
        out <- unsafePackByteString (keypair, 96)
        return $ KeyPair out
      else do
        free keypair
        error "could not generate key pair"

-- | Generate new 'SecKey'.
generateSecretKey :: IO SecKey
generateSecretKey = do
  gen <- newGenIO :: IO CtrDRBG
  let Right (randomBytes, newGen) = genBytes 32 gen
  unsafeUseByteString randomBytes $ \(sec_key_ptr, _) -> do
    ret <- ecSecKeyVerify ctx sec_key_ptr
    if isSuccess ret
      then return (SecKey randomBytes)
      else generateSecretKey

-- | Derive 'SecKey' from 'KeyPair'
deriveSecKey :: KeyPair -> SecKey
deriveSecKey (KeyPair kp) =
  unsafePerformIO $
  unsafeUseByteString kp $ \(kp_ptr, _) -> do
    sec_key_ptr <- mallocBytes 32
    ret <- keyPairSecKey ctx sec_key_ptr kp_ptr
    unless (isSuccess ret) $ do
      free sec_key_ptr
      error "could not compute public key"
    SecKey <$> unsafePackByteString (sec_key_ptr, 32)

-- | Derive 'PubKey' from 'SecKey'.
derivePubKey :: SecKey -> PubKey
derivePubKey (SecKey sec_key) =
  unsafePerformIO $
  unsafeUseByteString sec_key $ \(sec_key_ptr, _) -> do
    pub_key_ptr <- mallocBytes 64
    ret <- ecPubKeyCreate ctx pub_key_ptr sec_key_ptr
    unless (isSuccess ret) $ do
      free pub_key_ptr
      error "could not compute public key"
    PubKey <$> unsafePackByteString (pub_key_ptr, 64)

-- | Derive 'XOnlyPubKey' from 'KeyPair'.
deriveXOnlyPubKey :: KeyPair -> XOnlyPubKey
deriveXOnlyPubKey kp =
  deriveXOnlyPubKeyFromPubKey $ derivePubKey $ deriveSecKey kp

-- | Derive 'XOnlyPubKey' from 'PubKey'.
deriveXOnlyPubKeyFromPubKey :: PubKey -> XOnlyPubKey
deriveXOnlyPubKeyFromPubKey (PubKey bs) =
  unsafePerformIO $
  unsafeUseByteString bs $ \(pub_key_ptr, _) -> do
    x_only_pub_key <- mallocBytes 64
    ret <- xOnlyPubKeyFromPubKey ctx x_only_pub_key nullPtr pub_key_ptr
    if isSuccess ret
      then XOnlyPubKey <$> unsafePackByteString (x_only_pub_key, 64)
      else do
        free x_only_pub_key
        error "could not derive xonly pub key from pub key"

decodeHex :: ConvertibleStrings a ByteString => a -> Maybe ByteString
decodeHex str =
  case B16.decodeBase16 $ cs str of
    Right bs -> Just bs
    Left _   -> Nothing

-- | Parses a 'XOnlyPubKey' from a given 'ByteString'
xOnlyPubKey :: ByteString -> Maybe XOnlyPubKey
xOnlyPubKey bs
  | BS.length bs == 32 =
    unsafePerformIO $
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

-- | Parses a 'KeyPair' from a given 'ByteString'
keypair :: ByteString -> Maybe KeyPair
keypair bs
  | BS.length bs == 92 = Just $ KeyPair {getKeyPair = bs}
  | otherwise = Nothing

-- | Parses a 'SchnorrSig' from a given 'ByteString'
schnorrSig :: ByteString -> Maybe SchnorrSig
schnorrSig bs
  | BS.length bs == 64 = Just $ SchnorrSig {getSchnorrSig = bs}
  | otherwise = Nothing

-- | Import 32-byte 'ByteString' as 'Msg'.
msg :: ByteString -> Maybe Msg
msg bs
  | BS.length bs == 32 = Just $ Msg bs
  | otherwise = Nothing

-- | Import 32-byte 'ByteString' as 'SecKey'.
secKey :: ByteString -> Maybe SecKey
secKey bs
  | BS.length bs == 32 =
    unsafePerformIO $
    unsafeUseByteString bs $ \(ptr, _) -> do
      ret <- ecSecKeyVerify ctx ptr
      if ret == 1
        then return $ Just $ SecKey bs
        else return Nothing
  | otherwise = Nothing

-- | Import 64-byte 'ByteString' as 'PubKey'.
pubKey :: ByteString -> Maybe PubKey
pubKey bs
  | BS.length bs == 64 = Just $ PubKey bs
  | otherwise = Nothing

-- | Combines a 'SecKey' and 'PubKey' into a 'KeyPair'.
combineKeyPair :: SecKey -> PubKey -> KeyPair
combineKeyPair (SecKey s) (PubKey p) = KeyPair (s <> p)

-- | Computes a 'KeyPair' given a 'SecKey'.
keyPairFromSecKey :: SecKey -> KeyPair
keyPairFromSecKey (SecKey s) = KeyPair (s <> p)
  where
    (PubKey p) = derivePubKey (SecKey s)

-- | Helper function to convert a 'String' to 'ByteString'.
hexToBytes :: String -> ByteString
hexToBytes = fromRight undefined . B16.decodeBase16 . B8.pack
