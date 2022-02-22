{-|
Module      : Crypto.Schnorr.Internal
License     : MIT
Maintainer  : Sascha-Oliver Prolic <saschaprolic@googlemail.com>
Stability   : experimental
Portability : POSIX

Schnorr signatures from Bitcoin’s secp256k1 library.
-}
module Crypto.Schnorr.Internal where

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Unsafe as BU
import           Foreign                (Ptr, castPtr)
import           Foreign.C              (CInt (..), CSize (..), CString, CUChar,
                                         CUInt (..))
import           System.IO.Unsafe       (unsafePerformIO)

data XOnlyPubKey64

data SchnorrSig64

data LCtx

data PubKey64

data Msg32

data Sig64

data Compact64

data Seed32

data SecKey32

data KeyPair96

type CtxFlags = CUInt

type SerFlags = CUInt

type Ret = CInt

type NonceFun a
   = Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> Ptr a -> CInt -> IO CInt

type Ctx = Ptr LCtx

verify :: CtxFlags
verify = 0x0101

sign :: CtxFlags
sign = 0x0201

signVerify :: CtxFlags
signVerify = 0x0301

isSuccess :: Ret -> Bool
isSuccess 0 = False
isSuccess 1 = True
isSuccess n = error $ "isSuccess expected 0 or 1 but got " ++ show n

unsafeUseByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
unsafeUseByteString bs f =
  BU.unsafeUseAsCStringLen bs $ \(b, l) -> f (castPtr b, fromIntegral l)

useByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
useByteString bs f =
  BS.useAsCStringLen bs $ \(b, l) -> f (castPtr b, fromIntegral l)

unsafePackByteString :: (Ptr a, CSize) -> IO ByteString
unsafePackByteString (b, l) =
  BU.unsafePackMallocCStringLen (castPtr b, fromIntegral l)

packByteString :: (Ptr a, CSize) -> IO ByteString
packByteString (b, l) = BS.packCStringLen (castPtr b, fromIntegral l)

ctx :: Ctx
ctx = unsafePerformIO $ contextCreate signVerify

{-# NOINLINE ctx #-}
foreign import ccall safe "secp256k1.h secp256k1_context_create" contextCreate
  :: CtxFlags -> IO Ctx

foreign import ccall safe "secp256k1.h secp256k1_schnorrsig_sign" schnorrSign
  :: Ctx ->
  Ptr SchnorrSig64 -> Ptr Msg32 -> Ptr KeyPair96 -> Ptr a -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_schnorrsig_verify" schnorrSignatureVerify
  :: Ctx ->
  Ptr SchnorrSig64 ->
    Ptr CUChar -> CSize -> Ptr XOnlyPubKey64 -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_parse" schnorrXOnlyPubKeyParse
  :: Ctx -> Ptr XOnlyPubKey64 -> Ptr CUChar -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_serialize" schnorrPubKeySerialize
  :: Ctx -> Ptr CUChar -> Ptr XOnlyPubKey64 -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_cmp" xOnlyPubKeyCompare
  :: Ctx -> Ptr XOnlyPubKey64 -> Ptr XOnlyPubKey64 -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_verify" ecSecKeyVerify
  :: Ctx -> Ptr SecKey32 -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_xonly_pubkey_from_pubkey" xOnlyPubKeyFromPubKey
  :: Ctx -> Ptr XOnlyPubKey64 -> Ptr CInt -> Ptr PubKey64 -> IO Ret

foreign import ccall unsafe "secp256k1.h secp256k1_keypair_create" keyPairCreate
  :: Ctx -> Ptr KeyPair96 -> Ptr SecKey32 -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_keypair_sec" keyPairSecKey
  :: Ctx -> Ptr SecKey32 -> Ptr KeyPair96 -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_keypair_pub" keyPairPubKey
  :: Ctx -> Ptr PubKey64 -> Ptr KeyPair96 -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_keypair_xonly_pub" keyPairXOnlyPubKey
  :: Ctx -> Ptr PubKey64 -> CInt -> Ptr KeyPair96 -> IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_create" ecPubKeyCreate
  :: Ctx -> Ptr PubKey64 -> Ptr SecKey32 -> IO Ret
