{-# LANGUAGE CPP                        #-}
{-|
Module      : Crypto.Schnorr.Internal
License     : UNLICENSE
Maintainer  : Sascha-Oliver Prolic <saschaprolic@googlemail.com>
Stability   : experimental
Portability : POSIX

The API for this module may change at any time. This is an internal module only
exposed for hacking and experimentation.
-}
module Crypto.Schnorr.Internal where

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Unsafe as BU
import           Foreign                (FunPtr, Ptr, castPtr)
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
data Tweak32

type CtxFlags = CUInt
type SerFlags = CUInt
type Ret = CInt

type NonceFun a =
    Ptr CUChar ->
    Ptr CUChar ->
    Ptr CUChar ->
    Ptr CUChar ->
    Ptr a ->
    CInt ->
    IO CInt

type Ctx = Ptr LCtx

verify :: CtxFlags
verify = 0x0101

sign :: CtxFlags
sign = 0x0201

signVerify :: CtxFlags
signVerify = 0x0301

compressed :: SerFlags
compressed = 0x0102

uncompressed :: SerFlags
uncompressed = 0x0002

isSuccess :: Ret -> Bool
isSuccess 0 = False
isSuccess 1 = True
isSuccess n = error $ "isSuccess expected 0 or 1 but got " ++ show n

unsafeUseByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
unsafeUseByteString bs f =
    BU.unsafeUseAsCStringLen bs $ \(b, l) ->
    f (castPtr b, fromIntegral l)

useByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
useByteString bs f =
    BS.useAsCStringLen bs $ \(b, l) ->
    f (castPtr b, fromIntegral l)

unsafePackByteString :: (Ptr a, CSize) -> IO ByteString
unsafePackByteString (b, l) =
    BU.unsafePackMallocCStringLen (castPtr b, fromIntegral l)

packByteString :: (Ptr a, CSize) -> IO ByteString
packByteString (b, l) =
    BS.packCStringLen (castPtr b, fromIntegral l)

ctx :: Ctx
ctx = unsafePerformIO $ contextCreate signVerify
{-# NOINLINE ctx #-}

foreign import ccall safe
    "secp256k1.h secp256k1_context_create"
    contextCreate
    :: CtxFlags
    -> IO Ctx

foreign import ccall safe
    "secp256k1.h secp256k1_ec_privkey_negate"
    ecTweakNegate
    :: Ctx
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_xonly_pubkey_tweak_add"
    schnorrPubKeyTweakAdd
    :: Ctx
    -> Ptr XOnlyPubKey64
    -> Ptr CInt
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_xonly_seckey_tweak_add"
    schnorrSecKeyTweakAdd
    :: Ctx
    -> Ptr SecKey32
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_schnorrsig_serialize"
    signatureSerializeSchnorr
    :: Ctx
    -> Ptr CUChar -- ^ array for encoded signature, must be large enough
    -> Ptr SchnorrSig64
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_schnorrsig_sign"
    schnorrSign
    :: Ctx
    -> Ptr SchnorrSig64
    -> Ptr Msg32
    -> Ptr SecKey32
    -- TODO
    -- This is actually an "extended nonce function" in the C code. So this signature is broken,
    -- but we pass a nullFunPtr (and this module is Internal), so it doesn't matter right now.
    -> FunPtr (NonceFun a)
    -> Ptr a -- ^ nonce data
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_xonly_pubkey_tweak_test"
    xOnlyPubKeyTweakTest
    :: Ctx
    -> Ptr XOnlyPubKey64 -- output_pubkey
    -> CInt -- is_negated
    -> Ptr XOnlyPubKey64 -- internal_pubkey
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_xonly_pubkey_serialize"
    schnorrPubKeySerialize
    :: Ctx
    -> Ptr CUChar -- 32 bytes output buffer
    -> Ptr XOnlyPubKey64
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_schnorrsig_verify"
    schnorrSignatureVerify
    :: Ctx
    -> Ptr SchnorrSig64
    -> Ptr Msg32
    -> Ptr XOnlyPubKey64
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_schnorrsig_parse"
    schnorrSignatureParse
    :: Ctx
    -> Ptr SchnorrSig64 -- out
    -> Ptr CUChar -- in
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_xonly_pubkey_parse"
    schnorrXOnlyPubKeyParse
    :: Ctx
    -> Ptr XOnlyPubKey64 -- out
    -> Ptr CUChar -- in
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_xonly_pubkey_create"
    schnorrXOnlyPubKeyCreate
    :: Ctx
    -> Ptr XOnlyPubKey64
    -> Ptr SecKey32
    -> IO Ret
