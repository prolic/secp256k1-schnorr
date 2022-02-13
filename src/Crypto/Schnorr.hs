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
    , Tweak
    , SecKey
    , tweak
    , msg
    , secKey
    , getSecKey
    , getMsg
    , XOnlyPubKey
    , SchnorrSig
    , signMsgSchnorr
    , exportSchnorrSig
    , importSchnorrSig
    , exportXOnlyPubKey
    , importXOnlyPubKey
    , verifyMsgSchnorr
    , deriveXOnlyPubKey
    , schnorrTweakAddPubKey
    , schnorrTweakAddSecKey
    , testTweakXOnlyPubKey
    ) where

import           Control.DeepSeq           (NFData)
import           Control.Monad             (replicateM, unless, (<=<))
import           Crypto.Schnorr.Internal
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base16    as B16
import           Data.Hashable             (Hashable (..))
import           Data.Maybe                (fromJust, fromMaybe, isJust)
import           Data.Serialize            (Serialize (..), getByteString,
                                            putByteString)
import           Data.String               (IsString (..))
import           Data.String.Conversions   (ConvertibleStrings, cs)
import           Foreign                   (alloca, allocaBytes, free, mallocBytes,
                                            nullFunPtr, nullPtr, peek)
import           Foreign.C.Types           (CInt)
import           GHC.Generics              (Generic)
import           System.IO.Unsafe          (unsafePerformIO)
import           Test.QuickCheck           (Arbitrary (..),
                                            arbitraryBoundedRandom, suchThat)
import           Text.Read                 (Lexeme (String), lexP, parens,
                                            pfail, readPrec)

newtype XOnlyPubKey = XOnlyPubKey { getXOnlyPubKey :: ByteString }
    deriving (Eq, Generic, NFData)
newtype SchnorrSig = SchnorrSig   { getSchnorrSig  :: ByteString }
    deriving (Eq, Generic, NFData)

-- reimplemented those because of hidden constructor in base package
newtype Msg        = Msg        { getMsg        :: ByteString    }
    deriving (Eq, Generic, NFData)
newtype SecKey     = SecKey     { getSecKey     :: ByteString    }
    deriving (Eq, Generic, NFData)
newtype Tweak      = Tweak      { getTweak      :: ByteString    }
    deriving (Eq, Generic, NFData)

instance Serialize XOnlyPubKey where
    put (XOnlyPubKey bs) = putByteString bs
    get = XOnlyPubKey <$> getByteString 64

instance Serialize SchnorrSig where
    put (SchnorrSig bs) = putByteString bs
    get = SchnorrSig <$> getByteString 64

instance Serialize Msg where
     put (Msg m) = putByteString m
     get = Msg <$> getByteString 32

instance Serialize SecKey where
    put (SecKey bs) = putByteString bs
    get = SecKey <$> getByteString 32

instance Serialize Tweak where
    put (Tweak bs) = putByteString bs
    get = Tweak <$> getByteString 32

instance Show SchnorrSig where
    showsPrec _ = shows . B16.encodeBase16 . exportSchnorrSig

instance Read SchnorrSig where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ importSchnorrSig =<< decodeHex str

instance IsString SchnorrSig where
    fromString = fromMaybe e . (importSchnorrSig <=< decodeHex) where
        e = error "Could not decode Schnorr signature from hex string"

instance Hashable SchnorrSig where
    i `hashWithSalt` s = i `hashWithSalt` exportSchnorrSig s

instance Show XOnlyPubKey where
    showsPrec _ = shows . B16.encodeBase16 . exportXOnlyPubKey

instance Read XOnlyPubKey where
    readPrec = do
        String str <- lexP
        maybe pfail return $ importXOnlyPubKey =<< decodeHex str

instance IsString XOnlyPubKey where
    fromString = fromMaybe e . (importXOnlyPubKey <=< decodeHex) where
        e = error "Could not decode public key from hex string"

instance Hashable XOnlyPubKey where
    i `hashWithSalt` k = i `hashWithSalt` exportXOnlyPubKey k

instance Read Msg where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ msg =<< decodeHex str

instance Hashable Msg where
    i `hashWithSalt` m = i `hashWithSalt` getMsg m

instance IsString Msg where
    fromString = fromMaybe e . (msg <=< decodeHex)  where
        e = error "Could not decode message from hex string"

instance Show Msg where
    showsPrec _ = shows . B16.encodeBase16 . getMsg

instance Read SecKey where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ secKey =<< decodeHex str

instance Hashable SecKey where
    i `hashWithSalt` k = i `hashWithSalt` getSecKey k

instance IsString SecKey where
    fromString = fromMaybe e . (secKey <=< decodeHex) where
        e = error "Colud not decode secret key from hex string"

instance Show SecKey where
    showsPrec _ = shows . B16.encodeBase16 . getSecKey

instance Hashable Tweak where
    i `hashWithSalt` t = i `hashWithSalt` getTweak t

instance Read Tweak where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ tweak =<< decodeHex str

instance IsString Tweak where
    fromString = fromMaybe e . (tweak <=< decodeHex) where
        e = error "Could not decode tweak from hex string"

instance Show Tweak where
    showsPrec _ = shows . B16.encodeBase16 . getTweak

schnorrTweakAddPubKey :: XOnlyPubKey -> Tweak -> Maybe (XOnlyPubKey, CInt)
schnorrTweakAddPubKey (XOnlyPubKey fp) (Tweak ft) = unsafePerformIO $
    unsafeUseByteString new_bs $ \(pub_key_ptr, _) ->
    unsafeUseByteString ft $ \(tweak_ptr, _) -> do
    alloca $ \is_negated -> do
        ret <- schnorrPubKeyTweakAdd ctx pub_key_ptr is_negated tweak_ptr
        peeked_is_negated <- peek is_negated
        if isSuccess ret
            then return $ Just $ (XOnlyPubKey new_bs, peeked_is_negated)
            else return Nothing
    where
        new_bs = BS.copy fp

schnorrTweakAddSecKey :: SecKey -> Tweak -> Maybe SecKey
schnorrTweakAddSecKey (SecKey sec_key) (Tweak t) = unsafePerformIO $
    unsafeUseByteString new_bs $ \(sec_key_ptr, _) ->
    unsafeUseByteString t $ \(tweak_ptr, _) -> do
    ret <- schnorrSecKeyTweakAdd ctx sec_key_ptr tweak_ptr
    if isSuccess ret
        then return $ Just $ SecKey new_bs
        else return Nothing
  where
    new_bs = BS.copy sec_key

signMsgSchnorr :: SecKey -> Msg -> SchnorrSig
signMsgSchnorr (SecKey sec_key) (Msg m) = unsafePerformIO $
    unsafeUseByteString sec_key $ \(sec_key_ptr, _) ->
    unsafeUseByteString m $ \(msg_ptr, _) -> do
    sig_ptr <- mallocBytes 64
    ret <- schnorrSign ctx sig_ptr msg_ptr sec_key_ptr nullFunPtr nullPtr
    unless (isSuccess ret) $ do
        free sig_ptr
        error "could not schnorr-sign message"
    SchnorrSig <$> unsafePackByteString (sig_ptr, 64)

exportSchnorrSig :: SchnorrSig -> ByteString
exportSchnorrSig (SchnorrSig in_sig) = unsafePerformIO $
    unsafeUseByteString in_sig $ \(in_ptr, _) ->
    allocaBytes 64 $ \out_ptr -> do
    ret <- signatureSerializeSchnorr ctx out_ptr in_ptr
    unless (isSuccess ret) $ error "could not serialize schnorr signature"
    packByteString (out_ptr, 64)

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
    | BS.length bs == 64 = unsafePerformIO $
        unsafeUseByteString bs $ \(in_ptr, in_len) -> do
            fp <- mallocBytes 64
            ret <- schnorrSignatureParse ctx fp in_ptr
            if isSuccess ret
                then do
                    io <- unsafePackByteString (fp, 64)
                    return $ Just $ SchnorrSig io
                else return Nothing
    | otherwise = Nothing

verifyMsgSchnorr :: XOnlyPubKey -> SchnorrSig -> Msg -> Bool
verifyMsgSchnorr (XOnlyPubKey fp) (SchnorrSig fg) (Msg fm) = unsafePerformIO $
    unsafeUseByteString fp $ \(p, _) ->
    unsafeUseByteString fg $ \(g, _) ->
    unsafeUseByteString fm $ \(m, _) ->
    isSuccess <$> schnorrSignatureVerify ctx g m p

exportXOnlyPubKey :: XOnlyPubKey -> ByteString
exportXOnlyPubKey (XOnlyPubKey pub) = unsafePerformIO $
    unsafeUseByteString pub $ \(in_ptr, in_len) -> do
        allocaBytes 32 $ \o -> do
            ret <- schnorrPubKeySerialize ctx o in_ptr
            unless (isSuccess ret) $ error "could not serialize x-only public key"
            packByteString (in_ptr, 32)

deriveXOnlyPubKey :: SecKey -> XOnlyPubKey
deriveXOnlyPubKey (SecKey fk) = unsafePerformIO $
    unsafeUseByteString fk $ \(in_ptr, in_len) -> do
        fp <- mallocBytes 64
        ret <- schnorrXOnlyPubKeyCreate ctx fp in_ptr
        unless (isSuccess ret) $ error "could not derive x-only public key"
        io <- unsafePackByteString (fp, 64)
        return $ XOnlyPubKey io

testTweakXOnlyPubKey :: XOnlyPubKey -> CInt -> XOnlyPubKey -> Tweak -> Bool
testTweakXOnlyPubKey (XOnlyPubKey fp) is_negated (XOnlyPubKey internal) (Tweak ft) = unsafePerformIO $
    unsafeUseByteString fp $ \(p, _) ->
    unsafeUseByteString internal $ \(internalp, _) ->
    unsafeUseByteString ft $ \(t, _) -> do
        ret <- xOnlyPubKeyTweakTest ctx p is_negated internalp t
        return $ isSuccess ret

instance Arbitrary XOnlyPubKey where
    arbitrary = do
        key <- arbitrary
        return $ deriveXOnlyPubKey key

instance Arbitrary Msg where
    arbitrary = gen_msg
      where
        valid_bs = bs_gen `suchThat` isJust
        bs_gen = msg . BS.pack <$> replicateM 32 arbitraryBoundedRandom
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
msg :: ByteString -> Maybe Msg
msg bs
    | BS.length bs == 32 = Just (Msg bs)
    | otherwise = Nothing

-- | Import 32-byte 'ByteString' as 'SecKey'.
secKey :: ByteString -> Maybe SecKey
secKey bs
    | BS.length bs == 32 = Just (SecKey bs)
    | otherwise = Nothing

-- | 32-Byte 'ByteString' as 'Tweak'.
tweak :: ByteString -> Maybe Tweak
tweak bs
    | BS.length bs == 32 = Just (Tweak bs)
    | otherwise          = Nothing

tweakNegate :: Tweak -> Maybe Tweak
tweakNegate (Tweak t) = unsafePerformIO $
    unsafeUseByteString new $ \(out, _) -> do
    ret <- ecTweakNegate ctx out
    if isSuccess ret
        then return (Just (Tweak new))
        else return Nothing
  where
    new = BS.copy t
