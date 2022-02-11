{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-|
Module      : Crypto.Secp256k1
License     : UNLICENSE
Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
Stability   : experimental
Portability : POSIX

Crytpographic functions from Bitcoin’s secp256k1 library.
-}
module Crypto.Secp256k1
    ( -- * Messages
      Msg
    , msg
    , getMsg

    -- * Secret Keys
    , SecKey
    , secKey
    , getSecKey
    , derivePubKey

    -- * Public Keys
    , PubKey
    , importPubKey
    , exportPubKey

    -- * Signatures
    , Sig
    , signMsg
    , verifySig
    , normalizeSig
    -- ** DER
    , importSig
    , exportSig
    -- ** Compact
    , CompactSig
    , getCompactSig
    , compactSig
    , exportCompactSig
    , importCompactSig
#ifdef RECOVERY
    -- ** Recovery
    , RecSig
    , CompactRecSig(..)
    , importCompactRecSig
    , exportCompactRecSig
    , convertRecSig
    , signRecMsg
    , recover
#endif

    -- * Addition & Multiplication
    , Tweak
    , tweak
    , getTweak
    , tweakAddSecKey
    , tweakMulSecKey
    , tweakAddPubKey
    , tweakMulPubKey
    , combinePubKeys
#ifdef NEGATE
    , tweakNegate
#endif

#ifdef ECDH
    -- * Diffie Hellman
    , ecdh
#endif

#ifdef SCHNORR
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
#endif
    ) where

import           Control.DeepSeq           (NFData)
import           Control.Monad             (replicateM, unless, (<=<))
import           Crypto.Secp256k1.Internal
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base16    as B16
import           Data.Hashable             (Hashable (..))
import           Data.Maybe                (fromJust, fromMaybe, isJust)
import           Data.Serialize            (Serialize (..), getByteString,
                                            putByteString)
import           Data.String               (IsString (..))
import           Data.String.Conversions   (ConvertibleStrings, cs)
import           Foreign                   (alloca, allocaArray, allocaBytes,
                                            free, mallocBytes, nullFunPtr,
                                            nullPtr, peek, poke, pokeArray)
import           GHC.Generics              (Generic)
import           System.IO.Unsafe          (unsafePerformIO)
import           Test.QuickCheck           (Arbitrary (..),
                                            arbitraryBoundedRandom, suchThat)
import           Text.Read                 (Lexeme (String), lexP, parens,
                                            pfail, readPrec)

newtype PubKey     = PubKey     { getPubKey     :: ByteString    }
    deriving (Eq, Generic, NFData)
newtype Msg        = Msg        { getMsg        :: ByteString    }
    deriving (Eq, Generic, NFData)
newtype Sig        = Sig        { getSig        :: ByteString    }
    deriving (Eq, Generic, NFData)
newtype SecKey     = SecKey     { getSecKey     :: ByteString    }
    deriving (Eq, Generic, NFData)
newtype Tweak      = Tweak      { getTweak      :: ByteString    }
    deriving (Eq, Generic, NFData)
newtype CompactSig = CompactSig { getCompactSig :: ByteString    }
    deriving (Eq, Generic, NFData)

instance Serialize PubKey where
    put (PubKey bs) = putByteString bs
    get = PubKey <$> getByteString 64

instance Serialize Msg where
    put (Msg m) = putByteString m
    get = Msg <$> getByteString 32

instance Serialize Sig where
    put (Sig bs) = putByteString bs
    get = Sig <$> getByteString 64

instance Serialize SecKey where
    put (SecKey bs) = putByteString bs
    get = SecKey <$> getByteString 32

instance Serialize Tweak where
    put (Tweak bs) = putByteString bs
    get = Tweak <$> getByteString 32

instance Serialize CompactSig where
    put (CompactSig bs) = putByteString bs
    get = CompactSig <$> getByteString 64

#ifdef SCHNORR
newtype XOnlyPubKey = XOnlyPubKey { getXOnlyPubKey :: ByteString }
    deriving (Eq, Generic, NFData)
newtype SchnorrSig = SchnorrSig   { getSchnorrSig  :: ByteString }
    deriving (Eq, Generic, NFData)

instance Serialize XOnlyPubKey where
    put (XOnlyPubKey bs) = putByteString bs
    get = XOnlyPubKey <$> getByteString 64

instance Serialize SchnorrSig where
    put (SchnorrSig bs) = putByteString bs
    get = SchnorrSig <$> getByteString 64
#endif

decodeHex :: ConvertibleStrings a ByteString => a -> Maybe ByteString
decodeHex str = case B16.decodeBase16 $ cs str of
  Right bs -> Just bs
  Left _ -> Nothing

instance Read PubKey where
    readPrec = do
        String str <- lexP
        maybe pfail return $ importPubKey =<< decodeHex str

instance Hashable PubKey where
    i `hashWithSalt` k = i `hashWithSalt` exportPubKey True k

instance IsString PubKey where
    fromString = fromMaybe e . (importPubKey <=< decodeHex) where
        e = error "Could not decode public key from hex string"

instance Show PubKey where
    showsPrec _ = shows . B16.encodeBase16 . exportPubKey True

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

instance Read Sig where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ importSig =<< decodeHex str

instance IsString Sig where
    fromString = fromMaybe e . (importSig <=< decodeHex) where
        e = error "Could not decode signature from hex string"

instance Hashable Sig where
    i `hashWithSalt` s = i `hashWithSalt` exportSig s

instance Show Sig where
    showsPrec _ = shows . B16.encodeBase16 . exportSig

#ifdef RECOVERY
recSigFromString :: String -> Maybe RecSig
recSigFromString str = do
    bs <- decodeHex str
    rs <- either (const Nothing) Just $ decode bs
    importCompactRecSig rs

instance Hashable RecSig where
    i `hashWithSalt` s = i `hashWithSalt` encode (exportCompactRecSig s)

instance Read RecSig where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ recSigFromString str

instance IsString RecSig where
    fromString = fromMaybe e . recSigFromString
      where
        e = error "Could not decode signature from hex string"

instance Show RecSig where
    showsPrec _ = shows . B16.encode . encode . exportCompactRecSig
#endif

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

#ifdef SCHNORR
instance NFData SchnorrSig where
    rnf (SchnorrSig p) = p `seq` ()

instance Show SchnorrSig where
    showsPrec _ = shows . B16.encode . exportSchnorrSig

instance Read SchnorrSig where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ importSchnorrSig =<< decodeHex str

instance Eq SchnorrSig where
    fg1 == fg2 = exportSchnorrSig fg1 == exportSchnorrSig fg2

instance IsString SchnorrSig where
    fromString = fromMaybe e . (importSchnorrSig <=< decodeHex) where
        e = error "Could not decode Schnorr signature from hex string"

instance Hashable SchnorrSig where
    i `hashWithSalt` s = i `hashWithSalt` exportSchnorrSig s

instance NFData XOnlyPubKey where
    rnf (XOnlyPubKey p) = p `seq` ()

instance Show XOnlyPubKey where
    showsPrec _ = shows . B16.encode . exportXOnlyPubKey

instance Read XOnlyPubKey where
    readPrec = do
        String str <- lexP
        maybe pfail return $ importXOnlyPubKey =<< decodeHex str

instance Eq XOnlyPubKey where
    fp1 == fp2 = getXOnlyPubKey fp1 == getXOnlyPubKey fp2

instance IsString XOnlyPubKey where
    fromString = fromMaybe e . (importXOnlyPubKey <=< decodeHex) where
        e = error "Could not decode public key from hex string"

instance Hashable XOnlyPubKey where
    i `hashWithSalt` k = i `hashWithSalt` exportXOnlyPubKey k
#endif

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

compactSig :: ByteString -> Maybe CompactSig
compactSig bs
    | BS.length bs == 64 = Just (CompactSig bs)
    | otherwise = Nothing

-- | Convert signature to a normalized lower-S form. 'Nothing' indicates that it
-- was already normal.
normalizeSig :: Sig -> Maybe Sig
normalizeSig (Sig sig) = unsafePerformIO $
    unsafeUseByteString sig $ \(sig_in, _) -> do
    sig_out <- mallocBytes 64
    ret <- ecdsaSignatureNormalize ctx sig_out sig_in
    if isSuccess ret
        then do
            bs <- unsafePackByteString (sig_out, 64)
            return (Just (Sig bs))
        else do
            free sig_out
            return Nothing

-- | 32-Byte 'ByteString' as 'Tweak'.
tweak :: ByteString -> Maybe Tweak
tweak bs
    | BS.length bs == 32 = Just (Tweak bs)
    | otherwise          = Nothing

-- | Import DER-encoded public key.
importPubKey :: ByteString -> Maybe PubKey
importPubKey bs
  | BS.null bs = Nothing
  | otherwise = unsafePerformIO $
    unsafeUseByteString bs $ \(input, len) -> do
    pub_key <- mallocBytes 64
    ret <- ecPubKeyParse ctx pub_key input len
    if isSuccess ret
        then do
            out <- unsafePackByteString (pub_key, 64)
            return (Just (PubKey out))
        else do
            free pub_key
            return Nothing

-- | Encode public key as DER. First argument 'True' for compressed output.
exportPubKey :: Bool -> PubKey -> ByteString
exportPubKey compress (PubKey in_bs) = unsafePerformIO $
    unsafeUseByteString in_bs $ \(in_ptr, _) ->
    alloca $ \len_ptr ->
    allocaBytes len $ \out_ptr -> do
    poke len_ptr $ fromIntegral len
    ret <- ecPubKeySerialize ctx out_ptr len_ptr in_ptr flags
    unless (isSuccess ret) $ error "could not serialize public key"
    final_len <- peek len_ptr
    packByteString (out_ptr, final_len)
  where
    len   = if compress then 33 else 65
    flags = if compress then compressed else uncompressed

exportCompactSig :: Sig -> CompactSig
exportCompactSig (Sig sig_bs) = unsafePerformIO $
    unsafeUseByteString sig_bs $ \(sig_ptr, _) -> do
    out_ptr <- mallocBytes 64
    ret <- ecdsaSignatureSerializeCompact ctx out_ptr sig_ptr
    unless (isSuccess ret) $ do
        free out_ptr
        error "Could not obtain compact signature"
    out_bs <- unsafePackByteString (out_ptr, 64)
    return $ CompactSig out_bs

importCompactSig :: CompactSig -> Maybe Sig
importCompactSig (CompactSig compact_sig) = unsafePerformIO $
    unsafeUseByteString compact_sig $ \(compact_ptr, _) -> do
    out_sig <- mallocBytes 64
    ret <- ecdsaSignatureParseCompact ctx out_sig compact_ptr
    if isSuccess ret
        then do
            out_bs <- unsafePackByteString (out_sig, 64)
            return (Just (Sig out_bs))
        else do
            free out_sig
            return Nothing

-- | Import DER-encoded signature.
importSig :: ByteString -> Maybe Sig
importSig bs
  | BS.null bs = Nothing
  | otherwise = unsafePerformIO $
    unsafeUseByteString bs $ \(in_ptr, in_len) -> do
    out_sig <- mallocBytes 64
    ret <- ecdsaSignatureParseDer ctx out_sig in_ptr in_len
    if isSuccess ret
        then do
            out_bs <- unsafePackByteString (out_sig, 64)
            return (Just (Sig out_bs))
        else do
            free out_sig
            return Nothing

-- | Encode signature as strict DER.
exportSig :: Sig -> ByteString
exportSig (Sig in_sig) = unsafePerformIO $
    unsafeUseByteString in_sig $ \(in_ptr, _) ->
    alloca $ \out_len ->
    allocaBytes 72 $ \out_ptr -> do
    poke out_len 72
    ret <- ecdsaSignatureSerializeDer ctx out_ptr out_len in_ptr
    unless (isSuccess ret) $ error "could not serialize signature"
    final_len <- peek out_len
    packByteString (out_ptr, final_len)

-- | Verify message signature. 'True' means that the signature is correct.
verifySig :: PubKey -> Sig -> Msg -> Bool
verifySig (PubKey pub_key) (Sig sig) (Msg m) = unsafePerformIO $
    unsafeUseByteString pub_key $ \(pub_key_ptr, _) ->
    unsafeUseByteString sig $ \(sig_ptr, _) ->
    unsafeUseByteString m $ \(msg_ptr, _) ->
    isSuccess <$> ecdsaVerify ctx sig_ptr msg_ptr pub_key_ptr

signMsg :: SecKey -> Msg -> Sig
signMsg (SecKey sec_key) (Msg m) = unsafePerformIO $
    unsafeUseByteString sec_key $ \(sec_key_ptr, _) ->
    unsafeUseByteString m $ \(msg_ptr, _) -> do
    sig_ptr <- mallocBytes 64
    ret <- ecdsaSign ctx sig_ptr msg_ptr sec_key_ptr nullFunPtr nullPtr
    unless (isSuccess ret) $ do
        free sig_ptr
        error "could not sign message"
    Sig <$> unsafePackByteString (sig_ptr, 64)

derivePubKey :: SecKey -> PubKey
derivePubKey (SecKey sec_key) = unsafePerformIO $
    unsafeUseByteString sec_key $ \(sec_key_ptr, _) -> do
    pub_key_ptr <- mallocBytes 64
    ret <- ecPubKeyCreate ctx pub_key_ptr sec_key_ptr
    unless (isSuccess ret) $ do
        free pub_key_ptr
        error "could not compute public key"
    PubKey <$> unsafePackByteString (pub_key_ptr, 64)


-- | Add tweak to secret key.
tweakAddSecKey :: SecKey -> Tweak -> Maybe SecKey
tweakAddSecKey (SecKey sec_key) (Tweak t) = unsafePerformIO $
    unsafeUseByteString new_bs $ \(sec_key_ptr, _) ->
    unsafeUseByteString t $ \(tweak_ptr, _) -> do
    ret <- ecSecKeyTweakAdd ctx sec_key_ptr tweak_ptr
    if isSuccess ret
        then return (Just (SecKey new_bs))
        else return Nothing
  where
    new_bs = BS.copy sec_key

-- | Multiply secret key by tweak.
tweakMulSecKey :: SecKey -> Tweak -> Maybe SecKey
tweakMulSecKey (SecKey sec_key) (Tweak t) = unsafePerformIO $
    unsafeUseByteString new_bs $ \(sec_key_ptr, _) ->
    unsafeUseByteString t $ \(tweak_ptr, _) -> do
    ret <- ecSecKeyTweakMul ctx sec_key_ptr tweak_ptr
    if isSuccess ret
        then return (Just (SecKey new_bs))
        else return Nothing
  where
    new_bs = BS.copy sec_key

-- | Add tweak to public key. Tweak is multiplied first by G to obtain a point.
tweakAddPubKey :: PubKey -> Tweak -> Maybe PubKey
tweakAddPubKey (PubKey pub_key) (Tweak t) = unsafePerformIO $
    unsafeUseByteString new_bs $ \(pub_key_ptr, _) ->
    unsafeUseByteString t $ \(tweak_ptr, _) -> do
    ret <- ecPubKeyTweakAdd ctx pub_key_ptr tweak_ptr
    if isSuccess ret
        then return (Just (PubKey new_bs))
        else return Nothing
  where
    new_bs = BS.copy pub_key

-- | Multiply public key by tweak. Tweak is multiplied first by G to obtain a
-- point.
tweakMulPubKey :: PubKey -> Tweak -> Maybe PubKey
tweakMulPubKey (PubKey pub_key) (Tweak t) = unsafePerformIO $
    unsafeUseByteString new_bs $ \(pub_key_ptr, _) ->
    unsafeUseByteString t $ \(tweak_ptr, _) -> do
    ret <- ecPubKeyTweakMul ctx pub_key_ptr tweak_ptr
    if isSuccess ret
        then return (Just (PubKey new_bs))
        else return Nothing
  where
    new_bs = BS.copy pub_key

-- | Add multiple public keys together.
combinePubKeys :: [PubKey] -> Maybe PubKey
combinePubKeys [] = Nothing
combinePubKeys pubs = unsafePerformIO $
    pointers [] pubs $ \ps ->
    allocaArray (length ps) $ \a -> do
    out <- mallocBytes 64
    pokeArray a ps
    ret <- ecPubKeyCombine ctx out a (fromIntegral $ length ps)
    if isSuccess ret
        then do
            bs <- unsafePackByteString (out, 64)
            return (Just (PubKey bs))
        else do
            free out
            return Nothing
  where
    pointers ps [] f = f ps
    pointers ps (PubKey pub_key : pub_keys) f =
        unsafeUseByteString pub_key $ \(p, _) ->
        pointers (p : ps) pub_keys f

#ifdef RECOVERY
-- | Parse a compact ECDSA signature (64 bytes + recovery id).
importCompactRecSig :: CompactRecSig -> Maybe RecSig
importCompactRecSig cr =
  if getCompactRecSigV cr `notElem` [0,1,2,3]
  then Nothing
  else withContext $ \ctx -> alloca $ \pc -> do
    let
      c = CompactSig (getCompactRecSigR cr) (getCompactRecSigS cr)
      recid = fromIntegral $ getCompactRecSigV cr
    poke pc c
    fg <- mallocForeignPtr
    ret <- withForeignPtr fg $ \pg ->
        ecdsaRecoverableSignatureParseCompact ctx pg pc recid
    if isSuccess ret then return $ Just $ RecSig fg else return Nothing

-- | Serialize an ECDSA signature in compact format (64 bytes + recovery id).
exportCompactRecSig :: RecSig -> CompactRecSig
exportCompactRecSig (RecSig fg) = withContext $ \ctx ->
    withForeignPtr fg $ \pg -> alloca $ \pc -> alloca $ \pr -> do
        ret <- ecdsaRecoverableSignatureSerializeCompact ctx pc pr pg
        unless (isSuccess ret) $ error "Could not obtain compact signature"
        CompactSig r s <- peek pc
        v <- fromIntegral <$> peek pr
        return $ CompactRecSig r s v

-- | Convert a recoverable signature into a normal signature.
convertRecSig :: RecSig -> Sig
convertRecSig (RecSig frg) = withContext $ \ctx ->
    withForeignPtr frg $ \prg -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \pg ->
            ecdsaRecoverableSignatureConvert ctx pg prg
        unless (isSuccess ret) $
            error "Could not convert a recoverable signature"
        return $ Sig fg

-- | Create a recoverable ECDSA signature.
signRecMsg :: SecKey -> Msg -> RecSig
signRecMsg (SecKey fk) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr fm $ \m -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g ->
            ecdsaSignRecoverable ctx g m k nullPtr nullPtr
        unless (isSuccess ret) $ error "could not sign message"
        return $ RecSig fg

-- | Recover an ECDSA public key from a signature.
recover :: RecSig -> Msg -> Maybe PubKey
recover (RecSig frg) (Msg fm) = withContext $ \ctx ->
    withForeignPtr frg $ \prg -> withForeignPtr fm $ \pm -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \pp -> ecdsaRecover ctx pp prg pm
        if isSuccess ret then return $ Just $ PubKey fp else return Nothing
#endif

#ifdef NEGATE
tweakNegate :: Tweak -> Maybe Tweak
tweakNegate (Tweak t) = unsafePerformIO $
    unsafeUseByteString new $ \(out, _) -> do
    ret <- ecTweakNegate ctx out
    if isSuccess ret
        then return (Just (Tweak new))
        else return Nothing
  where
    new = BS.copy t
#endif

#ifdef ECDH
-- | Compute Diffie-Hellman secret.
ecdh :: PubKey -> SecKey -> ByteString
ecdh (PubKey pk) (SecKey sk) = withContext $ \ctx ->
    withForeignPtr pk $ \pkPtr -> withForeignPtr sk $ \skPtr ->
        allocaBytes size $ \o -> do
            ret <- ecEcdh ctx o pkPtr skPtr nullPtr nullPtr
            unless (isSuccess ret) $ error "ecdh failed"
            packByteString (o, size)
  where
    size :: Integral a => a
    size = 32
#endif

#ifdef SCHNORR
-- | Add tweak to public key. Tweak is multiplied first by G to obtain a point.
schnorrTweakAddPubKey :: XOnlyPubKey -> Tweak -> Maybe (XOnlyPubKey, CInt)
{- remove this all
schnorrTweakAddPubKey (XOnlyPubKey fp) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr ft $ \t -> alloca $ \is_negated -> do
        fp' <- mallocForeignPtr
        ret <- withForeignPtr fp' $ \p' -> do
            pub <- peek p
            poke p' pub
            schnorrPubKeyTweakAdd ctx p' is_negated t
        peeked_is_negated <- peek is_negated
        if isSuccess ret then return $ Just $ (XOnlyPubKey fp', peeked_is_negated) else return Nothing
-}
schnorrTweakAddPubKey (XOnlyPubKey pub_key) (Tweak t) = unsafePerformIO $
    unsafeUseByteString new_bs $ \(pub_key_ptr, _) ->
    unsafeUseByteString t $ \(tweak_ptr, _) -> do
    ret <- schnorrPubKeyTweakAdd ctx pub_key_ptr tweak_ptr
    if isSuccess ret
        then return (Just (PubKey new_bs))
        else return Nothing
  where
    new_bs = BS.copy pub_key


-- | Add tweak to secret key.
schnorrTweakAddSecKey :: SecKey -> Tweak -> Maybe SecKey
{- remove this all
schnorrTweakAddSecKey (SecKey fk) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr ft $ \t -> do
        fk' <- mallocForeignPtr
        ret <- withForeignPtr fk' $ \k' ->  do
            key <- peek k
            poke k' key
            schnorrSecKeyTweakAdd ctx k' t
        if isSuccess ret then return $ Just $ SecKey fk' else return Nothing
-}
schnorrTweakAddSecKey (SecKey sec_key) (Tweak t) = unsafePerformIO $
    unsafeUseByteString new_bs $ \(sec_key_ptr, _) ->
    unsafeUseByteString t $ \(tweak_ptr, _) -> do
    ret <- schnorrSecKeyTweakAdd ctx sec_key_ptr tweak_ptr
    if isSuccess ret
        then return (Just (SecKey new_bs))
        else return Nothing
  where
    new_bs = BS.copy sec_key

signMsgSchnorr :: SecKey -> Msg -> SchnorrSig
{- remove this all
signMsgSchnorr (SecKey fk) (Msg fm) =
  withContext $ \ctx ->
    withForeignPtr fk $ \k ->
      withForeignPtr fm $ \m -> do
        fg <- mallocForeignPtr
        ret <-
          withForeignPtr fg $ \g ->
            schnorrSign ctx g m k nullPtr nullPtr
        unless (isSuccess ret) $ error "could not schnorr-sign message"
        return $ SchnorrSig fg
-}
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
{- remove this all
exportSchnorrSig (SchnorrSig fg) = withContext $ \ctx ->
    withForeignPtr fg $ \g -> allocaBytes 64 $ \o -> do
        ret <- signatureSerializeSchnorr ctx o g
        unless (isSuccess ret) $ error "could not serialize schnorr signature"
        packByteString (o, 64)
-}
exportSchnorrSig (SchnorrSig in_sig) = unsafePerformIO $
    unsafeUseByteString in_sig $ \(in_ptr, _) ->
    alloca $ \out_len ->
    allocaBytes 64 $ \out_ptr -> do
    poke out_len 64
    ret <- signatureSerializeSchnorr ctx out_ptr out_len in_ptr
    unless (isSuccess ret) $ error "could not serialize schnorr signature"
    final_len <- peek out_len
    packByteString (out_ptr, final_len)

importXOnlyPubKey :: ByteString -> Maybe XOnlyPubKey
importXOnlyPubKey bs
{-
    | BS.length bs == 32 = withContext $ \ctx -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \pfp -> useByteString bs $ \(inp, _) ->
            schnorrXOnlyPubKeyParse ctx pfp inp
        if isSuccess ret
            then return $ Just $ XOnlyPubKey fp
            else return Nothing
    | otherwise = Nothing
-}
    | BS.length bs == 32 = unsafePerformIO $
        unsafeUseByteString bs $ \(input, len) -> do
        pub_key <- mallocBytes 64
        ret <- schnorrXOnlyPubKeyParse ctx pub_key input len
        if isSuccess ret
            then do
                out <- unsafePackByteString (pub_key, 64)
                return $ Just $ XOnlyPubKey out
            else do
                free pub_key
                return Nothing
    | otherwise = Nothing

importSchnorrSig :: ByteString -> Maybe SchnorrSig
importSchnorrSig bs
    {- remote this all
    | BS.length bs == 64 = withContext $ \ctx -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \pfp -> useByteString bs $ \(inp, _) ->
            schnorrSignatureParse ctx pfp inp
        if isSuccess ret
            then return $ Just $ SchnorrSig fp
            else return Nothing
    | otherwise = Nothing
    -}
    | BS.length bs == 64 = unsafeUseByteString bs $ \(in_ptr, in_len) -> do
        out_sig <- mallocBytes 64
        ret <- schnorrSignatureParse ctx out_sig in_ptr in_len
        if isSuccess ret
            then do
                out_bs <- unsafePackByteString (out_sig, 64)
                return (Just (Sig out_bs))
            else do
                free out_sig
                return Nothing
    | otherwise = Nothing

verifyMsgSchnorr :: XOnlyPubKey -> SchnorrSig -> Msg -> Bool
{- remote this all
verifyMsgSchnorr (XOnlyPubKey fp) (SchnorrSig fg) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr fg $ \g ->
        withForeignPtr fm $ \m -> isSuccess <$> schnorrSignatureVerify ctx g m p
-}
verifyMsgSchnorr (XOnlyPubKey fp) (SchnorrSig fg) (Msg fm) = unsafeUseByteString bs \(in_ptr, in_len) -> do
    isSuccess <$> schnorrSignatureVerify ctx g m p

exportXOnlyPubKey :: XOnlyPubKey -> ByteString
{- remove all this
exportXOnlyPubKey (XOnlyPubKey pub) = withContext $ \ctx ->
    withForeignPtr pub $ \p -> allocaBytes 32 $ \o -> do
        ret <- schnorrPubKeySerialize ctx o p
        unless (isSuccess ret) $ error "could not serialize x-only public key"
        packByteString (o, 32)
-}
exportXOnlyPubKey (XOnlyPubKey pub) =
    unsafeUseByteString bs $ \(in_ptr, in_len) -> do
        p <- allocaBytes 32
        ret <- schnorrPubKeySerialize ctx in_ptr p
        unless (isSuccess ret) $ error "could not serialize x-only public key"
        packByteString (in_ptr, 32)

deriveXOnlyPubKey :: SecKey -> XOnlyPubKey
{- remove all this
deriveXOnlyPubKey (SecKey fk) = withContext $ \ctx -> withForeignPtr fk $ \k -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> schnorrXOnlyPubKeyCreate ctx p k
    unless (isSuccess ret) $ error "could not derive x-only public key"
    return $ XOnlyPubKey fp
-}
deriveXOnlyPubKey (SecKey fk) =
    unsafeUseByteString bs $ \(in_ptr, in_len) -> do
        p <- mallocForeignPtr
        ret <- schnorrXOnlyPubKeyCreate ctx in_ptr p
        unless (isSuccess ret) $ error "could not derive x-only public key"
        return $ XOnlyPubKey in_ptr

testTweakXOnlyPubKey :: XOnlyPubKey -> CInt -> XOnlyPubKey -> Tweak -> Bool
testTweakXOnlyPubKey (XOnlyPubKey fp) is_negated (XOnlyPubKey internal) (Tweak ft) =
    withContext $ \ctx ->
    withForeignPtr fp $ \p ->
    withForeignPtr internal $ \internalp ->
    withForeignPtr ft $ \t -> do
        ret <- xOnlyPubKeyTweakTest ctx p is_negated internalp t
        return $ isSuccess ret
-- End of Schnorr block
#endif

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

instance Arbitrary PubKey where
    arbitrary = derivePubKey <$> arbitrary

#ifdef SCHNORR
instance Arbitrary XOnlyPubKey where
    arbitrary = do
        key <- arbitrary
        return $ deriveXOnlyPubKey key
#endif
