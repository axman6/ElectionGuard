{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DerivingStrategies #-}
module ElGamal (module ElGamal) where

import Group
    ( ElementModP,
      ElementModQ,
      ElementMod(ElementMod),
      zeroModQ,
      powMod,
      gPowP,
      mult, multInv, elementMod )
import DLog (dlog)
import Hash ( Hashed(..) )

type ElGamalSecretKey = ElementModQ
type ElGamalPublicKey = ElementModP

data ElGamalKeyPair = ElGamalKeyPair
  { secretKey :: {-#UNPACK#-}!ElGamalSecretKey
  , publicKey :: {-#UNPACK#-}!ElGamalPublicKey
  } deriving stock (Show)

data ElGamalCiphertext = ElGamalCiphertext
  { pad :: {-#UNPACK#-}!ElementModP
  , data' :: {-#UNPACK#-}!ElementModP
  } deriving stock (Show, Eq)

instance Hashed ElGamalCiphertext where
  hashTree ElGamalCiphertext{..} = hashTree (pad,data')

keypairFromSecret :: ElementModQ -> Maybe ElGamalKeyPair
keypairFromSecret a@(ElementMod n)
  | n < 2 = Nothing
  | otherwise = Just $ ElGamalKeyPair a (gPowP a)

encrypt :: Integer -> ElementModQ -> ElementModP -> Maybe ElGamalCiphertext
encrypt m nonce pubK =
  let
    pad = gPowP nonce
    gpowp_m = gPowP (elementMod m :: ElementModP)
    pubkey_pow_n = powMod pubK nonce :: ElementModP
    data' = mult gpowp_m pubkey_pow_n

  in if nonce == zeroModQ
    then Nothing
    else Just $! ElGamalCiphertext{..}

add :: ElGamalCiphertext -> ElGamalCiphertext -> ElGamalCiphertext
add a b = ElGamalCiphertext
  (mult (pad a) (pad b))
  (mult (data' a) (data' b))

neg :: ElGamalCiphertext -> ElGamalCiphertext
neg ElGamalCiphertext{..} = ElGamalCiphertext (multInv pad) (multInv data')

sub :: ElGamalCiphertext -> ElGamalCiphertext -> ElGamalCiphertext
sub a b = add a (neg b)

decrypt :: ElGamalSecretKey -> ElGamalCiphertext -> Int
decrypt sec enc = decryptKnownProduct enc (powMod (pad enc) sec)

decryptKnownProduct :: ElGamalCiphertext -> ElementModP -> Int
decryptKnownProduct enc prod = dlog (mult (data' enc) (multInv prod :: ElementModP))

partialDecrypt :: ElGamalSecretKey -> ElGamalCiphertext -> ElementModP
partialDecrypt sec enc = powMod (pad enc) sec
