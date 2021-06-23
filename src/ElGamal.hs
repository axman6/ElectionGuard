{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DerivingStrategies #-}
module ElGamal (module ElGamal) where

import Group
    ( ElementModPOrQ(POrQ'Q),
      ElementModP,
      ElementModQ,
      ElementMod(ElementMod),
      zeroModQ,
      powMod,
      gPowP,
      mult, multInv )
import DLog (dlog)

type ElGamalSecretKey = ElementModQ
type ElGamalPublicKey = ElementModP

data ElGamalKeyPair = ElGamalKeyPair
  { secretKey :: {-#UNPACK#-}!ElGamalSecretKey
  , publicKey :: {-#UNPACK#-}!ElGamalPublicKey
  } deriving stock (Show)

data ElGamalCiphertext = ElGamalCiphertext
  { pubKey :: {-#UNPACK#-}!ElementModP
  , ciphertext :: {-#UNPACK#-}!ElementModP
  } deriving stock (Show, Eq)

keypairFromSecret :: ElementModQ -> Maybe ElGamalKeyPair
keypairFromSecret a@(ElementMod n)
  | n < 2 = Nothing
  | otherwise = Just $ ElGamalKeyPair a (gPowP $ POrQ'Q a)

encrypt :: Int -> ElementModQ -> ElementModP -> Maybe ElGamalCiphertext
encrypt m nonce pubK =
  let
    pubKey = gPowP (POrQ'Q nonce)
    gpowp_m = gPowP (POrQ'Q (ElementMod (toInteger m)))
    pubkey_pow_n = powMod pubK nonce :: ElementModP
    ciphertext = mult gpowp_m pubkey_pow_n

  in if nonce == zeroModQ
    then Nothing
    else Just $! ElGamalCiphertext{..}

add :: ElGamalCiphertext -> ElGamalCiphertext -> ElGamalCiphertext
add a b = ElGamalCiphertext
  (mult (pubKey a) (pubKey b))
  (mult (ciphertext a) (ciphertext b))

neg :: ElGamalCiphertext -> ElGamalCiphertext
neg ElGamalCiphertext{..} = ElGamalCiphertext (multInv pubKey) (multInv ciphertext)

sub :: ElGamalCiphertext -> ElGamalCiphertext -> ElGamalCiphertext
sub a b = add a (neg b)

decrypt :: ElGamalSecretKey -> ElGamalCiphertext -> Int
decrypt sec enc = decryptKnownProduct enc (powMod (pubKey enc) sec)

decryptKnownProduct :: ElGamalCiphertext -> ElementModP -> Int
decryptKnownProduct enc prod = dlog (mult (ciphertext enc) (multInv prod :: ElementModP))

partialDecrypt :: ElGamalSecretKey -> ElGamalCiphertext -> ElementModP
partialDecrypt sec enc = powMod (pubKey enc) sec
