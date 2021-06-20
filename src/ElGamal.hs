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
      mult )
import Data.Foldable (toList)
import Data.List (foldl')

type ElGamalSecretKey = ElementModQ
type ElGamalPublicKey = ElementModP

data ElGamalKeyPair = ElGamalKeyPair
  { secretKey :: {-#UNPACK#-}!ElGamalSecretKey
  , publicKey :: {-#UNPACK#-}!ElGamalPublicKey
  } deriving stock (Show)

data ElGamalCiphertext = ElGamalCiphertext
  { pad :: {-#UNPACK#-}!ElementModP
  , dat :: {-#UNPACK#-}!ElementModP
  }

keypairFromSecret :: ElementModQ -> Maybe ElGamalKeyPair
keypairFromSecret a@(ElementMod n)
  | n < 2 = Nothing
  | otherwise = Just $ ElGamalKeyPair a (gPowP $ POrQ'Q a)

encrypt :: Int -> ElementModQ -> ElementModP -> Maybe ElGamalCiphertext
encrypt m nonce pubKey =
  let
    pad = gPowP (POrQ'Q nonce)
    gpowp_m = gPowP (POrQ'Q (ElementMod (toInteger m)))
    pubkey_pow_n = powMod pubKey nonce
    dat = mult ([gpowp_m, pubkey_pow_n] :: [ElementModP])

  in if nonce == zeroModQ
    then Nothing
    else Just $! ElGamalCiphertext{..}

add :: Foldable t => t ElGamalCiphertext -> Maybe ElGamalCiphertext
add cs = case toList cs of
    [] -> Nothing
    x:xs -> Just $! foldl' f x xs
  where
    f !result next = ElGamalCiphertext
      (mult [pad result, pad next])
      (mult [dat result, dat next])

decrypt :: ElGamalSecretKey -> ElGamalCiphertext -> Int
decrypt sec enc = 0

decrypt_known_product :: ElGamalCiphertext -> ElementModP -> Int
decrypt_known_product enc prod = 0