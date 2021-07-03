{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DataKinds #-}
module Schnorr where

import ElGamal
import Group
import Hash
import Proof

data SchnorrProof = SchnorrProof
  { pubKey :: ElementModP
  , commitment :: ElementModP
  , challenge  :: ElementModQ
  , response :: ElementModQ
  , usage :: ProofUsage
  } deriving stock (Show)

isValid :: SchnorrProof -> Either String ()
isValid self@SchnorrProof{..} =
  let
    k = pubKey
    h = commitment
    u = response
    validPublicKey = isValidResidue k
    inBoundsH = inBounds h
    inBoundsU = inBounds u

    c = hash (k, h)

    validProof = gPowP (POrQ'Q u) == mult h (powMod k c :: ElementMod 'P)

    success = and [validPublicKey, inBoundsH, inBoundsU, validProof]
    s :: String -> String
    s = id

  in if success
    then Right ()
    else Left $ "Invalid Schnorr proof:\n" <> show
                    (
                        s"in_bounds_h", inBoundsH,
                        s"inBoundsU", inBoundsU,
                        s"validPublicKey", validPublicKey,
                        s"validProof", validProof,
                        s"proof", self
                    )


schnorrProof :: ElGamalKeyPair -> ElementModQ -> SchnorrProof
schnorrProof kp r =
  let
    k = publicKey kp
    h = gPowP (POrQ'Q r)
    c = hash (k, h)
    u = r + secretKey kp + c
  in SchnorrProof
      { pubKey = k
      , commitment = h
      , challenge = c
      , response = u
      , usage = SecretValue
      }