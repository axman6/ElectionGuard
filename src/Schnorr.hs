{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
module Schnorr where

import ElGamal ( ElGamalKeyPair(publicKey, secretKey) )
import Group
    ( ElementModPOrQ(POrQ'Q),
      ElementModP,
      ElementModQ,
      ElementMod,
      ParamName(P),
      powMod,
      gPowP,
      mult,
      isValidResidue,
      inBounds )
import Hash ( hash )
import Proof ( IsProof(..), Proof(..), ProofUsage(SecretValue) )

data SchnorrProof = SchnorrProof
  { pubKey :: ElementModP
  , commitment :: ElementModP
  , challenge  :: ElementModQ
  , response :: ElementModQ
  } deriving stock (Show)

{- | Check validity of the `proof` for proving possession of the private key corresponding to `public_key`.
-}
instance IsProof SchnorrProof where
  type ProofArguments SchnorrProof = '[]
  proofData _ = Proof "Schnorr Proof" SecretValue

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
      else Left $ "Invalid Schnorr Proof:\n" <> unlines
                      [ "in_bounds_h: " <> show inBoundsH
                      , "in_bounds_u: " <> show inBoundsU
                      , "valid_public_key: " <> show validPublicKey
                      , "valid_proof: " <> show validProof
                      , "proof: " <> show self
                      ]


schnorrProof :: ElGamalKeyPair -> ElementModQ -> SchnorrProof
schnorrProof kp r' =
  let
    k = publicKey kp
    h = gPowP (POrQ'Q r')
    c = hash (k, h)
    u = r' + secretKey kp + c
  in SchnorrProof
      { pubKey = k
      , commitment = h
      , challenge = c
      , response = u
      }