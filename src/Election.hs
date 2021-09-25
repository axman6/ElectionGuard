{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DataKinds #-}
module Election (module Election) where

import Group
    ( ElementModP,
      ElementModQ,
      ElementMod(ElementMod),
      ParamName(P, Q),
      q,
      p,
      r,
      g )
import Hash ( hash )

data ElectionConstants = ElectionConstants
  { largePrime :: Integer
  , smallPrime :: Integer
  , cofactor   :: Integer
  , generator  :: Integer
  }

defaultElection :: ElectionConstants
defaultElection = ElectionConstants
  { largePrime = p
  , smallPrime = q
  , cofactor   = r
  , generator  = g
  }

data CiphertextElectionContext = CiphertextElectionContext
  { numberOfGuardians      :: Integer
  , quorum                 :: Integer
  , elgamalPublicKey       :: ElementModP
  , commitmentHash         :: ElementModQ
  , manifestHash           :: ElementModQ
  , cryptoBaseHash         :: ElementModQ
  , cryptoExtendedBaseHash :: ElementModQ
  }

makeCipherTextElectionContext ::
  Integer
  -> Integer
  -> ElementModP
  -> ElementModQ
  -> ElementModQ
  -> CiphertextElectionContext
makeCipherTextElectionContext
  numberOfGuardians
  quorum
  elgamalPublicKey
  commitmentHash
  manifestHash
  = let cryptoBaseHash = hash
          ( ElementMod @'P p
          , ElementMod @'Q q
          , ElementMod @'P g
          , numberOfGuardians
          , quorum
          , manifestHash
          )
        cryptoExtendedBaseHash = hash (cryptoBaseHash, commitmentHash)
    in CiphertextElectionContext{..}