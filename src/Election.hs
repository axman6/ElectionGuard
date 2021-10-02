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

{-|
    Makes a CiphertextElectionContext.

    :param number_of_guardians: The number of guardians necessary to generate the public key
    :param quorum: The quorum of guardians necessary to decrypt an election.  Must be less than `number_of_guardians`
    :param elgamal_public_key: the public key of the election
    :param commitment_hash: the hash of the commitments the guardians make to each other
    :param manifest_hash: the hash of the election metadata
-}
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

