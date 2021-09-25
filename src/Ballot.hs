{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE DisambiguateRecordFields #-}
{-# OPTIONS_GHC -Wno-unused-imports #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PartialTypeSignatures #-}
module Ballot (module Ballot) where -- (CiphertextBallotSelection,isValidEncryption,validPlaintextBallotSelection) where

import Data.List ( sort )

import Data.ByteString (ByteString)
import Group (ElementModQ, ElementModP, zeroModQ)
import ElGamal (ElGamalCiphertext (ElGamalCiphertext))
import ChaumPedersen (DisjunctiveChaumPedersenProof, ConstantChaumPedersenProof)
import ElectionObjectBase (HasElectionObjectBase (getObjectIdStr), HasOrderedObjectBase (getOrderedObjectBase), ElectionObjectBase (ElectionObjectBase), OrderedObjectBase, sequenceOrderSort)
import Election (CiphertextElectionContext)
import Proof (IsProof(isValid))
import Hash (CryptoHashCheckable (cryptoHashWith), hash)

listEq :: [ElectionObjectBase] -> [ElectionObjectBase] -> Bool
listEq l1 l2 = sort l1 == sort l2

{-| ExtendedData represents any arbitrary data expressible as a string with a length.

    This is used primarily as a field on a selection to indicate a write-in candidate text value -}
data ExtendedData = ExtendedData
  { value :: ByteString
  , len :: Int
  } deriving stock (Show, Eq)


{-! A BallotSelection represents an individual selection on a ballot.

    This class accepts a `vote` integer field which has no constraints
    in the ElectionGuard Data Specification, but is constrained logically
    in the application to resolve to `False` or `True` aka only 0 and 1 is
    supported for now.

    This class can also be designated as `is_placeholder_selection` which has no
    context to the data specification but is useful for running validity checks internally

    an `extended_data` field exists to support any arbitrary data to be associated
    with the selection.  In practice, this field is the cleartext representation
    of a write-in candidate value.  In the current implementation these values are
    discarded when encrypting.
-}
data PlaintextBallotSelection = PlaintextBallotSelection
  { vote                   :: Integer            -- ^ Represents a selection of zero or one
  , isPlaceholderSelection :: Bool               -- ^ Determines if this is a placeholder selection
  , extendedData           :: Maybe ExtendedData -- ^ an optional field of arbitrary data, such as the value of a write-in candidate
  , _objectId              :: ElectionObjectBase
  } deriving stock (Show, Eq)

instance HasElectionObjectBase PlaintextBallotSelection where getObjectIdStr = _objectId

-- TODO: Check this again now types have changed
validPlaintextBallotSelection :: PlaintextBallotSelection -> ElectionObjectBase -> Either String ()
validPlaintextBallotSelection self@PlaintextBallotSelection{..} expectedObjectId
  | getObjectIdStr self /= expectedObjectId = Left $
      "invalid object_id: expected("<> show expectedObjectId <> ") actual(" <> show (getObjectIdStr self)  <> ")"
  | vote /= 1 && vote /= 0 = Left $
    "Currently only supporting vote choices of 0 or 1: " <> show self
  | otherwise = Right ()

class HasOrderedObjectBase a => HasCiphertextSelection a where
  descriptionHash :: a -> ElementModQ
  ciphertext :: a -> ElGamalCiphertext


{-| A CiphertextBallotSelection represents an individual encrypted selection on a ballot.

    This class accepts a `description_hash` and a `ciphertext` as required parameters
    in its constructor.

    When a selection is encrypted, the `description_hash` and `ciphertext` required fields must
    be populated at construction however the `nonce` is also usually provided by convention.

    After construction, the `crypto_hash` field is populated automatically in the `__post_init__` cycle

    A consumer of this object has the option to discard the `nonce` and/or discard the `proof`,
    or keep both values.

    By discarding the `nonce`, the encrypted representation and `proof`
    can only be regenerated if the nonce was derived from the ballot's master nonce.  If the nonce
    used for this selection is truly random, and it is discarded, then the proofs cannot be regenerated.

    By keeping the `nonce`, or deriving the selection nonce from the ballot nonce, an external system can
    regenerate the proofs on demand.  This is useful for storage or memory constrained systems.

    By keeping the `proof` the nonce is not required to verify the encrypted selection.
-}
data CiphertextBallotSelection = CiphertextBallotSelection
  { _objectId              :: ElectionObjectBase
  , _descriptionHash       :: ElementModQ
  , _ciphertext            :: ElGamalCiphertext
  , _sequenceOrder         :: OrderedObjectBase
  , cryptoHash             :: ElementModQ
  , isPlaceholderSelection :: Bool
  , nonce                  :: Maybe ElementModQ
  , proof                  :: Maybe DisjunctiveChaumPedersenProof
    -- TODO: ISSUE #35: encrypt/decrypt
  , extendedData           :: Maybe ElGamalCiphertext
  }

instance HasElectionObjectBase CiphertextBallotSelection where getObjectIdStr = _objectId
instance HasOrderedObjectBase CiphertextBallotSelection  where getOrderedObjectBase  = _sequenceOrder
instance HasCiphertextSelection CiphertextBallotSelection where
  descriptionHash = _descriptionHash
  ciphertext = _ciphertext



isValidEncryption :: CiphertextBallotSelection -> ElementModQ -> ElementModP -> ElementModQ -> Either String ()
isValidEncryption self@CiphertextBallotSelection{..} encryptionSeed elgamalPublicKey cryptoExtendedBaseHash
  | encryptionSeed /= descriptionHash self = Left $
    "mismatching selection hash: "<> show (getObjectIdStr self)
    <> " expected(" <> show encryptionSeed <> "),"
    <> " actual(" <> show (descriptionHash self) <> ")"
  | recalculatedCryptoHash <- cryptoHashWith self encryptionSeed
  , cryptoHash /= recalculatedCryptoHash = Left $
    "mismatching crypto hash: " <> show (getObjectIdStr self)
    <> " expected("<> show recalculatedCryptoHash <> "),"
    <> " actual("<> show cryptoHash <> ")"
  | Nothing <- proof = Left $
    "No proof exists for: "<> show (getObjectIdStr self)
  | Just prf <- proof = isValid prf (ciphertext self) elgamalPublicKey cryptoExtendedBaseHash


instance CryptoHashCheckable CiphertextBallotSelection where
  cryptoHashWith self encryptionSeed = hash (getObjectIdStr self, encryptionSeed, ciphertext self)

{- TODO:

def make_ciphertext_ballot_selection(
    object_id: str,
    sequence_order: int,
    description_hash: ElementModQ,
    ciphertext: ElGamalCiphertext,
    elgamal_public_key: ElementModP,
    crypto_extended_base_hash: ElementModQ,
    proof_seed: ElementModQ,
    selection_representation: int,
    is_placeholder_selection: bool = False,
    nonce: Optional[ElementModQ] = None,
    crypto_hash: Optional[ElementModQ] = None,
    proof: Optional[DisjunctiveChaumPedersenProof] = None,
    extended_data: Optional[ElGamalCiphertext] = None,
) -> CiphertextBallotSelection:

-}

data PlaintextBallotContest = PlaintextBallotContest
  { _objectId :: ElectionObjectBase
  , ballotSelections :: [PlaintextBallotSelection]
  }

instance HasElectionObjectBase PlaintextBallotContest where getObjectIdStr = _objectId


data CiphertextContest a = CiphertextContest
  { _objectId :: ElectionObjectBase
  , _sequenceOrder :: OrderedObjectBase
  , _descriptionHash :: ElementModQ
  , selections :: [a] -- HasCiphertextSelection
  } deriving stock (Show, Eq)

instance HasElectionObjectBase (CiphertextContest a) where getObjectIdStr = _objectId
instance HasOrderedObjectBase  (CiphertextContest a) where getOrderedObjectBase = _sequenceOrder

data CiphertextBallotContest = CiphertextBallotContest
  { _descriptionHash :: ElementModQ
  , _objectId :: ElectionObjectBase
  , _sequenceOrder :: OrderedObjectBase
  , ballotSelections :: [CiphertextBallotSelection]
  , ciphertextAccumulation :: ElGamalCiphertext
  , cryptoHash :: ElementModQ
  , nonce :: Maybe ElementModQ
  , proof :: Maybe ConstantChaumPedersenProof
  }

instance HasElectionObjectBase CiphertextBallotContest where getObjectIdStr = _objectId
instance HasOrderedObjectBase CiphertextBallotContest where getOrderedObjectBase = _sequenceOrder

instance CryptoHashCheckable CiphertextBallotContest where
  cryptoHashWith self@CiphertextBallotContest{ballotSelections} encryptionSeed =
    hash ( getObjectIdStr self
         , (cryptoHash :: CiphertextBallotSelection -> _) <$> sequenceOrderSort ballotSelections
         , encryptionSeed)


data PlaintextBallot = PlaintextBallot
  { _objectId :: ElectionObjectBase
  , styleId :: ByteString
  , contests :: [PlaintextBallotContest]
  }

instance HasElectionObjectBase PlaintextBallot where getObjectIdStr = _objectId

isValidPlaintextBallot :: PlaintextBallotContest -> ByteString -> Either String ()
isValidPlaintextBallot self expectedBallotStyleId
  | styleId self /= expectedBallotStyleId = Left $
    "invalid ballot_style: for: "<> show (getObjectIdStr self)
    <> " expected(" <> show expectedBallotStyleId <> ")"
    <> " actual("<> show (styleId self) <> ")"
  | otherwise = Right ()

data CiphertextBallot = CiphertextBallot
  { _objectId :: ElectionObjectBase
  , styleId :: ByteString
  , manifestHash :: ElementModQ
  , contests :: [CiphertextBallotContest]
  , code :: ElementModQ
  , timestamp :: Integer
  , cryptoHash :: ElementModQ
  , nonce :: Maybe ElementModQ
  }

nonceSeed :: ElementModQ -> ElectionObjectBase -> ElementModQ -> ElementModQ
nonceSeed manifestHash objectId nonce = hash (manifestHash, objectId, nonce)

hashedBallotNonce :: CiphertextBallot -> Maybe ElementModQ
hashedBallotNonce self =
  nonceSeed (manifestHash self) (objectId self) <$> (nonce :: CiphertextBallot -> _) self

instance CryptoHashCheckable CiphertextBallot where
  cryptoHashWith self encryptionSeed
    | null ((contests :: CiphertextBallot -> _) self) = zeroModQ