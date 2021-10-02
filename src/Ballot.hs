{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE DisambiguateRecordFields #-}
{-# OPTIONS_GHC -Wno-unused-imports #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-partial-type-signatures #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module Ballot (module Ballot) where -- (CiphertextBallotSelection,isValidEncryption,validPlaintextBallotSelection) where

import Data.List ( sort )
import Data.Foldable (for_)

import Data.ByteString (ByteString)
import Group (ElementModQ, ElementModP, zeroModQ)
import ElGamal (ElGamalCiphertext (ElGamalCiphertext), add)
import ChaumPedersen (DisjunctiveChaumPedersenProof, ConstantChaumPedersenProof, disjunctiveChaumPedersenProof)
import ElectionObjectBase (HasElectionObjectBase (getObjectIdStr), HasOrderedObjectBase (getOrderedObjectBase), ElectionObjectBase (ElectionObjectBase, objectIdStr), OrderedObjectBase, sequenceOrderSort)
import Election (CiphertextElectionContext (elgamalPublicKey))
import Proof (IsProof(..), Proof (Proof), ProofUsage (Unknown))
import Hash (CryptoHashCheckable (cryptoHashWith), hash)
import Data.Maybe (fromMaybe)
import Data.Functor ((<&>))

listEq :: [ElectionObjectBase] -> [ElectionObjectBase] -> Bool
listEq l1 l2 = sort l1 == sort l2

mismatch :: (HasElectionObjectBase a, Show b) => String -> a -> b -> b -> Either String c
mismatch err self a b =
      Left $ err <> ": " <> show (getObjectIdStr self) <> "\n\
      \expected(" <> show a <> "),\n\
      \  actual(" <> show b <> ")"


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

instance IsProof CiphertextBallotSelection where
  type ProofArguments CiphertextBallotSelection = '[ElementModQ, ElementModP, ElementModQ]
  proofData _ = Proof "CiphertextBallotSelection Proof" Unknown
  isValid :: CiphertextBallotSelection -> ElementModQ -> ElementModP -> ElementModQ -> Either String ()
  isValid self@CiphertextBallotSelection{..} encryptionSeed elgamalPublicKey cryptoExtendedBaseHash
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


{-|
    Constructs a `CipherTextBallotSelection` object. Most of the parameters here match up to fields
    in the class, but this helper function will optionally compute a Chaum-Pedersen proof if the
    given nonce isn't `None`. Likewise, if a crypto_hash is not provided, it will be derived from
    the other fields.
-}
makeCiphertextBallotSelection ::
  ElectionObjectBase
  -> OrderedObjectBase
  -> ElementModQ
  -> ElGamalCiphertext
  -> ElementModP
  -> ElementModQ
  -> ElementModQ
  -> Bool
  -> Bool
  -> Maybe ElementModQ
  -> Maybe ElementModQ
  -> Maybe DisjunctiveChaumPedersenProof
  -> Maybe ElGamalCiphertext
  -> CiphertextBallotSelection
makeCiphertextBallotSelection
  _objectId
  _sequenceOrder
  _descriptionHash
  _ciphertext
  elgamalPublicKey
  cryptoExtendedBaseHash
  proofSeed
  selectionRepresentation
  isPlaceholderSelection
  nonce
  cryptoHash0
  proof0
  extendedData =
    let cryptoHash = fromMaybe (hash (_objectId, _descriptionHash, _ciphertext)) cryptoHash0
        proof = maybe
          (nonce <&> \n -> disjunctiveChaumPedersenProof _ciphertext n elgamalPublicKey cryptoExtendedBaseHash proofSeed selectionRepresentation)
          pure
          proof0

    in CiphertextBallotSelection{..}



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

instance IsProof CiphertextBallotContest where
  type ProofArguments CiphertextBallotContest = '[ElementModQ, ElementModP, ElementModQ]
  proofData _ = Proof "CiphertextBallotContest Proof" Unknown
  isValid :: CiphertextBallotContest -> ElementModQ -> ElementModP -> ElementModQ -> Either String ()
  isValid self encryptionSeed elgamalPublicKey cryptoExtendedBaseHash
    | encryptionSeed /=  dHash = mismatch "mismatching contest hash" self encryptionSeed dHash
    | cHash /= recalculatedCryptoHash = mismatch "mismatching crypto hash" self recalculatedCryptoHash cHash
    | Nothing <- (proof :: CiphertextBallotContest -> _) self = Left $ "no proof exists for: " <> show (getObjectIdStr self)
    -- TODO: write elgamal_accumulate, finish this
    | computedCiphertextAccumulation /= ciphertextAccumulation self = Left $ "ciphertext does not equal elgamal accumulation for: " <> show (getObjectIdStr self)
    | Just proof <-  (proof :: CiphertextBallotContest -> _) self = isValid proof (ciphertextAccumulation self) elgamalPublicKey cryptoExtendedBaseHash
    where recalculatedCryptoHash = cryptoHashWith self encryptionSeed
          dHash = (_descriptionHash :: CiphertextBallotContest -> _) self
          cHash = (cryptoHash :: CiphertextBallotContest -> _) self
          computedCiphertextAccumulation = elgamalAccumulate self

elgamalAccumulate :: CiphertextBallotContest-> ElGamalCiphertext
elgamalAccumulate = foldl1 add . map (ciphertext :: CiphertextBallotSelection -> _)  . (ballotSelections :: CiphertextBallotContest -> _)

data PlaintextBallot = PlaintextBallot
  { _objectId :: ElectionObjectBase
  , styleId :: ByteString
  , contests :: [PlaintextBallotContest]
  }

instance HasElectionObjectBase PlaintextBallot where getObjectIdStr = _objectId


instance IsProof PlaintextBallot where
  type ProofArguments PlaintextBallot = '[ByteString]
  proofData _ = Proof "PlaintextBallot Proof" Unknown
  isValid :: PlaintextBallot -> ByteString -> Either String ()
  isValid self expectedBallotStyleId
    | (styleId :: PlaintextBallot -> _) self /= expectedBallotStyleId = Left $
      "invalid ballot_style: for: "<> show (getObjectIdStr self)
      <> " expected(" <> show expectedBallotStyleId <> ")"
      <> " actual("<> show ((styleId :: PlaintextBallot -> _) self) <> ")"
    | otherwise = Right ()

data CiphertextBallot = CiphertextBallot
  { _objectId :: ElectionObjectBase
  , styleId :: ByteString
  , manifestHash :: ElementModQ
  , codeSeed :: ElementModQ
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
  nonceSeed (manifestHash self) (getObjectIdStr self) <$> (nonce :: CiphertextBallot -> _) self

instance HasElectionObjectBase CiphertextBallot where
  getObjectIdStr = _objectId

instance CryptoHashCheckable CiphertextBallot where
  cryptoHashWith self encryptionSeed
    | null ((contests :: CiphertextBallot -> _) self) = zeroModQ -- TODO: Add logging with writer?
    | otherwise = hash
      ( getObjectIdStr self
      , encryptionSeed
      , (cryptoHash :: CiphertextBallotContest -> _)
        <$> sequenceOrderSort ((contests :: CiphertextBallot -> _) self)
      )

instance IsProof CiphertextBallot where
  type ProofArguments CiphertextBallot = '[ElementModQ, ElementModP, ElementModQ]
  proofData _ = Proof "CiphertextBallot Proof" Unknown
  isValid :: CiphertextBallot -> ElementModQ -> ElementModP -> ElementModQ -> Either String ()
  isValid self encryptionSeed elgamalPublicKey cryptoExtendedBaseHash
      | encryptionSeed /= manifestHash self = mismatch "mismatching ballot" self encryptionSeed (manifestHash self)
      | recalculatedCryptoHash /= cHash = mismatch "mismatching crypto hash" self recalculatedCryptoHash cHash
      | otherwise =
        for_ ((contests :: CiphertextBallot -> _) self) $ \contest -> do
          for_ ((ballotSelections :: CiphertextBallotContest -> _) contest) $ \selection ->
            isValid selection (descriptionHash selection) elgamalPublicKey cryptoExtendedBaseHash
          isValid contest ((_descriptionHash :: CiphertextBallotContest -> _) contest) elgamalPublicKey cryptoExtendedBaseHash
    where recalculatedCryptoHash = cryptoHashWith self encryptionSeed
          cHash = (cryptoHash :: CiphertextBallot -> _) self

data BallotBoxState
  = CAST
  | SPOILED
  | UNKNOWN
  deriving stock (Show, Eq)

data SubmittedBallot = SubmittedBallot
  { ballot :: CiphertextBallot
  , state :: BallotBoxState
  }

makeCipherTextBallot ::
  ElectionObjectBase
  -> ByteString
  -> ElementModQ
  -> Maybe ElementModQ
  -> [CiphertextBallotContest]
  -> Maybe ElementModQ
  -> Maybe Integer
  -> Maybe ElementModQ
  -> IO (Either String CiphertextBallot)
makeCipherTextBallot
  _objectId
  styleId
  manifestHash
  codeSeed0
  contests
  nonce
  timestamp0
  ballotCode
    | null contests = pure (Left "ciphertext ballot with no contests")
    | otherwise = do
      timestamp <- case timestamp0 of Nothing -> error "getTime"; Just a -> pure a
      let cryptoHash = createBallotHash (objectIdStr _objectId) manifestHash contests
          codeSeed = fromMaybe manifestHash codeSeed0
          code = fromMaybe (hash (codeSeed, timestamp, cryptoHash)) ballotCode
      pure (Right CiphertextBallot{..})

createBallotHash :: ByteString -> ElementModQ -> [CiphertextBallotContest] -> ElementModQ
createBallotHash ballotId _descriptionHash contests =
    let contestHashes = map (cryptoHash :: CiphertextBallotContest -> _) $ sequenceOrderSort contests
    in hash (ballotId, _descriptionHash, contestHashes)

makeCiphertextSubmittedBallot ::
    ElectionObjectBase
    -> ByteString
    -> ElementModQ
    -> Maybe ElementModQ
    -> [CiphertextBallotContest]
    -> Maybe ElementModQ
    -> Maybe Integer
    -> BallotBoxState
    -> IO (Either String SubmittedBallot)
makeCiphertextSubmittedBallot
    _objectId
    styleId
    manifestHash
    codeSeed0
    contests0
    ballotCode0
    timestamp0
    state
      | null contests0 = pure $ Left "ciphertext ballot with no contests"
      | otherwise = do
        let contestHashes = map (cryptoHash :: CiphertextBallotContest -> _) $ sequenceOrderSort contests0
            contestHash = hash (_objectId, manifestHash, contestHashes)
        timestamp <- case timestamp0 of Nothing -> error "getTime"; Just a -> pure a
        let codeSeed = fromMaybe manifestHash codeSeed0
            code =  fromMaybe (hash (codeSeed, timestamp, contestHash)) ballotCode0
            contests = contests0 <&> (\CiphertextBallotContest{..} ->
                CiphertextBallotContest{
                  nonce = Nothing
                  , ballotSelections = ballotSelections <&> (\CiphertextBallotSelection{..} -> CiphertextBallotSelection{nonce = Nothing, ..})
                  , ..}
                )

        pure $ Right $ SubmittedBallot
          (CiphertextBallot{cryptoHash = contestHash, nonce = Nothing, ..})
          state
