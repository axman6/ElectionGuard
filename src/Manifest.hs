{-# LANGUAGE RecordWildCards #-}
module Manifest where

import Ballot (listEq)
import ElectionObjectBase (ElectionObjectBase (ElectionObjectBase),OrderedObjectBase, HasElectionObjectBase (getObjectIdStr), HasOrderedObjectBase (getOrderedObjectBase))
import Hash(Hashed(..), hash)
import Data.ByteString (ByteString)

import Data.Set (Set, insert, empty, size)

data ElectionType
  = UnknownET
  | General
  | PartisanPrimaryClosed
  | PartisanPrimaryOpen
  | Primary
  | Runoff
  | SpecialET
  | OtherET

data ReportingUnitType
  = UnknownRUT
  | BallotBatch
  | BallotStyleArea
  | Borough
  | City
  | CityCouncil
  | CombinedPrecinct
  | Congressional
  | Country
  | County
  | CountyCouncil
  | DropBox
  | Judicial
  | Municipality
  | PollingPlace
  | Precinct
  | School
  | SpecialRUT
  | SplitPrecinct
  | State
  | StateHouse
  | StateSenate
  | Township
  | Utility
  | Village
  | VoteCenter
  | Ward
  | Water
  | OtherRUT

instance Hashed ReportingUnitType where
  hashTree rut= hashTree @ByteString $ case rut of
    UnknownRUT       -> "unknown"
    BallotBatch      -> "ballot_batch"
    BallotStyleArea  -> "ballot_style_area"
    Borough          -> "borough"
    City             -> "city"
    CityCouncil      -> "city_council"
    CombinedPrecinct -> "combined_precinct"
    Congressional    -> "congressional"
    Country          -> "country"
    County           -> "county"
    CountyCouncil    -> "county_council"
    DropBox          -> "drop_box"
    Judicial         -> "judicial"
    Municipality     -> "municipality"
    PollingPlace     -> "polling_place"
    Precinct         -> "precinct"
    School           -> "school"
    SpecialRUT       -> "special"
    SplitPrecinct    -> "split_precinct"
    State            -> "state"
    StateHouse       -> "state_house"
    StateSenate      -> "state_senate"
    Township         -> "township"
    Utility          -> "utility"
    Village          -> "village"
    VoteCenter       -> "vote_center"
    Ward             -> "ward"
    Water            -> "water"
    OtherRUT         -> "other"

data VoteVariationType
  = UnknownVVT
  | OneOfM
  | Approval
  | Borda
  | Cumulative
  | Majority
  | NOfM
  | Plurality
  | Proportional
  | Range
  | Rcv
  | SuperMajority
  | OtherVVT


instance Hashed VoteVariationType where
  hashTree vvt = hashTree @ByteString $ case vvt of
     UnknownVVT -> "unknown"
     OneOfM -> "one_of_m"
     Approval -> "approval"
     Borda -> "borda"
     Cumulative -> "cumulative"
     Majority -> "majority"
     NOfM -> "n_of_m"
     Plurality -> "plurality"
     Proportional -> "proportional"
     Range -> "range"
     Rcv -> "rcv"
     SuperMajority -> "super_majority"
     OtherVVT -> "other"

data AnnotatedString = AnnotatedString
  { annotation :: ByteString
  , value :: ByteString
  }

instance Hashed AnnotatedString where hashTree AnnotatedString{..} = hashTree (annotation, value)

data Language = Language
  { value :: ByteString
  , language :: ByteString -- TODO: Enum?
  }

instance Hashed Language where hashTree Language{..} = hashTree (value, language)


newtype InternationalisedText = InternationalisedText { text :: [Language]}

instance Hashed InternationalisedText where hashTree = hashTree . text

data ContactInformation = ContactInformation
  { addressLine :: Maybe [ByteString]
  , email :: Maybe [AnnotatedString]
  , phone :: Maybe [AnnotatedString]
  , name :: Maybe ByteString
  }

instance Hashed ContactInformation where
  hashTree ContactInformation{..} = hashTree (name, addressLine, email, phone)

data GeopoliticalUnit = GeopoliticalUnit
  { _objectId :: ElectionObjectBase
  , name :: ByteString
  , type' :: ReportingUnitType
  , contactInformation :: Maybe ContactInformation
  }

instance HasElectionObjectBase GeopoliticalUnit where getObjectIdStr = _objectId
instance Hashed GeopoliticalUnit where hashTree GeopoliticalUnit{..} = hashTree (_objectId, name, type', contactInformation)

data BallotStyle = BallotStyle
  { _objectId :: ElectionObjectBase
  , geopoliticalUnitIds :: Maybe [ByteString]
  , partyIds :: Maybe [ByteString]
  , imageUri :: Maybe ByteString
  }

instance HasElectionObjectBase BallotStyle where getObjectIdStr = _objectId
instance Hashed BallotStyle where hashTree BallotStyle{..} = hashTree (_objectId, geopoliticalUnitIds, partyIds, imageUri)

data Party = Party
  { _objectId :: ElectionObjectBase
  , name :: InternationalisedText
  , abbreviation :: Maybe ByteString
  , color :: Maybe ByteString
  , logoUri :: Maybe ByteString
  }

instance HasElectionObjectBase Party where getObjectIdStr = _objectId
instance Hashed Party where hashTree Party{..} = hashTree (_objectId, name, abbreviation, color, logoUri)

data Candidate = Candidate
  { _objectId :: ElectionObjectBase
  , name :: InternationalisedText
  , partyId :: Maybe ByteString
  , imageUri :: Maybe ByteString
  , isWriteIn :: Maybe Bool
  }

candidateId :: Candidate -> ElectionObjectBase
candidateId = _objectId

instance HasElectionObjectBase Candidate where getObjectIdStr = _objectId
instance Hashed Candidate where hashTree Candidate{..} = hashTree (_objectId, name, partyId, imageUri)

data SelectionDescription = SelectionDescription
  { _objectId :: ElectionObjectBase
  , _sequenceOrder :: OrderedObjectBase
  , _candidateId :: ElectionObjectBase
  }

instance HasElectionObjectBase SelectionDescription where getObjectIdStr = _objectId
instance HasOrderedObjectBase SelectionDescription where getOrderedObjectBase = _sequenceOrder
instance Hashed SelectionDescription where hashTree SelectionDescription{..} = hashTree (_objectId, _candidateId, _sequenceOrder)

data ContestDescription = ContestDescription
  { _objectId :: ElectionObjectBase
  , _sequenceOrder :: OrderedObjectBase
  , electoralDistrictId :: ByteString
  , voteVariation :: VoteVariationType
  , numberElected :: Integer
  , votesAllowed :: Maybe Integer
  , name :: ByteString
  , ballotSelections :: [SelectionDescription]
  , ballotTitle :: Maybe InternationalisedText
  , ballotSubtitle :: Maybe InternationalisedText
  }

instance HasElectionObjectBase ContestDescription where getObjectIdStr = _objectId
instance HasOrderedObjectBase ContestDescription where getOrderedObjectBase = _sequenceOrder
instance Hashed ContestDescription where
  hashTree ContestDescription{..} =
    hashTree ( _objectId, _sequenceOrder, electoralDistrictId, voteVariation, ballotTitle, ballotSubtitle, name, numberElected, votesAllowed, ballotSelections )

isValidContestDescription :: ContestDescription -> Either String ()
isValidContestDescription self@ContestDescription{..}
    | success = Right ()
    | otherwise = Left $ "Contest " <> show _objectId <> " failed validation check: " <>
      unlines
        [ "contest_has_valid_number_elected: " <> show contest_has_valid_number_elected,
          "contest_has_valid_votes_allowed: " <> show contest_has_valid_votes_allowed,
          "selections_have_valid_candidate_ids: " <> show selections_have_valid_candidate_ids,
          "selections_have_valid_selection_ids: " <> show selections_have_valid_selection_ids,
          "selections_have_valid_sequence_ids: " <> show selections_have_valid_sequence_ids
        ]

  where contest_has_valid_number_elected =  numberElected <= fromIntegral (length ballotSelections)
        contest_has_valid_votes_allowed = maybe True (numberElected <=) votesAllowed
        expected_selection_count = length ballotSelections
        (candIds, selectIds, seqIds) = foldl
          (\(candIds', selectIds', seqIds') SelectionDescription{..} ->
            (insert _objectId candIds' , insert _sequenceOrder selectIds' , insert _candidateId seqIds') )
          (empty, empty, empty)
          ballotSelections
        selections_have_valid_candidate_ids = size candIds == expected_selection_count
        selections_have_valid_selection_ids = size selectIds == expected_selection_count
        selections_have_valid_sequence_ids = size seqIds == expected_selection_count
        success = and
          [ contest_has_valid_number_elected
          , contest_has_valid_votes_allowed
          , selections_have_valid_candidate_ids
          , selections_have_valid_selection_ids
          , selections_have_valid_sequence_ids
          ]


