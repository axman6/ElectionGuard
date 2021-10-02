module BallotValidator where

import Ballot(CiphertextBallot)
import Election(CiphertextElectionContext)
import Manifest( ContestDescriptionWithPlaceholders, InternalManifest, SelectionDescription )

ballotIsValidForElection :: CiphertextBallot -> InternalManifest -> CiphertextElectionContext -> Bool
ballotIsValidForElection _ _ _ = True