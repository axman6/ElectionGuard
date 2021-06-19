module Types (module Types) where

import Data.Text (Text)

newtype BallotID = BallotID Text
newtype ContextID = ContextID Text
newtype GuardianID = GuardianID Text
newtype MediatorID = MediatorID Text
newtype SelectionID = SelectionID Text