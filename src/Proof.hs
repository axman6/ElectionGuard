module Proof (module Proof) where

import Data.Text (Text)

data ProofUsage
  = Unknown
  | SecretValue
  | SelectionLimit
  | SelectionValue
  deriving stock (Show, Eq)



data Proof a = Proof
  { name :: Text
  , usage :: ProofUsage
  , content :: a
  }
