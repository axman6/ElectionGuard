{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE PolyKinds #-}
module Proof (module Proof) where

import Data.Text (Text)
import Data.Kind (Type)

data ProofUsage
  = Unknown
  | SecretValue
  | SelectionLimit
  | SelectionValue
  deriving stock (Show, Eq)

data Proof = Proof
  { name :: Text
  , usage :: ProofUsage
  } deriving stock (Show)


class IsProof a where
  type ProofArguments a :: [Type]
  proofData :: f a -> Proof
  isValid :: a -> ExpandArgs (ProofArguments a)

type family ExpandArgs (as :: [Type]) :: Type where
  ExpandArgs '[] = Either String ()
  ExpandArgs (x ': xs) = x -> ExpandArgs xs