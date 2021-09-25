{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module ElectionObjectBase
  ( ElectionObjectBase(..)
  , HasElectionObjectBase(..)
  , OrderedObjectBase(..)
  , HasOrderedObjectBase(..)
  ,sequenceOrderSort) where

import Data.ByteString ( ByteString )
import Data.List (sortOn)
import Hash (Hashed)

newtype ElectionObjectBase = ElectionObjectBase {objectIdStr :: ByteString}
  deriving newtype (Show, Eq, Ord, Hashed)

class HasElectionObjectBase a where
  getObjectIdStr :: a -> ElectionObjectBase
  -- default

newtype OrderedObjectBase = OrderedObjectBase { sequenceOrder :: Integer }
  deriving newtype (Eq, Ord, Show, Hashed)

class HasElectionObjectBase a => HasOrderedObjectBase a where
  getOrderedObjectBase :: a -> OrderedObjectBase


sequenceOrderSort :: HasOrderedObjectBase a => [a] -> [a]
sequenceOrderSort = sortOn getOrderedObjectBase
