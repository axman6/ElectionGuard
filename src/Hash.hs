{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
module Hash (module Hash) where

import Crypto.Number.Serialize (os2ip)
import Crypto.Hash
    ( hashFinalize, hashInit, hashUpdate, hashUpdates, SHA256, Context, Digest )
import Data.ByteArray ( ByteArray, convert )

import Group (ElementModQ, elementMod, toHex, ElementMod, AsInteger (asInteger))
import Data.ByteString (ByteString)
import Data.Foldable (toList)

-- data Input p
--   = External Integer
--   | Proof p

-- spec :: (p -> Integer) -> Input p -> Integer
-- spec f = \case
--   External i -> i
--   Proof p -> f p

-- hashIntegers :: [Integer] -> ElementModQ
-- hashIntegers = finaliseElement . flip hashComponents initContext

-- updateAll :: (Foldable t, Hashed a) => Context SHA256 -> t a -> Context SHA256
-- updateAll = foldl' (\acc a -> hashComponents (hashComponents acc a) pipe)

finalise :: Context SHA256 -> Digest SHA256
finalise = hashFinalize

finaliseElement :: Context SHA256 -> ElementModQ
finaliseElement = elementMod . os2ip . finalise

hash :: Hashed a => a -> ElementModQ
hash a = finaliseElement $ hashUpdates hashInit $ hashComponents' a

hashDirect :: ByteArray ba => ba -> ElementModQ
hashDirect ba = finaliseElement $ hashUpdate hashInit ba

hashComponents' :: Hashed a => a -> [ByteString]
hashComponents' a = interspersePipe (hashComponents a [])

interspersePipe :: [ByteString] -> [ByteString]
interspersePipe xs = pipe : foldr (\x rest -> x : pipe : rest) [] xs

hashOfElements :: [ByteString] -> ByteString
hashOfElements xs =
  toHex
  $ asInteger
  $ finaliseElement
  $ hashUpdates @SHA256 @ByteString hashInit
  $ interspersePipe xs

-- initContext :: Context SHA256
-- initContext = hashUpdate hashInit pipe

pipe :: ByteString
pipe = "|"
class Hashed a where
  hashComponents :: a -> [ByteString] -> [ByteString]

instance {-# OVERLAPS #-} Hashed Integer where
  hashComponents i = (toHex i :)

instance Hashed (ElementMod p) where
  hashComponents e = hashComponents (asInteger e)

instance {-# OVERLAPPABLE #-} ByteArray ba => Hashed ba where
  hashComponents ba = (convert ba :)

instance (Hashed a, Hashed b) => Hashed (a,b) where
  hashComponents (a,b) = hashComponents a . hashComponents b

instance (Hashed a, Hashed b, Hashed c) => Hashed (a,b,c) where
  hashComponents (a,b,c) = hashComponents (a,(b,c))

instance {-# OVERLAPS #-} Hashed a => Hashed (Maybe a) where
  hashComponents Nothing =  ("null" :)
  hashComponents (Just a) = hashComponents a

instance {-# OVERLAPPABLE #-} (Hashed a, Foldable t) => Hashed  (t a) where
  hashComponents xs next = hashFoldable xs : next

hashFoldable :: (Foldable t, Hashed a) => t a -> ByteString
hashFoldable xs =
  let subHash = toHex
        $ asInteger
        $ finaliseElement
        $ hashUpdates @SHA256 @ByteString hashInit
        $ interspersePipe (foldr hashComponents [] $ toList xs)
  in subHash

-- hashMessageWithCommitment ::