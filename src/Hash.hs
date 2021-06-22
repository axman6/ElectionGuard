{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
module Hash (module Hash) where

import Crypto.Number.Serialize (i2osp, os2ip)
import Crypto.Hash
import Data.ByteArray ( Bytes, ByteArray )
import Data.Foldable (foldl')

data Input p
  = External Integer
  | Proof p

spec :: (p -> Integer) -> Input p -> Integer
spec f = \case
  External i -> i
  Proof p -> f p

hashIntegers :: [Integer] -> Integer
hashIntegers = finaliseInteger . updateAll hashInit

updateAll :: (Foldable t, Hashed a) => Context SHA256 -> t a -> Context SHA256
updateAll = foldl' hashedUpdate

finalise :: Context SHA256 -> Digest SHA256
finalise = hashFinalize

finaliseInteger :: Context SHA256 -> Integer
finaliseInteger = os2ip . finalise

hash :: Hashed a => a -> Integer
hash = finaliseInteger . hashedUpdate hashInit

class Hashed a where
  hashedUpdate :: Context SHA256 -> a -> Context SHA256

instance Hashed Integer where
  hashedUpdate c = hashUpdate c . i2osp @Bytes

instance {-# OVERLAPPABLE #-} ByteArray ba => Hashed ba where
  hashedUpdate = hashUpdate

-- hashMessageWithCommitment ::