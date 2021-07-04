{-# LANGUAGE RecordWildCards #-}
module Nonce (module Nonce) where

import Group ( ElementModPOrQ(POrQ'Q), ElementModQ )
import Hash ( hash )
import Data.ByteString (ByteString)

data Nonces = Nonces
  { seed :: ElementModQ
  , headers :: [Either ByteString ElementModPOrQ]
  }

initNonces :: ElementModQ -> [Either ByteString ElementModPOrQ] -> Nonces
initNonces e = \case
  [] -> Nonces{seed = e, headers = []}
  xs -> Nonces{seed = hash (Right (POrQ'Q e) : xs), headers = xs}

nonceAt :: Nonces -> Integer -> ElementModQ
nonceAt Nonces{..} n =
  if null headers
  then hash (seed, n)
  else hash (seed, n, headers)