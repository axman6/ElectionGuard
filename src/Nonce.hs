{-# LANGUAGE RecordWildCards #-}
module Nonce (module Nonce) where

import Group
import Hash

data Nonces = Nonces
  { seed :: ElementModQ
  , headers :: [ElementModPOrQ]
  }

nonces :: ElementModQ -> [ElementModPOrQ] -> Nonces
nonces e = \case
  [] -> Nonces{seed = e, headers = []}
  xs -> Nonces{seed = hash (POrQ'Q e : xs), headers = xs}

nonceAt :: Nonces -> Integer -> Maybe ElementModQ
nonceAt Nonces{..} = \case
  n | n < 0 -> Nothing
    | otherwise -> Just $ hash (seed, n, headers)