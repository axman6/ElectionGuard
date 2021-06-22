module DLog (module DLog) where

import Group ( ElementModP, ElementMod(ElementMod), g, mult )
import Data.MemoTrie (memo)
data LogCache = LogCache
  !ElementModP
  !Int
  LogCache

logCache :: LogCache
logCache = LogCache (ElementMod 1) 0 (go logCache) where
  go (LogCache g0 n xs) = let n' = n+1 in LogCache (mult g0 (ElementMod g)) n' (go xs)

takeLog :: Int -> LogCache -> [(ElementModP,Int)]
takeLog = go where
  go k (LogCache e n xs)
    | k <= 0 = []
    | otherwise = (e,n) : go (k-1) xs

dlogFind :: ElementModP -> Int
dlogFind e = find logCache where
  find (LogCache e' n xs)
    | e == e' = n
    | otherwise = find xs

dlog :: ElementModP -> Int
dlog = memo dlogFind