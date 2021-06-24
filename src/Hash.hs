{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
module Hash (module Hash) where

import Crypto.Number.Serialize (os2ip, i2osp)
import Crypto.Hash
    ( hashFinalize, hashInit, hashUpdate, hashUpdates, SHA256 (SHA256), Context, Digest, hashWith )
import Data.ByteArray ( ByteArray, convert )

import Group (ElementModQ, elementMod, toHex, ElementMod, AsInteger (asInteger), ElementModP, toBytes, toHexBS, Parameter)
import Data.ByteString (ByteString)
import Data.Foldable (toList)

toModQ :: ByteString -> ElementModQ
toModQ = elementMod . os2ip

initContext :: Context SHA256
initContext = hashUpdate hashInit pipe

pipe :: ByteString
pipe = "|"

data HashTree
  = Item ByteString
  | Sequence [HashTree]
  deriving stock (Show)

hash :: Hashed a => a -> ElementModQ
hash = hashHashTree . hashTree

finaliseElement :: Context SHA256 -> ElementModQ
finaliseElement = elementMod . os2ip . hashFinalize

-- For testing
hashDirect :: ByteArray ba => ba -> ElementModQ
hashDirect ba = finaliseElement $ hashUpdate hashInit ba

showHashTree :: HashTree -> String
showHashTree = foldTree
   (\bs -> init . drop 1 $ show bs)
   (\strs -> "(" <> foldr (\b acc -> b <> "|" <> acc) ")" strs)

showPipedTree :: HashTree -> String
showPipedTree = foldTree
  (\bs -> init . drop 1 $ show bs)
  (\strs -> "|" <> foldr (\b acc -> b <> "|" <> acc) "|" strs)


foldTree :: (ByteString -> b) -> ([b] -> b) -> HashTree -> b
foldTree i _ (Item bs) = i bs
foldTree i s (Sequence xs) = s $ map (foldTree i s) xs

showAll :: HashTree -> IO ()
showAll tree = do
  print tree
  putStrLn (showHashTree tree)
  putStrLn (showPipedTree tree)

digestToElement :: Digest SHA256 -> ElementModQ
digestToElement = elementMod . os2ip @ByteString . convert

hashHashTree :: HashTree -> ElementModQ
hashHashTree (Item bs) = digestToElement $ hashWith SHA256 ("|" <> bs <> "|")
hashHashTree (Sequence xs) = digestToElement
  $ hashFinalize $ foldr (\bs ctx -> hashUpdate ctx (toBS bs <> "|")) initContext xs
  where
    toBS :: HashTree -> ByteString
    toBS (Item bs) = bs
    toBS (Sequence ss) = toHex $ hashHashTree (Sequence ss)

foldHash :: [ByteString] -> ByteString
foldHash = convert . hashFinalize . foldr (\bs ctx -> hashUpdate ctx (bs <> "|")) initContext


hashString :: HashTree -> ByteString
hashString (Item bs) = pipe <> bs <> pipe
hashString (Sequence bs) = pipe <> foldr (\b rest -> hashString' b <> pipe <> rest) "" bs where
  hashString' (Item bs) = bs
  hashString' (Sequence cs) = "hash("<>hashString (Sequence cs)<>")"

class Hashed a where
  hashTree :: a -> HashTree

instance Hashed HashTree where
  hashTree = id

instance Parameter p => Hashed (ElementMod p) where
  hashTree e
    | e == 0    = Item "null"
    | otherwise = Item $ toHex e

instance Hashed a => Hashed (Maybe a) where
  hashTree Nothing = Item "null"
  hashTree (Just a) = hashTree a
instance Hashed ByteString where
  hashTree "" = Item "null"
  hashTree e = Item e

instance Hashed a => Hashed [a] where
  hashTree [] = Item "null"
  hashTree xs = Sequence $ map hashTree xs

instance (Hashed a, Hashed b) => Hashed (a,b) where
  hashTree (a,b) = Sequence [hashTree a, hashTree b]

instance (Hashed a, Hashed b, Hashed c) => Hashed (a,b,c) where
  hashTree (a,b,c) = Sequence [hashTree a, hashTree b, hashTree c]

instance (Hashed a, Hashed b, Hashed c, Hashed d) => Hashed (a,b,c,d) where
  hashTree (a,b,c,d) = Sequence [hashTree a, hashTree b, hashTree c, hashTree d]

instance (Hashed a, Hashed b, Hashed c, Hashed d, Hashed e) => Hashed (a,b,c,d,e) where
  hashTree (a,b,c,d,e) = Sequence [hashTree a, hashTree b, hashTree c, hashTree d, hashTree e]


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
{-
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

-}