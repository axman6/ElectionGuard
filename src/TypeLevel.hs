{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ConstraintKinds #-}


module TypeLevel where

import GHC.TypeLits ( TypeError, ErrorMessage(ShowType, (:<>:), Text) )
import Data.Kind (Type, Constraint)

type family OneOf' (t :: Type) (ts :: [Type]) (allTs :: [Type]) :: Constraint where
  OneOf' t '[] allTs = TypeError (Text "The type " :<>: ShowType t :<>: Text " is not one of: " :<>: ShowType allTs )
  OneOf' t (t ': ts) allTs = ()
  OneOf' t (u ': ts) allTs = OneOf' t ts allTs

type OneOf t ts = OneOf' t ts ts
