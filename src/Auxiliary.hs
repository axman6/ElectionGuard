{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DuplicateRecordFields #-}

module Auxiliary (module Auxiliary) where

import Data.ByteString (ByteString)

import Types

newtype Message = Message ByteString
newtype AuxiliaryPubKey = AuxiliaryPubKey ByteString
newtype AuxiliarySecKey = AuxiliarySecKey ByteString
newtype EncryptedMessage = EncryptedMessage ByteString

data AuxiliaryPublicKey = AuxiliaryPublicKey
  { ownerId :: GuardianID
  , sequenceOrder :: Int
  , key :: AuxiliaryPubKey
  }

data AuxiliaryKeyPair = AuxiliaryKeyPair
  { ownerId :: GuardianID
  , sequenceOrder :: Int
  , secretKey :: AuxiliarySecKey
  , publicKey :: AuxiliaryPubKey
  }

toPubKey :: AuxiliaryKeyPair -> AuxiliaryPublicKey
toPubKey AuxiliaryKeyPair{..} = AuxiliaryPublicKey{key = publicKey,..}

type AuxiliaryEncrypt = Message          -> AuxiliaryPubKey -> Maybe EncryptedMessage
type AuxiliaryDecrypt = EncryptedMessage -> AuxiliarySecKey -> Maybe Message