{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
module Main (main) where

import Gauge.Main ( whnf, bench, defaultMain )
import Nonce (nonceAt, initNonces, Nonces)
import ElGamal (ElGamalKeyPair (publicKey), encrypt, keypairFromSecret, ElGamalCiphertext (ElGamalCiphertext))
import Group (ElementModQ, oneModQ)
import ChaumPedersen (disjunctiveChaumPedersenZero, DisjunctiveChaumPedersenProof, disjunctiveChaumPedersenOne)
import Proof (IsProof(isValid))
import Data.Maybe (fromJust)


data BenchInput = BenchInput
  { keypair :: {-# UNPACK #-} !ElGamalKeyPair
  , r       :: {-# UNPACK #-} !ElementModQ
  , s       :: {-# UNPACK #-} !ElementModQ
  }

nonces :: Nonces
nonces = initNonces 31337 []

chaumPedersenConstructZero :: BenchInput -> (ElGamalCiphertext,DisjunctiveChaumPedersenProof)
chaumPedersenConstructZero BenchInput{..} =
  let Just !ciphertext = encrypt 0 r (ElGamal.publicKey keypair)
      !proof = disjunctiveChaumPedersenZero ciphertext r (ElGamal.publicKey keypair) oneModQ s
  in (ciphertext,proof)

chaumPedersenValidateZero :: (BenchInput, ElGamalCiphertext, DisjunctiveChaumPedersenProof) -> ()
chaumPedersenValidateZero (BenchInput{..}, ciphertext,proof) =
  let !valid = isValid proof ciphertext (ElGamal.publicKey keypair) oneModQ
  in either (error . ("Invalid proof found! " <>)) id valid

chaumPedersenConstructOne :: BenchInput -> (ElGamalCiphertext,DisjunctiveChaumPedersenProof)
chaumPedersenConstructOne BenchInput{..} =
  let Just !ciphertext = encrypt 1 r (ElGamal.publicKey keypair)
      !proof = disjunctiveChaumPedersenOne ciphertext r (ElGamal.publicKey keypair) oneModQ s
  in (ciphertext,proof)

chaumPedersenValidateOne :: (BenchInput, ElGamalCiphertext, DisjunctiveChaumPedersenProof) -> ()
chaumPedersenValidateOne (BenchInput{..}, ciphertext,proof) =
  let !valid = isValid proof ciphertext (ElGamal.publicKey keypair) oneModQ
  in either (error . ("Invalid proof found! " <>)) id valid


constructInputZero :: BenchInput
constructInputZero = BenchInput (fromJust $ keypairFromSecret $ nonceAt nonces 0) (nonceAt nonces 10) (nonceAt nonces 11)

validateInputZero :: (BenchInput, ElGamalCiphertext,DisjunctiveChaumPedersenProof)
validateInputZero = case chaumPedersenConstructZero constructInputZero of (a,b) -> (constructInputZero, a, b)

constructInputOne :: BenchInput
constructInputOne = BenchInput (fromJust $ keypairFromSecret $ nonceAt nonces 0) (nonceAt nonces 10) (nonceAt nonces 11)

validateInputOne :: (BenchInput, ElGamalCiphertext,DisjunctiveChaumPedersenProof)
validateInputOne = case chaumPedersenConstructOne constructInputOne of (a,b) -> (constructInputOne, a, b)

main :: IO ()
main = defaultMain
    [ bench "const" (whnf const ())
    , bench "Chaum Pedersen Zero Construct" (whnf chaumPedersenConstructZero constructInputZero)
    , bench "Chaum Pedersen Zero Validate" (whnf chaumPedersenValidateZero validateInputZero)
    , bench "Chaum Pedersen One Construct" (whnf chaumPedersenConstructOne constructInputOne)
    , bench "Chaum Pedersen One Validate" (whnf chaumPedersenValidateOne validateInputOne)
    ]

