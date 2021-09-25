{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE DataKinds #-}
module ChaumPedersen.Disj where

-- import Auxiliary
import Group
import ElGamal


-- data DisjunctiveChaumPedersenProof


{-
 -- from electionguard-verifier in Rust

type Message = ElGamalCiphertext

type GenChallenge = (Message, Message) -> Integer

data Proofs = Proofs
  { zeroProof :: Proof
  , oneProof :: Proof}

data Proof = Proof
  { commitment :: Message
  , challenge :: Exponent
  , response :: Exponent
  }


data Status = Status
  { challenge' :: Bool
  , response' :: ResponseStatus
  }

data ResponseStatus = ResponseStatus
  { publicKey :: Bool
  , cipherText :: Bool
  }

checkZero :: Proof -> Element -> Message -> (GenChallenge) -> Status
checkZero prf pubKey msg genChallenge =
  let
    challengeOk =
      challenge prf == elementMod (genChallenge (msg, commitment prf))
    responseStatus = transcriptZero prf pubKey msg
  in Status challengeOk responseStatus

transcriptZero :: Proof -> Element -> Message -> ResponseStatus
transcriptZero prf pubK msg =
  let
    h = pubK
    a = pubKey msg
    b = ciphertext msg
    commit = commitment prf
    alpha  = pubKey commit
    beta   = ciphertext commit
    c = challenge prf
    u = response prf

    !alphaOk = gPowP (POrQ'P $ elementMod $ asInteger u)
              == alpha * powMod a c
    !betaOk  = powMod h u
            == beta * powMod b c

  in ResponseStatus {publicKey = alphaOk, cipherText = betaOk}

proveZero :: Element -> Message -> Exponent -> Exponent -> GenChallenge -> Proof
proveZero pubK msg oneTimeSecret oneTimeExponent genChallenge =

  let
    h = pubK
    rr = oneTimeSecret
    t = oneTimeExponent

    alpha = powMod g t
    beta = powMod h t

    commitment = ElGamalCiphertext { pubKey = alpha, ciphertext = beta }

    challenge = elementMod $ genChallenge (msg, commitment)

    c = challenge

    u = t + (c * rr)

  in Proof {commitment, challenge, response = u}

simulateZero :: Element -> Message -> Exponent -> Exponent -> Proof
simulateZero pubK msg challenge response =

  let
    h = pubK
    a = pubKey msg
    b = ciphertext msg
    c = challenge
    u = response

    alpha = powMod g u `divP` powMod a c
    beta  = powMod h u `divP` powMod b c

  in Proof
    { commitment = ElGamalCiphertext alpha beta
    , challenge = c
    , response = u
    }

checkEqual :: Proof -> Element -> Message -> Message -> (GenChallenge) -> Status
checkEqual prf pubK msg1 msg2 genChallenge =
  let
      combinedMsg = sub msg1 msg2

  in checkZero prf pubK combinedMsg genChallenge


transcriptEqual :: Proof -> Element -> Message -> Message -> ResponseStatus
transcriptEqual prf pubK msg1 msg2 =
  let combinedMsg = sub msg1 msg2
  in transcriptZero prf pubK combinedMsg

proveEqual :: Element -> Message -> Exponent -> Message -> Exponent -> Exponent -> GenChallenge -> Proof
proveEqual pubK msg1 oneTimeSecret1 msg2 oneTimeSecret2 oneTimeExponent genChallenge =
  let
    combinedMsg = sub msg1 msg2
    combinedOneTimeSecret = oneTimeSecret1 - oneTimeSecret2
  in proveZero pubK combinedMsg combinedOneTimeSecret oneTimeExponent genChallenge

simulateEqual :: Element -> Message -> Message -> Exponent -> Exponent -> Proof
simulateEqual pubK msg1 msg2 challenge response =
  let combinedMsg = sub msg1 msg2
  in simulateZero pubK combinedMsg challenge response

checkPlaintext :: Proof -> Element -> Message -> Int -> GenChallenge -> Status
checkPlaintext prf pubK msg plaintext genChallenge =
  let
    plaintextOTS = 0
    Just encryptedPlaintext = encrypt plaintext plaintextOTS pubK
  in checkEqual prf pubK msg encryptedPlaintext genChallenge

-- checkZeroOne ::

-}