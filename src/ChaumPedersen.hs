{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE NumericUnderscores #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
module ChaumPedersen (module ChaumPedersen) where

import Proof ( IsProof(..), Proof (..), ProofUsage (SecretValue, SelectionValue, SelectionLimit) )
import ElGamal ( ElGamalCiphertext(pubKey, ciphertext) )
import Group
    ( ElementModP,
      ElementModQ,
      (^%),
      gPowP,
      isValidResidue,
      inBounds, ParamName (Q), zeroModQ, ElementMod (ElementMod), negateN, mult )
import Hash ( hash, bs )
import Nonce (initNonces, nonceAt)
import Data.Maybe ()

data DisjunctiveChaumPedersenProof = DisjunctiveChaumPedersenProof
  { proofZeroPad       :: ElementModP
  , proofZeroData      :: ElementModP
  , proofOnePad        :: ElementModP
  , proofOneData       :: ElementModP
  , proofZeroChallenge :: ElementModQ
  , proofOneChallenge  :: ElementModQ
  , challenge          :: ElementModQ
  , proofZeroResponse  :: ElementModQ
  , proofOneResponse   :: ElementModQ
  } deriving stock (Show)

{- |
        Validates a "disjunctive" Chaum-Pedersen (zero or one) proof.

        `message`: The ciphertext message

        `k`: The public key of the election

        `qBar`: The extended base hash of the election \( \bar{𝑄} \)
-}
instance IsProof DisjunctiveChaumPedersenProof where
  type ProofArguments DisjunctiveChaumPedersenProof =
    [ElGamalCiphertext, ElementModP,  ElementModQ]
  proofData _ = Proof "Disjunctive Chaum Pedersen Proof" SelectionValue
  isValid :: DisjunctiveChaumPedersenProof -> ElGamalCiphertext -> ElementModP -> ElementModQ -> Either String ()
  isValid self@DisjunctiveChaumPedersenProof{..} message k qBar =
    let
      (alpha, beta) = (pubKey message, ciphertext message)
      a0 = proofZeroPad
      b0 = proofZeroData
      a1 = proofOnePad
      b1 = proofOneData
      c0 = proofZeroChallenge
      c1 = proofOneChallenge
      c  = challenge
      v0 = proofZeroResponse
      v1 = proofOneResponse

      inBoundsAlpha = isValidResidue alpha
      inBoundsBeta  = isValidResidue beta
      inBoundsA0    = isValidResidue a0
      inBoundsB0    = isValidResidue b0
      inBoundsA1    = isValidResidue a1
      inBoundsB1    = isValidResidue b1
      inBoundsC0    = inBounds c0
      inBoundsC1    = inBounds c1
      inBoundsV0    = inBounds v0
      inBoundsV1    = inBounds v1

      consistentC   = c0 + c1 == c && c == hash (qBar, alpha, beta, a0, b0, a1, b1)
      consistentGv0 = gPowP v0              == a0 * alpha ^% c0
      consistentGv1 = gPowP v1              == a1 * alpha ^% c1
      consistentKv0 = k ^% v0                        == b0 * beta ^% c0
      consistentGc1kv1 = gPowP c1 * k ^% v1 == b1 * beta ^% c1

      success = and
        [ inBoundsAlpha
        , inBoundsBeta
        , inBoundsA0
        , inBoundsB0
        , inBoundsA1
        , inBoundsB1
        , inBoundsC0
        , inBoundsC1
        , inBoundsV0
        , inBoundsV1
        , consistentC
        , consistentGv0
        , consistentGv1
        , consistentKv0
        , consistentGc1kv1
        ]

    in
      if success
      then Right ()
      else Left $ "Invalid Disjunctive Chaum-Pedersen proof: \n" <>
            unlines
              [
                "in_bounds_alpha: " <> show inBoundsAlpha,
                "in_bounds_beta: " <> show inBoundsBeta,
                "in_bounds_a0: " <> show inBoundsA0,
                "in_bounds_b0: " <> show inBoundsB0,
                "in_bounds_a1: " <> show inBoundsA1,
                "in_bounds_b1: " <> show inBoundsB1,
                "in_bounds_c0: " <> show inBoundsC0,
                "in_bounds_c1: " <> show inBoundsC1,
                "in_bounds_v0: " <> show inBoundsV0,
                "in_bounds_v1: " <> show inBoundsV1,
                "consistent_c: " <> show consistentC,
                "consistent_gv0: " <> show consistentGv0,
                "consistent_gv1: " <> show consistentGv1,
                "consistent_kv0: " <> show consistentKv0,
                "consistent_gc1kv1: " <> show consistentGc1kv1,
                "k: " <> show k,
                "proof: " <> show self
              ]

data ChaumPedersenProof = ChaumPedersenProof
  { pad :: ElementModP
  , data_ :: ElementModP
  , challenge :: ElementModQ
  , response :: ElementModQ
  } deriving stock (Show)

{- |
        Validates a Chaum-Pedersen proof.
        e.g.
        - The given value 𝑣𝑖 is in the set Z𝑞
        - The given values 𝑎𝑖 and 𝑏𝑖 are both in the set Z𝑞^𝑟
        - The challenge value 𝑐 satisfies 𝑐 = 𝐻(𝑄, (𝐴, 𝐵), (𝑎 , 𝑏 ), 𝑀 ).
        - that the equations 𝑔^𝑣𝑖 = 𝑎𝑖𝐾^𝑐𝑖 mod 𝑝 and 𝐴^𝑣𝑖 = 𝑏𝑖𝑀𝑖^𝑐𝑖 mod 𝑝 are satisfied.

        `message`: The ciphertext message

        `k`: The public key corresponding to the private key used to encrypt (e.g. the Guardian public election key)

        `m`: The value being checked for validity

        `qBar`: The extended base hash of the election \( \bar{𝑄} \)
-}
instance IsProof ChaumPedersenProof where
  type ProofArguments ChaumPedersenProof =
      [ElGamalCiphertext, ElementModP, ElementModP, ElementModQ]
  proofData _ = Proof "Chaum Pedersen Proof" SecretValue
  isValid :: ChaumPedersenProof -> ElGamalCiphertext  -> ElementModP -> ElementModP -> ElementModQ -> Either String ()
  isValid self@ChaumPedersenProof{..} message k m qBar =
    let
      (alpha, beta) = (pubKey message, ciphertext message)
      a = pad
      b = data_
      c = challenge
      v = response
      inBoundsAlpha = isValidResidue alpha
      inBoundsBeta = isValidResidue beta
      inBoundsK = isValidResidue k
      inBoundsM = isValidResidue m
      inBoundsA = isValidResidue a
      inBoundsB = isValidResidue b
      inBoundsC = inBounds c
      inBoundsV = inBounds v
      inBoundsQ = inBounds qBar

      sameC = c == hash (qBar, alpha, beta, a, b, m)

      consistentGV = and
        [ inBoundsV
        , inBoundsA
        , inBoundsC
      --  The equation 𝑔^𝑣𝑖 = 𝑎𝑖𝐾^𝑐𝑖
        , gPowP v == a * k ^% c
        ]

        -- The equation 𝐴^𝑣𝑖 = 𝑏𝑖𝑀𝑖^𝑐𝑖 mod 𝑝
      consistentAV = and
          [ inBoundsAlpha
          , inBoundsB
          , inBoundsC
          , inBoundsV
          , alpha ^% v == b * m ^% c
          ]

      success = and
        [ inBoundsAlpha
        , inBoundsBeta
        , inBoundsK
        , inBoundsM
        , inBoundsA
        , inBoundsB
        , inBoundsC
        , inBoundsV
        , inBoundsQ
        , sameC
        , consistentGV
        , consistentAV
        ]

    in if success
      then Right ()
      else Left $ "Invalid Chaum-Pedersen proof: \n" <> unlines
                    [ "in_bounds_alpha:" <> show inBoundsAlpha
                    , "in_bounds_beta:" <> show inBoundsBeta
                    , "in_bounds_k:" <> show inBoundsK
                    , "in_bounds_m:" <> show inBoundsM
                    , "in_bounds_a:" <> show inBoundsA
                    , "in_bounds_b:" <> show inBoundsB
                    , "in_bounds_c:" <> show inBoundsC
                    , "in_bounds_v:" <> show inBoundsV
                    , "in_bounds_q:" <> show inBoundsQ
                    , "same_c:" <> show sameC
                    , "consistent_gv:" <> show consistentGV
                    , "consistent_av:" <> show consistentAV
                    , "k:" <> show k
                    , "q:" <> show qBar
                    , "proof:" <> show self
                    ]


data ConstantChaumPedersenProof = ConstantChaumPedersenProof
  { pad :: ElementModP
  , data_ :: ElementModP
  , challenge :: ElementModQ
  , response :: ElementModQ
  , constant :: Integer
  } deriving stock (Show)

{-| Validates a "constant" Chaum-Pedersen proof.
        e.g. that the equations
        \( g𝑉 = a A C \pmod{p} \)
        and
        \( gLKv = b B C \pmod{p} \)
        are satisfied.

        `message`: The ciphertext message

        `k`: The public key of the election

        `qBar`: The extended base hash of the election \( \bar{𝑄} \)
-}
instance IsProof ConstantChaumPedersenProof where
  type ProofArguments ConstantChaumPedersenProof = '[ElGamalCiphertext, ElementModP, ElementModQ]
  proofData _ = Proof "Constant Chaum Pedersen Proof" SelectionLimit
  isValid :: ConstantChaumPedersenProof -> ElGamalCiphertext -> ElementModP  -> ElementModQ -> Either String ()
  isValid self@ ConstantChaumPedersenProof{..} message k qBar =
    let
      (alpha, beta) = (pubKey message, ciphertext message)
      a = pad
      b = data_
      c = challenge
      v = response
      inBoundsAlpha = isValidResidue alpha
      inBoundsBeta = isValidResidue beta
      inBoundsA = isValidResidue a
      inBoundsB = isValidResidue b
      inBoundsC = inBounds c
      inBoundsV = inBounds v
      unsafeConstant = ElementMod @'Q constant
      -- tmp = int_to_q(constant)
      (constantQ, inBoundsConstant) =
        if inBounds unsafeConstant
        then (zeroModQ,       False)
        else (unsafeConstant, True)
      saneConstant = 0 <= constant && constant < 1_000_000_000 -- Probably too big for current DLog implementation
      sameC = c == hash (qBar, alpha, beta, a, b)
      consistentGV = and
        [ inBoundsV
        , inBoundsA
        , inBoundsAlpha
        , inBoundsC
         -- The equation 𝑔^𝑉 = 𝑎𝐴^𝐶 mod 𝑝
        , gPowP v == a * alpha ^% c
        ]

      -- The equation 𝑔^𝐿𝐾^𝑣 = 𝑏𝐵^𝐶 mod 𝑝
      consistentKV =
        inBoundsConstant
        && gPowP (c * constantQ) * k ^% v == b * beta ^% c

      success = and
        [ inBoundsAlpha
        , inBoundsBeta
        , inBoundsA
        , inBoundsB
        , inBoundsC
        , inBoundsV
        , sameC
        , inBoundsConstant
        , saneConstant
        , consistentGV
        , consistentKV
        ]

    in if success
      then Right ()
      else Left $ "Invalid Constant Chaum-Pedersen proof: \n" <> unlines
              [ "in_bounds_alpha: " <> show inBoundsAlpha
              , "in_bounds_beta: " <> show inBoundsBeta
              , "in_bounds_a: " <> show inBoundsA
              , "in_bounds_b: " <> show inBoundsB
              , "in_bounds_c: " <> show inBoundsC
              , "in_bounds_v: " <> show inBoundsV
              , "in_bounds_constant: " <> show inBoundsConstant
              , "sane_constant: " <> show saneConstant
              , "same_c: " <> show sameC
              , "consistent_gv: " <> show consistentGV
              , "consistent_kv: " <> show consistentKV
              , "k: " <> show k
              , "proof: " <> show self
              ]

-- | Produces a "disjunctive" proof that an encryption of zero is either an encrypted zero or one.
disjunctiveChaumPedersenProof ::
  ElGamalCiphertext -- ^ message: An ElGamal ciphertext
  -> ElementModQ    -- ^ r: The nonce used creating the ElGamal ciphertext
  -> ElementModP    -- ^ k: The ElGamal public key for the election
  -> ElementModQ    -- ^ qBar: A value used when generating the challenge, usually the election extended base hash \( \bar{𝑄} \)
  -> ElementModQ    -- ^ seed: Used to generate other random values here
  -> Bool           -- ^ plaintext: Zero or one
  -> DisjunctiveChaumPedersenProof
disjunctiveChaumPedersenProof message r k qBar seed plaintext =
  (if plaintext then disjunctiveChaumPedersenOne else disjunctiveChaumPedersenZero) message r k qBar seed

disjunctiveChaumPedersenZero ::
  ElGamalCiphertext -- ^ message: An ElGamal ciphertext
  -> ElementModQ    -- ^ r: The nonce used creating the ElGamal ciphertext
  -> ElementModP    -- ^ k: The ElGamal public key for the election
  -> ElementModQ    -- ^ qBar: A value used when generating the challenge, usually the election extended base hash \( \bar{𝑄} \)
  -> ElementModQ    -- ^ seed: Used to generate other random values here
  -> DisjunctiveChaumPedersenProof
disjunctiveChaumPedersenZero message r k qBar seed =
  let
    (alpha, beta) = (pubKey message, ciphertext message)
    nonces = initNonces seed [Left $ bs"disjoint-chaum-pedersen-proof"]
    [c1, v, u0] = map (nonceAt nonces) [0,1,2]

    a0         = gPowP u0
    b0         = k ^% u0
    a1         = gPowP v
    b1         = mult (k ^% v :: ElementModP) (gPowP c1)
    c          = hash (qBar, alpha, beta, a0, b0, a1, b1)
    c0         = c - c1
    v0         = u0 + c0 * r

  in DisjunctiveChaumPedersenProof
    { proofZeroPad = a0
    , proofZeroData = b0
    , proofOnePad = a1
    , proofOneData = b1
    , proofZeroChallenge = c0
    , proofOneChallenge = c1
    , challenge = c
    , proofZeroResponse = v0
    , proofOneResponse = v
    }

-- | Produces a "disjunctive" proof that an encryption of one is either an encrypted zero or one.
disjunctiveChaumPedersenOne ::
  ElGamalCiphertext -- ^ message: An ElGamal ciphertext
  -> ElementModQ    -- ^ r: The nonce used creating the ElGamal ciphertext
  -> ElementModP    -- ^ k: The ElGamal public key for the election
  -> ElementModQ    -- ^ qBar: A value used when generating the challenge, usually the election extended base hash \( \bar{𝑄} \)
  -> ElementModQ    -- ^ seed: Used to generate other random values here
  -> DisjunctiveChaumPedersenProof
disjunctiveChaumPedersenOne message r k qBar seed =
  let
    (alpha, beta) = (pubKey message, ciphertext message)
    nonces = initNonces seed [Left $ bs"disjoint-chaum-pedersen-proof"]
    [w, v, u1] = map (nonceAt nonces) [0,1,2]

    a0       = gPowP v
    b0       = (k ^% v :: ElementModP) `mult` gPowP w
    a1       = gPowP u1
    b1       = k ^% u1
    c        = hash (qBar, alpha, beta, a0, b0, a1, b1)
    c0       = negateN  w
    c1       = c + w
    v0       = v + c0 * r
    v1       = u1 + c1 * r

  in DisjunctiveChaumPedersenProof
    { proofZeroPad = a0
    , proofZeroData = b0
    , proofOnePad = a1
    , proofOneData = b1
    , proofZeroChallenge = c0
    , proofOneChallenge = c1
    , challenge = c
    , proofZeroResponse = v0
    , proofOneResponse = v1
    }

chaumPedersen ::
  ElGamalCiphertext -- ^ `message`: An ElGamal ciphertext
  -> ElementModQ    -- ^ `s`: The nonce or secret used to derive the value
  -> ElementModP    -- ^ `m`: The value we are trying to prove
  -> ElementModQ    -- ^ `seed`: Used to generate other random values here
  -> ElementModQ    -- ^ `hashHeader`: A value used when generating the challenge,
  -> ChaumPedersenProof
chaumPedersen message s m seed hashHeader =
  let
    (alpha, beta) = (pubKey message, ciphertext message)
    -- Pick one random number in Q.
    u = nonceAt (initNonces seed [Left $ bs"constant-chaum-pedersen-proof"]) 0
    a = gPowP  u                                -- 𝑔^𝑢𝑖 mod 𝑝
    b = alpha ^% u                              -- 𝐴^𝑢𝑖 mod 𝑝
    c = hash (hashHeader, alpha, beta, a, b, m) -- sha256(𝑄', A, B, a𝑖, b𝑖, 𝑀𝑖)
    v = u + c * s                               -- (𝑢𝑖 + 𝑐𝑖𝑠𝑖) mod 𝑞
  in ChaumPedersenProof
      { pad = a
      , data_ = b
      , challenge = c
      , response = v
      }

constantChaumPedersen ::
  ElGamalCiphertext -- ^ `message`: An ElGamal ciphertext
  -> Integer        -- ^ The plaintext constant value used to make the ElGamal ciphertext (L in the spec)
  -> ElementModQ    -- ^ `r`: The aggregate nonce used creating the ElGamal ciphertext
  -> ElementModP    -- ^ `k`: The ElGamal public key for the election
  -> ElementModQ    -- ^ `seed`: Used to generate other random values here
  -> ElementModQ    -- ^ `hashHeader`: A value used when generating the challenge, usually the election
                    --   extended base hash \( \bar{Q} \)
  -> ConstantChaumPedersenProof
constantChaumPedersen message constant r k seed hashHeader =
  let
    (alpha, beta) = (pubKey message, ciphertext message)
    -- Pick one random number in Q.
    u = nonceAt (initNonces seed [Left $ bs"constant-chaum-pedersen-proof"]) 0
    a = gPowP u                               -- 𝑔^𝑢𝑖 mod 𝑝
    b = k ^% u                                -- 𝐴^𝑢𝑖 mod 𝑝
    c = hash (hashHeader, alpha, beta, a, b)  -- sha256(𝑄', A, B, a, b)
    v = u + c * r
  in ConstantChaumPedersenProof
      { pad = a
      , data_ = b
      , challenge = c
      , response = v
      , constant = constant
      }