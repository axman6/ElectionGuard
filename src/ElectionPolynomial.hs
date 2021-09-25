module ElectionPolynomial where

import Group
import Schnorr

type SecretCoefficient = ElementModQ
type PublicCommitment = ElementModP

data ElectionPolynomial = ElectionPolynomial
  { coefficients :: [SecretCoefficient]
  , coefficientCommitments :: [PublicCommitment]
  , coefficientProofs :: [SchnorrProof]
  }