module ElectionPolynomial
  ( SecretCoefficient
  , PublicCommitment
  , ElectionPolynomial(..))
  where

import Group ( ElementModP, ElementModQ )
import Schnorr ( SchnorrProof )

type SecretCoefficient = ElementModQ
type PublicCommitment = ElementModP

data ElectionPolynomial = ElectionPolynomial
  { coefficients :: [SecretCoefficient]
  , coefficientCommitments :: [PublicCommitment]
  , coefficientProofs :: [SchnorrProof]
  }