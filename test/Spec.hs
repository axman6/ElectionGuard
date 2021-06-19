module Main (main) where

import Test.Tasty
import Test.Tasty.HUnit

import Crypto.Number.ModArithmetic
import Crypto.Number.Prime

import Group

main :: IO ()
main = defaultMain $ testGroup "ElectionGuard"
  [ testCase "Baseline Parameters" $ do
     isProbablyPrime p @? "P is prime"
     isProbablyPrime q @? "Q is prime"
     assertEqual "p-1 = qr" (p-1) (q*r)
     (r `mod` q /= 0) @? "q is not a divisor of r"
     1 < g @? "1 < g"
     g < p @? "g < p"
     expFast g q p == 1 @? "g^q mod p = 1"

  ]
