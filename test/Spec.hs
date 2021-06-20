{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
module Main (main) where

import Test.Tasty ( defaultMain, testGroup )
import Test.Tasty.HUnit ( testCase, (@?), assertEqual )
import Test.Tasty.QuickCheck

import Crypto.Number.ModArithmetic ( expFast )
import Crypto.Number.Prime ( isProbablyPrime )

import Group ( ElementMod(ElementMod), q, p, r, g, elementMod )
import ElGamal
    ( ElGamalKeyPair(publicKey, secretKey),
      keypairFromSecret,
      encrypt,
      decrypt )

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
  , testCase "ElGamal" $ do
      let
         Just keyPair = keypairFromSecret (ElementMod $ 2^(255::Int) - 19)
         nonce = ElementMod 1337
         cleartext = 42
         Just encrypted = encrypt cleartext nonce $ publicKey keyPair
      decrypt (secretKey keyPair) encrypted == cleartext @? "decrypt . encrypt == id"
  , testProperty "ElGamal" $
      let
        Just keyPair = keypairFromSecret (ElementMod $ 2^(255::Int) - 19)
      in forAll arbitrary $ \(cleartext, nonce) ->
          cleartext >= 0 && nonce > 0 ==>
          let Just encrypted = encrypt cleartext (elementMod (toInteger @Int nonce)) $ publicKey keyPair
          in decrypt (secretKey keyPair) encrypted == cleartext

  ]
