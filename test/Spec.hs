{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
module Main (main) where

import Test.Tasty ( defaultMain, testGroup )
import Test.Tasty.HUnit ( testCase, (@?), assertEqual )
import Test.Tasty.QuickCheck

import Crypto.Number.ModArithmetic ( expFast )
import Crypto.Number.Prime ( isProbablyPrime )

import Group ( ElementMod(ElementMod), q, p, r, g, elementMod, ElementModQ, toHex )
import ElGamal
    ( ElGamalKeyPair(publicKey, secretKey),
      keypairFromSecret,
      encrypt,
      decrypt )
import Hash ( hash, hashDirect )
import Data.ByteString (ByteString)

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
      forAll arbitrary $ \(Positive cleartext, Positive nonce, Positive privKey) ->
         privKey > 1 ==>
          let Just keyPair = keypairFromSecret (elementMod privKey)
              Just encrypted = encrypt cleartext (elementMod (toInteger @Int nonce)) $ publicKey keyPair
          in decrypt (secretKey keyPair) encrypted == cleartext

  , testGroup "Hash"
        [testProperty "Hash equality" $ \(a :: ElementModQ) b ->
            if a == b
                then hash a === hash b
                else hash a =/= hash b
        , testCase "numbers and strings differ" $ do
            hash @ElementModQ 0 /= hash @ByteString "0" @? "0 /= \"0\""
            hash @ElementModQ 0 /= hash @ByteString "00" @? "0 /= \"00\""
            hash @ElementModQ 0 /= hash @ByteString "|00|" @? "0 /= \"|00|\"" -- Opinion: This should be true
            hash @ElementModQ 0 /= hashDirect @ByteString "|00|" @? "0 /= \"|00|\"" -- Opinion: This should be true
            hash @ElementModQ 1 /= hash @ByteString "1" @? "1 /= \"1\""

            hash @ElementModQ 0 == hash @ByteString "null" @? "0 == \"null\""
            hash @ElementModQ 1 == hash @ByteString "01" @? "1 == \"01\""
            hash @ByteString "Welcome To ElectionGuard"
                /= hash @ByteString "welcome To electionGuard"
                @? "Strings with differing case"
        , testCase "formats match simple" $ do
            hash (1 :: ElementModQ) == hashDirect @ByteString "|01|" @? "format for ElementModQ matches"
            hash @ByteString ""              == hash @ByteString "null" @? "empty bytestring"
            hash @(Maybe ByteString) Nothing == hash @ByteString "null" @? "maybe bytestring"
            hash @[ByteString] []            == hash @ByteString "null" @? "empty list"
        , testCase "formats match nested" $ do
            let nestedHash = hash ([b"0",b"1"], b"3")
                nonNested = hash (b"0",b"1")
                nonNested2 = hash (toHex nonNested,b"3")

            nestedHash /= nonNested @? "Obviously"
            nestedHash == nonNested2 @? "Nesting"




            -- hash (1::ElementModQ,2::ElementModQ) ==  hashDirect @ByteString "||01|02||" @? "Format for tuple matches"
        ]
  ]

b :: ByteString -> ByteString
b bs = bs