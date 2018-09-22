extern crate pairing;
extern crate rand;

use pairing::{CurveAffine, CurveProjective, Engine, Field};
use rand::{Rand, Rng};
use std::collections::HashSet;

#[derive(Debug, PartialEq)]
pub struct Signature<E: Engine> {
    s: E::G1,
}

pub struct SecretKey<E: Engine> {
    x: E::Fr,
}

impl<E: Engine> SecretKey<E> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        SecretKey {
            x: E::Fr::rand(csprng),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature<E> {
        let h = E::G1Affine::hash(message);
        Signature { s: h.mul(self.x) }
    }
}

pub struct PublicKey<E: Engine> {
    p_pub: E::G2,
}

impl<E: Engine> Clone for PublicKey<E> {
    fn clone(&self) -> Self {
        Self {
            p_pub: self.p_pub.clone()
        }
    }
}

impl<E: Engine> PublicKey<E> {
    pub fn from_secret(secret: &SecretKey<E>) -> Self {
        // TODO Decide on projective vs affine
        PublicKey {
            p_pub: E::G2Affine::one().mul(secret.x),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature<E>) -> bool {
        let h = E::G1Affine::hash(message);
        let lhs = E::pairing(signature.s, E::G2Affine::one());
        let rhs = E::pairing(h, self.p_pub);
        lhs == rhs
    }
}

pub struct Keypair<E: Engine> {
    pub secret: SecretKey<E>,
    pub public: PublicKey<E>,
}

impl<E: Engine> Keypair<E> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        let secret = SecretKey::generate(csprng);
        let public = PublicKey::from_secret(&secret);
        Keypair { secret, public }
    }

    pub fn sign(&self, message: &[u8]) -> Signature<E> {
        self.secret.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature<E>) -> bool {
        self.public.verify(message, signature)
    }
}

#[derive(Debug, PartialEq)]
pub struct AggregateSignature<E: Engine>(Signature<E>);

impl<E: Engine> AggregateSignature<E> {
    pub fn new() -> Self {
        AggregateSignature(Signature { s: E::G1::zero() })
    }

    pub fn from_signatures(sigs: &Vec<Signature<E>>) -> Self {
        let mut s = Self::new();
        for sig in sigs {
            s.aggregate(sig);
        }
        s
    }

    pub fn aggregate(&mut self, sig: &Signature<E>) {
        self.0.s.add_assign(&sig.s);
    }

    pub fn verify(&self, inputs: &Vec<(&PublicKey<E>, &[u8])>) -> bool {
        // Messages must be distinct
        let messages: HashSet<&[u8]> = inputs.iter().map(|&(_, m)| m).collect();
        if messages.len() != inputs.len() {
            return false;
        }
        // Check pairings
        let lhs = E::pairing(self.0.s, E::G2Affine::one());
        let mut rhs = E::Fqk::one();
        for input in inputs {
            let h = E::G1Affine::hash(input.1);
            rhs.mul_assign(&E::pairing(h, input.0.p_pub));
        }
        lhs == rhs
    }

    /// Verify a aggregate signatures over a common message.
    ///
    /// Warning: This method is vulnerable to the "rouge public-key attack".
    /// Every user must be required to prove knowledge or possession of their
    /// corresponding secret key. For more information, see: 
    /// https://eprint.iacr.org/2018/483.pdf
    pub fn verify_common_message(
        &self,
        message: &[u8],
        pubkeys: &Vec<&PublicKey<E>>)
        -> bool
    {
        let h = E::G1Affine::hash(message);
        // Check pairings
        let lhs = E::pairing(self.0.s, E::G2Affine::one());
        let mut rhs = E::Fqk::one();
        for pubkey in pubkeys {
            rhs.mul_assign(&E::pairing(h, pubkey.p_pub));
        }
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};

    #[test]
    fn sign_verify() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        for i in 0..500 {
            let keypair = Keypair::<Bls12>::generate(&mut rng);
            let message = format!(">16 character message {}", i);
            let sig = keypair.sign(&message.as_bytes());
            assert_eq!(keypair.verify(&message.as_bytes(), &sig), true);
        }
    }

    #[test]
    fn sign_verify_with_cloned_public() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        for i in 0..500 {
            let keypair = Keypair::<Bls12>::generate(&mut rng);
            let message = format!(">16 character message {}", i);
            let sig = keypair.sign(&message.as_bytes());
            let cloned_pub = keypair.public.clone();
            assert_eq!(cloned_pub.verify(&message.as_bytes(), &sig), true);
        }
    }

    #[test]
    fn test_sign_verify_aggregate_common_message_short() {
        sign_verify_aggregate_common_message(10);
    }
    #[test]
    #[ignore]
    fn test_sign_verify_aggregate_common_message_long() {
        sign_verify_aggregate_common_message(500);
    }
    fn sign_verify_aggregate_common_message(loop_count: u32) {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let mut pubkeys = Vec::with_capacity(1000);
        let mut signatures = Vec::with_capacity(1000);
        let message = ">16 character indentical message".as_bytes();
        for i in 0..loop_count {
            let keypair = Keypair::<Bls12>::generate(&mut rng);
            let signature = keypair.sign(&message);
            pubkeys.push(keypair.public);
            signatures.push(signature);

            if i < 10 || i > (loop_count - 5) {
                let asig = AggregateSignature::from_signatures(&signatures);
                assert_eq!(
                    asig.verify_common_message(&message, &pubkeys.iter().map(|&ref pk| pk).collect()),
                    true
                );
            }
        }
    }

    #[test]
    fn test_sign_verify_aggregate_common_message_missing_sig_short() {
        sign_verify_aggregate_common_message_missing_sig(10);
    }
    #[test]
    #[ignore]
    fn test_sign_verify_aggregate_common_message_missing_sig_long() {
        sign_verify_aggregate_common_message_missing_sig(500);
    }
    fn sign_verify_aggregate_common_message_missing_sig(loop_count: u32) {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let skipped_sig = loop_count / 2;
        let mut pubkeys = Vec::with_capacity(1000);
        let mut signatures = Vec::with_capacity(1000);
        let message = ">16 character indentical message".as_bytes();
        for i in 0..loop_count {
            let keypair = Keypair::<Bls12>::generate(&mut rng);
            let signature = keypair.sign(&message);
            pubkeys.push(keypair.public);
            if i != skipped_sig {
                signatures.push(signature);
            }

            if i < 10 || i > (loop_count - 5) {
                let asig = AggregateSignature::from_signatures(&signatures);
                assert_eq!(
                    asig.verify_common_message(&message, &pubkeys.iter().map(|&ref pk| pk).collect()),
                    i < skipped_sig
                );
            }
        }
    }

    #[test]
    fn aggregate_signatures() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let mut inputs = Vec::with_capacity(1000);
        let mut signatures = Vec::with_capacity(1000);
        for i in 0..500 {
            let keypair = Keypair::<Bls12>::generate(&mut rng);
            let message = format!(">16 character message {}", i);
            let signature = keypair.sign(&message.as_bytes());
            inputs.push((keypair.public, message));
            signatures.push(signature);

            // Only test near the beginning and the end, to reduce test runtime
            if i < 10 || i > 495 {
                let asig = AggregateSignature::from_signatures(&signatures);
                assert_eq!(
                    asig.verify(&inputs
                        .iter()
                        .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                        .collect()),
                    true
                );
            }
        }
    }

    #[test]
    fn aggregate_signatures_duplicated_messages() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let mut inputs = Vec::new();
        let mut asig = AggregateSignature::new();

        // Create the first signature
        let keypair = Keypair::<Bls12>::generate(&mut rng);
        let message = ">16 char first message";
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The first "aggregate" signature should pass
        assert_eq!(
            asig.verify(&inputs
                .iter()
                .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                .collect()),
            true
        );

        // Create the second signature
        let keypair = Keypair::<Bls12>::generate(&mut rng);
        let message = ">16 char second message";
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The second (now-)aggregate signature should pass
        assert_eq!(
            asig.verify(&inputs
                .iter()
                .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                .collect()),
            true
        );

        // Create the third signature, reusing the second message
        let keypair = Keypair::<Bls12>::generate(&mut rng);
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The third aggregate signature should fail
        assert_eq!(
            asig.verify(&inputs
                .iter()
                .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                .collect()),
            false
        );
    }
}
