use pairing::{
    group::{ff::Field, prime::PrimeCurveAffine, Group},
    Engine,
};
use rand_core::RngCore;
use std::collections::HashSet;

pub trait BlsEngine: Engine {
    fn hash_message(message: &[u8]) -> Self::G1Affine;
}

pub struct Signature<E: BlsEngine> {
    s: E::G1Affine,
}

pub struct SecretKey<E: BlsEngine> {
    x: E::Fr,
}

impl<E: BlsEngine> SecretKey<E> {
    pub fn generate<R: RngCore>(csprng: &mut R) -> Self {
        SecretKey {
            x: E::Fr::random(csprng),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature<E> {
        let h = E::hash_message(message);
        Signature {
            s: (h * self.x).into(),
        }
    }
}

pub struct PublicKey<E: BlsEngine> {
    p_pub: E::G2Affine,
}

impl<E: BlsEngine> PublicKey<E> {
    pub fn from_secret(secret: &SecretKey<E>) -> Self {
        // TODO Decide on projective vs affine
        PublicKey {
            p_pub: (E::G2Affine::generator() * secret.x).into(),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature<E>) -> bool {
        let h = E::hash_message(message);
        let lhs = E::pairing(&signature.s, &E::G2Affine::generator());
        let rhs = E::pairing(&h, &self.p_pub);
        lhs == rhs
    }
}

pub struct Keypair<E: BlsEngine> {
    pub secret: SecretKey<E>,
    pub public: PublicKey<E>,
}

impl<E: BlsEngine> Keypair<E> {
    pub fn generate<R: RngCore>(csprng: &mut R) -> Self {
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

pub struct AggregateSignature<E: BlsEngine>(Signature<E>);

impl<E: BlsEngine> AggregateSignature<E> {
    pub fn new() -> Self {
        AggregateSignature(Signature {
            s: E::G1Affine::identity(),
        })
    }

    pub fn from_signatures(sigs: &Vec<Signature<E>>) -> Self {
        let mut s = Self::new();
        for sig in sigs {
            s.aggregate(sig);
        }
        s
    }

    pub fn aggregate(&mut self, sig: &Signature<E>) {
        self.0.s = (self.0.s.to_curve() + sig.s).into();
    }

    pub fn verify(&self, inputs: &Vec<(&PublicKey<E>, &[u8])>) -> bool {
        // Messages must be distinct
        let messages: HashSet<&[u8]> = inputs.iter().map(|&(_, m)| m).collect();
        if messages.len() != inputs.len() {
            return false;
        }
        // Check pairings
        let lhs = E::pairing(&self.0.s, &E::G2Affine::generator());
        let mut rhs = E::Gt::identity();
        for input in inputs {
            let h = E::hash_message(input.1);
            rhs += E::pairing(&h, &input.0.p_pub);
        }
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bls12_381::{
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
        Bls12,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    impl BlsEngine for Bls12 {
        fn hash_message(message: &[u8]) -> Self::G1Affine {
            <Self::G1 as HashToCurve<ExpandMsgXmd<blake3::Hasher>>>::hash_to_curve(
                message,
                b"BLSSignatureSeed",
            )
            .into()
        }
    }

    #[test]
    fn sign_verify() {
        let mut rng = ChaChaRng::from_seed([
            0x4f, 0x6d, 0x44, 0xbc, 0x2f, 0x27, 0x6c, 0xd6, 0x63, 0xaf, 0xd0, 0xb9, 0x55, 0x86,
            0x3d, 0x54, 0x4f, 0x6d, 0x44, 0xbc, 0x2f, 0x27, 0x6c, 0xd6, 0x63, 0xaf, 0xd0, 0xb9,
            0x55, 0x86, 0x3d, 0x54,
        ]);

        for i in 0..500 {
            let keypair = Keypair::<Bls12>::generate(&mut rng);
            let message = format!("Message {}", i);
            let sig = keypair.sign(&message.as_bytes());
            assert_eq!(keypair.verify(&message.as_bytes(), &sig), true);
        }
    }

    #[test]
    fn aggregate_signatures() {
        let mut rng = ChaChaRng::from_seed([
            0x4f, 0x6d, 0x44, 0xbc, 0x2f, 0x27, 0x6c, 0xd6, 0x63, 0xaf, 0xd0, 0xb9, 0x55, 0x86,
            0x3d, 0x54, 0x4f, 0x6d, 0x44, 0xbc, 0x2f, 0x27, 0x6c, 0xd6, 0x63, 0xaf, 0xd0, 0xb9,
            0x55, 0x86, 0x3d, 0x54,
        ]);

        let mut inputs = Vec::with_capacity(1000);
        let mut signatures = Vec::with_capacity(1000);
        for i in 0..500 {
            let keypair = Keypair::<Bls12>::generate(&mut rng);
            let message = format!("Message {}", i);
            let signature = keypair.sign(&message.as_bytes());
            inputs.push((keypair.public, message));
            signatures.push(signature);

            // Only test near the beginning and the end, to reduce test runtime
            if i < 10 || i > 495 {
                let asig = AggregateSignature::from_signatures(&signatures);
                assert_eq!(
                    asig.verify(
                        &inputs
                            .iter()
                            .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                            .collect()
                    ),
                    true
                );
            }
        }
    }

    #[test]
    fn aggregate_signatures_duplicated_messages() {
        let mut rng = ChaChaRng::from_seed([
            0x4f, 0x6d, 0x44, 0xbc, 0x2f, 0x27, 0x6c, 0xd6, 0x63, 0xaf, 0xd0, 0xb9, 0x55, 0x86,
            0x3d, 0x54, 0x4f, 0x6d, 0x44, 0xbc, 0x2f, 0x27, 0x6c, 0xd6, 0x63, 0xaf, 0xd0, 0xb9,
            0x55, 0x86, 0x3d, 0x54,
        ]);

        let mut inputs = Vec::new();
        let mut asig = AggregateSignature::new();

        // Create the first signature
        let keypair = Keypair::<Bls12>::generate(&mut rng);
        let message = "First message";
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The first "aggregate" signature should pass
        assert_eq!(
            asig.verify(
                &inputs
                    .iter()
                    .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                    .collect()
            ),
            true
        );

        // Create the second signature
        let keypair = Keypair::<Bls12>::generate(&mut rng);
        let message = "Second message";
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The second (now-)aggregate signature should pass
        assert_eq!(
            asig.verify(
                &inputs
                    .iter()
                    .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                    .collect()
            ),
            true
        );

        // Create the third signature, reusing the second message
        let keypair = Keypair::<Bls12>::generate(&mut rng);
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The third aggregate signature should fail
        assert_eq!(
            asig.verify(
                &inputs
                    .iter()
                    .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                    .collect()
            ),
            false
        );
    }
}
