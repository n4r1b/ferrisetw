use rand::distr::Alphanumeric;
use rand::{rng, Rng};

pub fn rand_string() -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
}
