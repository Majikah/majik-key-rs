


//! majik_key
//! ---
//! Post-quantum ready seed phrase account library for the Majikah ecosystem.

pub mod crypto;
// pub mod database;
pub mod error;
pub mod types;
pub mod validator;
pub mod web3;
pub mod majik_key;


pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
