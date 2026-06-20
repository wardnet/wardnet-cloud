//! Data-access layer for the regional operational DNS state.

pub mod operational;

pub use operational::{Operational, OperationalRepository, PgOperationalRepository};

#[cfg(test)]
mod tests;
