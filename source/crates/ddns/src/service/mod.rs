//! The DDNS service — the regional DNS operational plane.

pub mod ddns;

pub use ddns::{DdnsError, DdnsService};

#[cfg(test)]
mod tests;
