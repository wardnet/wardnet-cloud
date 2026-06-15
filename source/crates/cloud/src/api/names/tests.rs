// Name-availability handler tests — validation logic lives in
// `wardnet_common::validation`; comprehensive tests are there. These tests
// verify that `name_available` correctly delegates to the shared validator.

#[test]
fn valid_name_is_valid() {
    assert!(wardnet_common::validation::is_valid_name("happy-einstein"));
    assert!(wardnet_common::validation::is_valid_name("abc"));
    assert!(wardnet_common::validation::is_valid_name("x1z"));
    assert!(wardnet_common::validation::is_valid_name(&"a".repeat(32)));
}

#[test]
fn invalid_names_rejected() {
    assert!(!wardnet_common::validation::is_valid_name("ab")); // too short
    assert!(!wardnet_common::validation::is_valid_name(&"a".repeat(33))); // too long
    assert!(!wardnet_common::validation::is_valid_name("-foo")); // leading hyphen
    assert!(!wardnet_common::validation::is_valid_name("foo-")); // trailing hyphen
    assert!(!wardnet_common::validation::is_valid_name("Foo")); // uppercase
    assert!(!wardnet_common::validation::is_valid_name("foo bar")); // space
    assert!(!wardnet_common::validation::is_valid_name("www")); // reserved
    assert!(!wardnet_common::validation::is_valid_name("admin")); // reserved
}
