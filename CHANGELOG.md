# django secure changelog
(Using Semantic Versioning)
## [unreleased] - 2017-
### Changed
  - Encode utf-8 before returning decoded for Python 3 @djangosecure.cryptolib.decrypt()

## [0.0.1]  - 2017-01-21
### Added
  - Python 3.5 compatibility
  - Unittest
### Changed
  - Modify prompts to enable testing
### Security
  - TODO: Seed the random number generator
### Fixed
  - get_database() bug: with cryptokey as parameter & return decrypted on file creation
  - hidden_setting() bug: with cryptokey as parameter & return decrypted on file creation
### Removed
  - Unnecessary files (admin.py, models.py, views.py)

## [0.0.1]  - 2017-01-14
### Added
### Changed
### Fixed
### Removed
### Security

[0.0.2]: https://github.com/rafahsolis/djangosecure/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/rafahsolis/djangosecure