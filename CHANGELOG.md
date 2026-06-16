# CHANGELOG


## v9.1.0 (2026-06-16)

### Bug Fixes

- **uv**: Update aioresponses source to specific revision
  ([#234](https://github.com/MountainGod2/cb-events/pull/234),
  [`4a5e11d`](https://github.com/MountainGod2/cb-events/commit/4a5e11d0bcab85f789b6cedcdd74324e36cf8408))

### Features

- **event**: Add private attributes for sub-models
  ([#234](https://github.com/MountainGod2/cb-events/pull/234),
  [`4a5e11d`](https://github.com/MountainGod2/cb-events/commit/4a5e11d0bcab85f789b6cedcdd74324e36cf8408))

### Refactoring

- Relax User model fields and simplify validation
  ([#222](https://github.com/MountainGod2/cb-events/pull/222),
  [`1628580`](https://github.com/MountainGod2/cb-events/commit/1628580c241ce24fbbb6dbccff3af51e78a2f129))

- Remove slots and update dependencies ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- Standardize modules names to improve public API surface
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **api**: Change __all__ to use list ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Add caching option to _build_url
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Add connect timeout to ClientSession
  ([#234](https://github.com/MountainGod2/cb-events/pull/234),
  [`4a5e11d`](https://github.com/MountainGod2/cb-events/commit/4a5e11d0bcab85f789b6cedcdd74324e36cf8408))

- **client**: Add missing docstrings and refactor parsing
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Handle invalid ports in nextUrl
  ([#222](https://github.com/MountainGod2/cb-events/pull/222),
  [`1628580`](https://github.com/MountainGod2/cb-events/commit/1628580c241ce24fbbb6dbccff3af51e78a2f129))

- **client**: Improve client state management with Enum
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Improve error messages for nextUrl validation
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Improve nextUrl handling and polling logic
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Improve session management and error handling
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Remove redundant type imports
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Rename poll to _poll and make private
  ([#217](https://github.com/MountainGod2/cb-events/pull/217),
  [`a1d092e`](https://github.com/MountainGod2/cb-events/commit/a1d092e35f47940455f439627245bff59b7ec8e2))

- **client**: Simplify error handling and response parsing
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Simplify nextUrl validation logging
  ([#222](https://github.com/MountainGod2/cb-events/pull/222),
  [`1628580`](https://github.com/MountainGod2/cb-events/commit/1628580c241ce24fbbb6dbccff3af51e78a2f129))

- **client**: Simplify nextUrl validation logic
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Simplify type imports using compatibility shims
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Split response parsing and request handling responsibilities
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **client**: Update docstring for error handling
  ([#222](https://github.com/MountainGod2/cb-events/pull/222),
  [`1628580`](https://github.com/MountainGod2/cb-events/commit/1628580c241ce24fbbb6dbccff3af51e78a2f129))

- **config**: Change timeout type from float to int
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **config**: Simplify error message for invalid delays
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **config**: Update retry attempts and max delay
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **deps**: Adjust typing-extensions for Python version
  ([#222](https://github.com/MountainGod2/cb-events/pull/222),
  [`1628580`](https://github.com/MountainGod2/cb-events/commit/1628580c241ce24fbbb6dbccff3af51e78a2f129))

- **deps**: Simplify linting ([#234](https://github.com/MountainGod2/cb-events/pull/234),
  [`4a5e11d`](https://github.com/MountainGod2/cb-events/commit/4a5e11d0bcab85f789b6cedcdd74324e36cf8408))

- **docs**: Remove obsolete API documentation files
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **docs**: Update mdformat dependencies and exclude api docs
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **exceptions**: Move truncate_text utility to _utils.py
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **exceptions**: Remove __slots__ from error classes
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **exceptions**: Rename constants and functions
  ([#219](https://github.com/MountainGod2/cb-events/pull/219),
  [`97be6ef`](https://github.com/MountainGod2/cb-events/commit/97be6ef695fbd3bd418b821839cca734006dd796))

- **imports**: Update import handling for Self and override
  ([#222](https://github.com/MountainGod2/cb-events/pull/222),
  [`1628580`](https://github.com/MountainGod2/cb-events/commit/1628580c241ce24fbbb6dbccff3af51e78a2f129))

- **init**: Change __all__ from list to tuple
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **lint**: Combine lint and test groups for pyrefly check
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **lint**: Update pyrefly check command to include test group
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **makefile**: Correct status handling in test-cov-lowest-direct
  ([#234](https://github.com/MountainGod2/cb-events/pull/234),
  [`4a5e11d`](https://github.com/MountainGod2/cb-events/commit/4a5e11d0bcab85f789b6cedcdd74324e36cf8408))

- **makefile**: Update requirements export command options
  ([#222](https://github.com/MountainGod2/cb-events/pull/222),
  [`1628580`](https://github.com/MountainGod2/cb-events/commit/1628580c241ce24fbbb6dbccff3af51e78a2f129))

- **models**: Add literal types for user fields
  ([#217](https://github.com/MountainGod2/cb-events/pull/217),
  [`a1d092e`](https://github.com/MountainGod2/cb-events/commit/a1d092e35f47940455f439627245bff59b7ec8e2))

- **models**: Change media type to str ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **models**: Clean up imports and fix media type docstring
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **models**: Remove caching logic from Event model
  ([#222](https://github.com/MountainGod2/cb-events/pull/222),
  [`1628580`](https://github.com/MountainGod2/cb-events/commit/1628580c241ce24fbbb6dbccff3af51e78a2f129))

- **models**: Replace Literal types with str for User fields
  ([#222](https://github.com/MountainGod2/cb-events/pull/222),
  [`1628580`](https://github.com/MountainGod2/cb-events/commit/1628580c241ce24fbbb6dbccff3af51e78a2f129))

- **pre-commit**: Simplify hooks and remove pip-audit
  ([#229](https://github.com/MountainGod2/cb-events/pull/229),
  [`7ad0dc7`](https://github.com/MountainGod2/cb-events/commit/7ad0dc7559ad41eecedad1bce327ad63e487b788))

- **pyproject**: Add aiohttp 3.14 restriction for compatibility with aioresponses
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **release**: Update validation for CB_EVENTS_URL
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **router**: Add async callable check logic
  ([#234](https://github.com/MountainGod2/cb-events/pull/234),
  [`4a5e11d`](https://github.com/MountainGod2/cb-events/commit/4a5e11d0bcab85f789b6cedcdd74324e36cf8408))

- **router**: Change typed_handlers to use list
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **router**: Improve async callable check logic
  ([#234](https://github.com/MountainGod2/cb-events/pull/234),
  [`4a5e11d`](https://github.com/MountainGod2/cb-events/commit/4a5e11d0bcab85f789b6cedcdd74324e36cf8408))

- **router**: Optimize handler registration logic
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **router**: Simplify callable check ([#234](https://github.com/MountainGod2/cb-events/pull/234),
  [`4a5e11d`](https://github.com/MountainGod2/cb-events/commit/4a5e11d0bcab85f789b6cedcdd74324e36cf8408))

- **router**: Simplify handler name retrieval logic
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **tests**: Remove aiohttp constraint from test dependencies
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **tests**: Remove unused callable wrapper classes
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **typing**: Replace Self import with typing_extensions
  ([#234](https://github.com/MountainGod2/cb-events/pull/234),
  [`4a5e11d`](https://github.com/MountainGod2/cb-events/commit/4a5e11d0bcab85f789b6cedcdd74324e36cf8408))

- **uv**: Include aiohttp in exclude-newer-package
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **uv**: Remove aiohttp from exclude-newer-package
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))

- **uv**: Replace required-version with exclude-newer-package
  ([#219](https://github.com/MountainGod2/cb-events/pull/219),
  [`97be6ef`](https://github.com/MountainGod2/cb-events/commit/97be6ef695fbd3bd418b821839cca734006dd796))

- **xenon**: Update max-absolute argument
  ([#224](https://github.com/MountainGod2/cb-events/pull/224),
  [`76490c5`](https://github.com/MountainGod2/cb-events/commit/76490c562ff1529bcba81c79980a2ee939665521))


## v9.0.2 (2026-05-30)

### Bug Fixes

- **models**: Handle None in allowed_types check
  ([#212](https://github.com/MountainGod2/cb-events/pull/212),
  [`d19069b`](https://github.com/MountainGod2/cb-events/commit/d19069b315d9c2bdbed430af1b78e23b667429b5))

### Refactoring

- **client**: Consolidate retry status codes and session management
  ([#189](https://github.com/MountainGod2/cb-events/pull/189),
  [`e6d19fa`](https://github.com/MountainGod2/cb-events/commit/e6d19fa62207c082252f2f41d3839a0279b99490))

- **client**: Extract nextUrl validation logging
  ([#207](https://github.com/MountainGod2/cb-events/pull/207),
  [`c9c20c9`](https://github.com/MountainGod2/cb-events/commit/c9c20c96e0ae003a42dc719d9673a0a1f96950c0))

- **client**: Implement terminal state checks
  ([#212](https://github.com/MountainGod2/cb-events/pull/212),
  [`d19069b`](https://github.com/MountainGod2/cb-events/commit/d19069b315d9c2bdbed430af1b78e23b667429b5))

- **client**: Improve validation and error handling
  ([#194](https://github.com/MountainGod2/cb-events/pull/194),
  [`421af0f`](https://github.com/MountainGod2/cb-events/commit/421af0ff112432a3af0eca83ee39ba003dd7f6ed))

- **client**: Improve variable assignment in EventClient
  ([#212](https://github.com/MountainGod2/cb-events/pull/212),
  [`d19069b`](https://github.com/MountainGod2/cb-events/commit/d19069b315d9c2bdbed430af1b78e23b667429b5))

- **client**: Include username in error logging
  ([#212](https://github.com/MountainGod2/cb-events/pull/212),
  [`d19069b`](https://github.com/MountainGod2/cb-events/commit/d19069b315d9c2bdbed430af1b78e23b667429b5))

- **client**: Remove unused attributes from EventClient
  ([#212](https://github.com/MountainGod2/cb-events/pull/212),
  [`d19069b`](https://github.com/MountainGod2/cb-events/commit/d19069b315d9c2bdbed430af1b78e23b667429b5))

- **client**: Rename exception for retryable status errors
  ([#185](https://github.com/MountainGod2/cb-events/pull/185),
  [`fb8a648`](https://github.com/MountainGod2/cb-events/commit/fb8a648f77c3647f4a4e2cea40c20c9bb3b2d611))

- **client**: Simplify async iterator implementation
  ([#212](https://github.com/MountainGod2/cb-events/pull/212),
  [`d19069b`](https://github.com/MountainGod2/cb-events/commit/d19069b315d9c2bdbed430af1b78e23b667429b5))

- **client**: Simplify type hints and improve error handling
  ([#207](https://github.com/MountainGod2/cb-events/pull/207),
  [`c9c20c9`](https://github.com/MountainGod2/cb-events/commit/c9c20c96e0ae003a42dc719d9673a0a1f96950c0))

- **client**: Update URL parsing and error handling
  ([#181](https://github.com/MountainGod2/cb-events/pull/181),
  [`b3cf7c2`](https://github.com/MountainGod2/cb-events/commit/b3cf7c27560d36c23aebf2cbae8051d341f6014c))

- **docker**: Add Docker example and update event handling
  ([#193](https://github.com/MountainGod2/cb-events/pull/193),
  [`7c4908a`](https://github.com/MountainGod2/cb-events/commit/7c4908a6dae37f768ecef1bc1c51b0e4043f2fb4))

- **docker**: Move Docker example and configuration
  ([#193](https://github.com/MountainGod2/cb-events/pull/193),
  [`7c4908a`](https://github.com/MountainGod2/cb-events/commit/7c4908a6dae37f768ecef1bc1c51b0e4043f2fb4))

- **docker**: Update Dockerfile build process
  ([#187](https://github.com/MountainGod2/cb-events/pull/187),
  [`51bb2b4`](https://github.com/MountainGod2/cb-events/commit/51bb2b402a783d1e5cd535803c5585dfc5da710c))

- **docs**: Restructure error handling examples
  ([#203](https://github.com/MountainGod2/cb-events/pull/203),
  [`dca6931`](https://github.com/MountainGod2/cb-events/commit/dca693106b3350c1a976c37aa682f446d5072c82))

- **exceptions**: Simplify error handling for Cloudflare codes
  ([#189](https://github.com/MountainGod2/cb-events/pull/189),
  [`e6d19fa`](https://github.com/MountainGod2/cb-events/commit/e6d19fa62207c082252f2f41d3839a0279b99490))

- **exceptions**: Use HTTPStatus for error codes
  ([#207](https://github.com/MountainGod2/cb-events/pull/207),
  [`c9c20c9`](https://github.com/MountainGod2/cb-events/commit/c9c20c96e0ae003a42dc719d9673a0a1f96950c0))

- **model_config**: Update type hints for class settings
  ([#207](https://github.com/MountainGod2/cb-events/pull/207),
  [`c9c20c9`](https://github.com/MountainGod2/cb-events/commit/c9c20c96e0ae003a42dc719d9673a0a1f96950c0))

- **router**: Convert handlers to tuples for consistency
  ([#207](https://github.com/MountainGod2/cb-events/pull/207),
  [`c9c20c9`](https://github.com/MountainGod2/cb-events/commit/c9c20c96e0ae003a42dc719d9673a0a1f96950c0))

- **router**: Improve event handler dispatch logic
  ([#207](https://github.com/MountainGod2/cb-events/pull/207),
  [`c9c20c9`](https://github.com/MountainGod2/cb-events/commit/c9c20c96e0ae003a42dc719d9673a0a1f96950c0))

- **router**: Update on_any decorator usage
  ([#212](https://github.com/MountainGod2/cb-events/pull/212),
  [`d19069b`](https://github.com/MountainGod2/cb-events/commit/d19069b315d9c2bdbed430af1b78e23b667429b5))

- **tests**: Improve error handling in URL validation
  ([#194](https://github.com/MountainGod2/cb-events/pull/194),
  [`421af0f`](https://github.com/MountainGod2/cb-events/commit/421af0ff112432a3af0eca83ee39ba003dd7f6ed))

- **tests**: Move TESTBED_POLL_URL to test file
  ([#212](https://github.com/MountainGod2/cb-events/pull/212),
  [`d19069b`](https://github.com/MountainGod2/cb-events/commit/d19069b315d9c2bdbed430af1b78e23b667429b5))

- **tests**: Remove redundant stamina state setup
  ([#212](https://github.com/MountainGod2/cb-events/pull/212),
  [`d19069b`](https://github.com/MountainGod2/cb-events/commit/d19069b315d9c2bdbed430af1b78e23b667429b5))


## v9.0.1 (2026-05-19)

### Bug Fixes

- **makefile**: Simplify requirements-check command
  ([#175](https://github.com/MountainGod2/cb-events/pull/175),
  [`9a97ef0`](https://github.com/MountainGod2/cb-events/commit/9a97ef0c1c6c0649eaf0077dae02c04c090191ab))


## v9.0.0 (2026-05-18)

### Features

- Switch to URL-based Events API configuration
  ([#167](https://github.com/MountainGod2/cb-events/pull/167),
  [`93c7e80`](https://github.com/MountainGod2/cb-events/commit/93c7e8041e1c2bc53925bbc9c3a087c70b34ac1d))

- **pre-commit**: Add docstrfmt for formatting RST files
  ([#167](https://github.com/MountainGod2/cb-events/pull/167),
  [`93c7e80`](https://github.com/MountainGod2/cb-events/commit/93c7e8041e1c2bc53925bbc9c3a087c70b34ac1d))

### Refactoring

- **ci**: Streamline CI/CD workflow and commands
  ([#165](https://github.com/MountainGod2/cb-events/pull/165),
  [`8504aad`](https://github.com/MountainGod2/cb-events/commit/8504aada03ebae85d6bb71a7122bd05f7081b390))

- **client**: Improve validation for events URL port
  ([#167](https://github.com/MountainGod2/cb-events/pull/167),
  [`93c7e80`](https://github.com/MountainGod2/cb-events/commit/93c7e8041e1c2bc53925bbc9c3a087c70b34ac1d))

- **examples**: Require CB_EVENTS_URL ([#167](https://github.com/MountainGod2/cb-events/pull/167),
  [`93c7e80`](https://github.com/MountainGod2/cb-events/commit/93c7e8041e1c2bc53925bbc9c3a087c70b34ac1d))

- **readme**: Add Star History section with chart
  ([#165](https://github.com/MountainGod2/cb-events/pull/165),
  [`8504aad`](https://github.com/MountainGod2/cb-events/commit/8504aada03ebae85d6bb71a7122bd05f7081b390))

- **readme**: Simplify note admonitions in substitutions
  ([#165](https://github.com/MountainGod2/cb-events/pull/165),
  [`8504aad`](https://github.com/MountainGod2/cb-events/commit/8504aada03ebae85d6bb71a7122bd05f7081b390))

- **readme**: Update pattern to remove Star History section
  ([#165](https://github.com/MountainGod2/cb-events/pull/165),
  [`8504aad`](https://github.com/MountainGod2/cb-events/commit/8504aada03ebae85d6bb71a7122bd05f7081b390))

- **tests**: Improve event client factory logic and add testbed URL check
  ([#167](https://github.com/MountainGod2/cb-events/pull/167),
  [`93c7e80`](https://github.com/MountainGod2/cb-events/commit/93c7e8041e1c2bc53925bbc9c3a087c70b34ac1d))

- **tests**: Update e2e test marker description
  ([#167](https://github.com/MountainGod2/cb-events/pull/167),
  [`93c7e80`](https://github.com/MountainGod2/cb-events/commit/93c7e8041e1c2bc53925bbc9c3a087c70b34ac1d))

- **tests**: Update test-live command to include e2e
  ([#167](https://github.com/MountainGod2/cb-events/pull/167),
  [`93c7e80`](https://github.com/MountainGod2/cb-events/commit/93c7e8041e1c2bc53925bbc9c3a087c70b34ac1d))

- **tests**: Update URL validation for events API
  ([#167](https://github.com/MountainGod2/cb-events/pull/167),
  [`93c7e80`](https://github.com/MountainGod2/cb-events/commit/93c7e8041e1c2bc53925bbc9c3a087c70b34ac1d))


## v8.1.3 (2026-05-14)

### Bug Fixes

- **ci**: Simplify build metadata handling
  ([#164](https://github.com/MountainGod2/cb-events/pull/164),
  [`d90974e`](https://github.com/MountainGod2/cb-events/commit/d90974e6ee22834683f4310fd1c80802063970a5))


## v8.1.2 (2026-05-13)

### Bug Fixes

- **ci**: Change permissions for release job and persist bot credentials
  ([#163](https://github.com/MountainGod2/cb-events/pull/163),
  [`f04bb2b`](https://github.com/MountainGod2/cb-events/commit/f04bb2b9783cb4b1a0a49db9acc52d31c858327f))


## v8.1.1 (2026-05-12)

### Bug Fixes

- **deps**: Add requirements.txt for pip-audit scanning
  ([#161](https://github.com/MountainGod2/cb-events/pull/161),
  [`bd07145`](https://github.com/MountainGod2/cb-events/commit/bd0714564cadf5d9a43fa30368bbf93e7a2d9830))

- **deps**: Widen supported dependency versions
  ([#161](https://github.com/MountainGod2/cb-events/pull/161),
  [`bd07145`](https://github.com/MountainGod2/cb-events/commit/bd0714564cadf5d9a43fa30368bbf93e7a2d9830))

- **pre-commit**: Update requirements-sync entry to use bash
  ([#161](https://github.com/MountainGod2/cb-events/pull/161),
  [`bd07145`](https://github.com/MountainGod2/cb-events/commit/bd0714564cadf5d9a43fa30368bbf93e7a2d9830))

- **renovate**: Update runtime scope and disable automerge for vulnerability alerts
  ([#161](https://github.com/MountainGod2/cb-events/pull/161),
  [`bd07145`](https://github.com/MountainGod2/cb-events/commit/bd0714564cadf5d9a43fa30368bbf93e7a2d9830))


## v8.1.0 (2026-05-10)

### Features

- **pyproject**: Remove refactor pattern from commit exclusions
  ([#160](https://github.com/MountainGod2/cb-events/pull/160),
  [`bad9d6d`](https://github.com/MountainGod2/cb-events/commit/bad9d6d92725c926d10c9f4d7dbbf84442b0bf50))


## v8.0.10 (2026-05-10)

### Bug Fixes

- Update permissions and author for release process
  ([#159](https://github.com/MountainGod2/cb-events/pull/159),
  [`8556b42`](https://github.com/MountainGod2/cb-events/commit/8556b42861ff665f253a47ede87490562d40d1a9))

- **ci**: Update permissions and author for release process
  ([#159](https://github.com/MountainGod2/cb-events/pull/159),
  [`8556b42`](https://github.com/MountainGod2/cb-events/commit/8556b42861ff665f253a47ede87490562d40d1a9))


## v8.0.9 (2026-05-08)

### Bug Fixes

- **client**: Enforce HTTPS scheme for nextUrl validation
  ([#154](https://github.com/MountainGod2/cb-events/pull/154),
  [`a2463b9`](https://github.com/MountainGod2/cb-events/commit/a2463b92b260ec3298e7ad9b20d5c395dca692eb))


## v8.0.8 (2026-05-05)

### Bug Fixes

- Add pip to constraint-dependencies ([#151](https://github.com/MountainGod2/cb-events/pull/151),
  [`75fa17c`](https://github.com/MountainGod2/cb-events/commit/75fa17cf56f6c334789ef55f33010b7089fcfc67))

### Refactoring

- Improve error handling in EventClient ([#149](https://github.com/MountainGod2/cb-events/pull/149),
  [`f92aa6f`](https://github.com/MountainGod2/cb-events/commit/f92aa6f499f633f2171bc833e504bf8df5b7de3e))

- **client**: Add method to resolve absolute URLs
  ([#143](https://github.com/MountainGod2/cb-events/pull/143),
  [`40ea972`](https://github.com/MountainGod2/cb-events/commit/40ea972e5dd96abfbc82742dc0322ab2e5dd2ee4))

- **client**: Handle missing scheme in URL parsing
  ([#143](https://github.com/MountainGod2/cb-events/pull/143),
  [`40ea972`](https://github.com/MountainGod2/cb-events/commit/40ea972e5dd96abfbc82742dc0322ab2e5dd2ee4))

- **client**: Improve error handling in EventClient
  ([#149](https://github.com/MountainGod2/cb-events/pull/149),
  [`f92aa6f`](https://github.com/MountainGod2/cb-events/commit/f92aa6f499f633f2171bc833e504bf8df5b7de3e))

- **docker**: Rearrange environment variables and entrypoint
  ([#150](https://github.com/MountainGod2/cb-events/pull/150),
  [`8925aef`](https://github.com/MountainGod2/cb-events/commit/8925aef69210752e7d539b046d40eee2154b7261))

- **docker**: Update runtime environment settings
  ([#150](https://github.com/MountainGod2/cb-events/pull/150),
  [`8925aef`](https://github.com/MountainGod2/cb-events/commit/8925aef69210752e7d539b046d40eee2154b7261))

- **makefile**: Streamline lint checks ([#144](https://github.com/MountainGod2/cb-events/pull/144),
  [`daadeea`](https://github.com/MountainGod2/cb-events/commit/daadeeaf9d7269ee76eb5ed1c57500e993fda3ba))

- **tests**: Unify event payload structure in helpers
  ([#149](https://github.com/MountainGod2/cb-events/pull/149),
  [`f92aa6f`](https://github.com/MountainGod2/cb-events/commit/f92aa6f499f633f2171bc833e504bf8df5b7de3e))


## v8.0.7 (2026-04-27)

### Bug Fixes

- **deps**: Add GitPython constraint ([#141](https://github.com/MountainGod2/cb-events/pull/141),
  [`28ee76c`](https://github.com/MountainGod2/cb-events/commit/28ee76c3e72064d868f3f1254beb9bec5bdcd3fd))

- **runtime**: Update dependency pydantic to >=2.13.3
  ([#141](https://github.com/MountainGod2/cb-events/pull/141),
  [`28ee76c`](https://github.com/MountainGod2/cb-events/commit/28ee76c3e72064d868f3f1254beb9bec5bdcd3fd))


## v8.0.6 (2026-04-25)

### Bug Fixes

- **runtime**: Update dependency pydantic to >=2.13.2
  ([#139](https://github.com/MountainGod2/cb-events/pull/139),
  [`10d5fdb`](https://github.com/MountainGod2/cb-events/commit/10d5fdb29e044a8e29207f0d630a09e55e3665d0))


## v8.0.5 (2026-04-24)

### Bug Fixes

- **runtime**: Update dependency pydantic to >=2.13.1
  ([#129](https://github.com/MountainGod2/cb-events/pull/129),
  [`174d46b`](https://github.com/MountainGod2/cb-events/commit/174d46bf5a3520d996e5a9dd7f042fdea49b15b1))


## v8.0.4 (2026-04-21)

### Bug Fixes

- **runtime**: Update dependency stamina to v26
  ([`1734acc`](https://github.com/MountainGod2/cb-events/commit/1734acc86be039182dea441dfc61d7ae62dc2507))


## v8.0.3 (2026-04-21)

### Bug Fixes

- **runtime**: Update dependency pydantic to >=2.13.0
  ([`9a48ce8`](https://github.com/MountainGod2/cb-events/commit/9a48ce845d114882a7e2ceaa0be2f7a60b6dc618))

### Refactoring

- **Makefile**: Add pip-audit scan to security group
  ([`fbedc2c`](https://github.com/MountainGod2/cb-events/commit/fbedc2c0c33172dd46437cdebb5bc1083f8f80ab))

- **Makefile**: Add zizmor to security checks
  ([`f6416e2`](https://github.com/MountainGod2/cb-events/commit/f6416e21c40ac6c3d28d5381bd36fe75cc745e39))

- **Makefile**: Reorganize targets and improve structure
  ([`e1295a9`](https://github.com/MountainGod2/cb-events/commit/e1295a9ee04b51f0fe213c1f23e4996309aca96b))

- **pyproject**: Update dev dependency groups for typecheck
  ([`e359211`](https://github.com/MountainGod2/cb-events/commit/e359211fa76061ada80ba281b7de57dfbccc3d36))


## v8.0.2 (2026-04-20)

### Bug Fixes

- **semantic_release**: Update commit patterns for changelog
  ([`5b0c8e1`](https://github.com/MountainGod2/cb-events/commit/5b0c8e1916288c1c7fea6e52a13f65e590d5f0ec))

### Refactoring

- **api_response**: Rename example API response
  ([`5d7f4d9`](https://github.com/MountainGod2/cb-events/commit/5d7f4d92d416a96139cd07661c113582e81a82ad))

- **models**: Disable pylint warning for broadcaster access
  ([`833f745`](https://github.com/MountainGod2/cb-events/commit/833f745377454eed7581978f8c64efcabcaf22c3))

- **models**: Update broadcaster property to return None if missing
  ([`d6c55a9`](https://github.com/MountainGod2/cb-events/commit/d6c55a987b988df0fc948b71d031c0a1b0871420))

- **tip_activated_lights**: Improve environment variable handling
  ([`97f61e6`](https://github.com/MountainGod2/cb-events/commit/97f61e64bf97533c91dda02172b54a5037f33638))

- **tip_activated_lights**: Improve light state management
  ([`7f44dc2`](https://github.com/MountainGod2/cb-events/commit/7f44dc2e16d3c02af9f8bf58ce5a73a32065090c))


## v8.0.1 (2026-04-18)

### Bug Fixes

- **models**: Improve handling of empty string subgender
  ([#115](https://github.com/MountainGod2/cb-events/pull/115),
  [`f1f0ece`](https://github.com/MountainGod2/cb-events/commit/f1f0ece80e7e7ffb7d87472811454c94b8df65cf))

### Refactoring

- **event_handling**: Improve log level configuration
  ([#115](https://github.com/MountainGod2/cb-events/pull/115),
  [`f1f0ece`](https://github.com/MountainGod2/cb-events/commit/f1f0ece80e7e7ffb7d87472811454c94b8df65cf))

- **models**: Simplify user model field descriptions
  ([#115](https://github.com/MountainGod2/cb-events/pull/115),
  [`f1f0ece`](https://github.com/MountainGod2/cb-events/commit/f1f0ece80e7e7ffb7d87472811454c94b8df65cf))


## v8.0.0 (2026-04-18)

### Refactoring

- Improve text truncation and caching logic
  ([#112](https://github.com/MountainGod2/cb-events/pull/112),
  [`c059904`](https://github.com/MountainGod2/cb-events/commit/c059904ddc3c618f74d6856a5d1e5d17480f59b6))

- Removed option to extend additional URLs
  ([#114](https://github.com/MountainGod2/cb-events/pull/114),
  [`a9534fb`](https://github.com/MountainGod2/cb-events/commit/a9534fb54ab7c5efed9182bf2625470632dc2328))

- Reorganize renovate rules, update linting, and improve docs
  ([#109](https://github.com/MountainGod2/cb-events/pull/109),
  [`e80b159`](https://github.com/MountainGod2/cb-events/commit/e80b159b2a49d694e17ce6fe54b4a8b5535192ff))

- Replace pyrefly and pyright with basedpyright
  ([#111](https://github.com/MountainGod2/cb-events/pull/111),
  [`265de69`](https://github.com/MountainGod2/cb-events/commit/265de69bcf89d5890cb88d8e886de6a5a0658098))

- Simplify cache handling and imports ([#112](https://github.com/MountainGod2/cb-events/pull/112),
  [`c059904`](https://github.com/MountainGod2/cb-events/commit/c059904ddc3c618f74d6856a5d1e5d17480f59b6))

- **exceptions**: Ignore private usage warning for _TRUNCATE_LENGTH
  ([#111](https://github.com/MountainGod2/cb-events/pull/111),
  [`265de69`](https://github.com/MountainGod2/cb-events/commit/265de69bcf89d5890cb88d8e886de6a5a0658098))

- **exceptions**: Raise ValueError for negative limit in truncate_text
  ([#112](https://github.com/MountainGod2/cb-events/pull/112),
  [`c059904`](https://github.com/MountainGod2/cb-events/commit/c059904ddc3c618f74d6856a5d1e5d17480f59b6))

- **exceptions**: Remove deprecated _TRUNCATE_LENGTH
  ([#112](https://github.com/MountainGod2/cb-events/pull/112),
  [`c059904`](https://github.com/MountainGod2/cb-events/commit/c059904ddc3c618f74d6856a5d1e5d17480f59b6))

- **exceptions**: Rename TRUNCATE_LENGTH to _TRUNCATE_LENGTH
  ([#111](https://github.com/MountainGod2/cb-events/pull/111),
  [`265de69`](https://github.com/MountainGod2/cb-events/commit/265de69bcf89d5890cb88d8e886de6a5a0658098))

- **renovate**: Simplify group names and scopes
  ([#109](https://github.com/MountainGod2/cb-events/pull/109),
  [`e80b159`](https://github.com/MountainGod2/cb-events/commit/e80b159b2a49d694e17ce6fe54b4a8b5535192ff))

- **tests**: Improve test coverage and docs
  ([#109](https://github.com/MountainGod2/cb-events/pull/109),
  [`e80b159`](https://github.com/MountainGod2/cb-events/commit/e80b159b2a49d694e17ce6fe54b4a8b5535192ff))


## v7.1.2 (2026-04-13)

### Bug Fixes

- **security**: Update dependency pytest to v9.0.3 [security]
  ([#104](https://github.com/MountainGod2/cb-events/pull/104),
  [`0fc4480`](https://github.com/MountainGod2/cb-events/commit/0fc4480d73e65466ac37e314e8edc0ca52ad9c7f))

### Refactoring

- **Dockerfile**: Replace pip install with COPY for uv
  ([#103](https://github.com/MountainGod2/cb-events/pull/103),
  [`26fc564`](https://github.com/MountainGod2/cb-events/commit/26fc564ea7cc8eb05add378c630946e54791e41c))

- **uv**: Add pytest to exclude-newer-package
  ([#105](https://github.com/MountainGod2/cb-events/pull/105),
  [`37c6d14`](https://github.com/MountainGod2/cb-events/commit/37c6d14336e64fe0d98ab5ad95f4d7028930668e))


## v7.1.1 (2026-04-13)

### Bug Fixes

- Update admonitions pattern ([#102](https://github.com/MountainGod2/cb-events/pull/102),
  [`51eac6c`](https://github.com/MountainGod2/cb-events/commit/51eac6c5d9f1c268a58dc58931f51808b5e44491))

- **pyproject**: Update admonitions pattern
  ([#102](https://github.com/MountainGod2/cb-events/pull/102),
  [`51eac6c`](https://github.com/MountainGod2/cb-events/commit/51eac6c5d9f1c268a58dc58931f51808b5e44491))

### Refactoring

- Improve signal handling and shutdown process
  ([#101](https://github.com/MountainGod2/cb-events/pull/101),
  [`60cc836`](https://github.com/MountainGod2/cb-events/commit/60cc836442f22c780ed3e2a7ffe23479bac86f1b))

- **event_handling**: Improve signal handling and shutdown process
  ([#101](https://github.com/MountainGod2/cb-events/pull/101),
  [`60cc836`](https://github.com/MountainGod2/cb-events/commit/60cc836442f22c780ed3e2a7ffe23479bac86f1b))


## v7.1.0 (2026-04-11)

### Features

- Convert next_url_allowed_hosts to tuple and reorganize constants
  ([#100](https://github.com/MountainGod2/cb-events/pull/100),
  [`57ea719`](https://github.com/MountainGod2/cb-events/commit/57ea7190ea266668d4bfc97a5a92577a2b55de30))

### Refactoring

- **client**: Update type hints ([#100](https://github.com/MountainGod2/cb-events/pull/100),
  [`57ea719`](https://github.com/MountainGod2/cb-events/commit/57ea7190ea266668d4bfc97a5a92577a2b55de30))

- **exceptions**: Simplify error handling
  ([#100](https://github.com/MountainGod2/cb-events/pull/100),
  [`57ea719`](https://github.com/MountainGod2/cb-events/commit/57ea7190ea266668d4bfc97a5a92577a2b55de30))

- **exceptions**: Update status code definitions
  ([#100](https://github.com/MountainGod2/cb-events/pull/100),
  [`57ea719`](https://github.com/MountainGod2/cb-events/commit/57ea7190ea266668d4bfc97a5a92577a2b55de30))

- **makefile**: Rename test-all to check-all
  ([#100](https://github.com/MountainGod2/cb-events/pull/100),
  [`57ea719`](https://github.com/MountainGod2/cb-events/commit/57ea7190ea266668d4bfc97a5a92577a2b55de30))

- **router**: Simplify handler logging and type checks
  ([#100](https://github.com/MountainGod2/cb-events/pull/100),
  [`57ea719`](https://github.com/MountainGod2/cb-events/commit/57ea7190ea266668d4bfc97a5a92577a2b55de30))

- **tests**: Remove TOKEN_VISIBLE_CHARS assertions
  ([#100](https://github.com/MountainGod2/cb-events/pull/100),
  [`57ea719`](https://github.com/MountainGod2/cb-events/commit/57ea7190ea266668d4bfc97a5a92577a2b55de30))


## v7.0.1 (2026-04-09)

### Bug Fixes

- Handle status_code check for None ([#93](https://github.com/MountainGod2/cb-events/pull/93),
  [`b02019e`](https://github.com/MountainGod2/cb-events/commit/b02019e8c47d2073a3e2bc3e49c0785ca3ed4f5a))

- **exceptions**: Handle status_code check for None
  ([#93](https://github.com/MountainGod2/cb-events/pull/93),
  [`b02019e`](https://github.com/MountainGod2/cb-events/commit/b02019e8c47d2073a3e2bc3e49c0785ca3ed4f5a))

### Refactoring

- **__init__**: Change __all__ from list to tuple
  ([#93](https://github.com/MountainGod2/cb-events/pull/93),
  [`b02019e`](https://github.com/MountainGod2/cb-events/commit/b02019e8c47d2073a3e2bc3e49c0785ca3ed4f5a))

- **client**: Replace timeout attribute with config.timeout
  ([#93](https://github.com/MountainGod2/cb-events/pull/93),
  [`b02019e`](https://github.com/MountainGod2/cb-events/commit/b02019e8c47d2073a3e2bc3e49c0785ca3ed4f5a))

- **models**: Replace cached_property with property
  ([#93](https://github.com/MountainGod2/cb-events/pull/93),
  [`b02019e`](https://github.com/MountainGod2/cb-events/commit/b02019e8c47d2073a3e2bc3e49c0785ca3ed4f5a))


## v7.0.0 (2026-04-08)

### Refactoring

- Update workflow and dependency groups ([#81](https://github.com/MountainGod2/cb-events/pull/81),
  [`1efa39d`](https://github.com/MountainGod2/cb-events/commit/1efa39d12ff77316bbf8612e250893c90ac67b25))

- **config**: Change `strict_validation` default to false
  ([#92](https://github.com/MountainGod2/cb-events/pull/92),
  [`eb3ab1c`](https://github.com/MountainGod2/cb-events/commit/eb3ab1ceaa9465069b0790e254f6aef2bd3c3f7e))

- **docs**: Clean up comments and improve docstrings
  ([#90](https://github.com/MountainGod2/cb-events/pull/90),
  [`5a728ab`](https://github.com/MountainGod2/cb-events/commit/5a728aba47e94dee928b02f3719cd242069faefc))

- **examples**: Standardize color timeout validation logic
  ([#82](https://github.com/MountainGod2/cb-events/pull/82),
  [`e7ebe59`](https://github.com/MountainGod2/cb-events/commit/e7ebe599760b35cf5b52440b5c838cba74b8ecf4))

- **Makefile**: Restore format command ([#81](https://github.com/MountainGod2/cb-events/pull/81),
  [`1efa39d`](https://github.com/MountainGod2/cb-events/commit/1efa39d12ff77316bbf8612e250893c90ac67b25))


## v6.3.1 (2026-04-01)

### Bug Fixes

- **deps**: Update aiohttp to v3.13.5 and adjust settings
  ([#78](https://github.com/MountainGod2/cb-events/pull/78),
  [`425d141`](https://github.com/MountainGod2/cb-events/commit/425d141d2c0bf8899e43418618da971d07fd9131))


## v6.3.0 (2026-03-30)

### Features

- Expand support to cover Python 3.10+ ([#71](https://github.com/MountainGod2/cb-events/pull/71),
  [`ddaace2`](https://github.com/MountainGod2/cb-events/commit/ddaace2600e220ae8bcc48eadeab6e0aa66e04c8))

- Update supported Python versions ([#71](https://github.com/MountainGod2/cb-events/pull/71),
  [`ddaace2`](https://github.com/MountainGod2/cb-events/commit/ddaace2600e220ae8bcc48eadeab6e0aa66e04c8))

### Refactoring

- **client**: Improve error message for request failures
  ([#70](https://github.com/MountainGod2/cb-events/pull/70),
  [`ea2aa56`](https://github.com/MountainGod2/cb-events/commit/ea2aa56930d6bdd31655b9f4327dd1c762a72dad))

- **client**: Simplify error messages and notes
  ([#70](https://github.com/MountainGod2/cb-events/pull/70),
  [`ea2aa56`](https://github.com/MountainGod2/cb-events/commit/ea2aa56930d6bdd31655b9f4327dd1c762a72dad))

- **exceptions**: Add AuthError handling in build_http_error
  ([#71](https://github.com/MountainGod2/cb-events/pull/71),
  [`ddaace2`](https://github.com/MountainGod2/cb-events/commit/ddaace2600e220ae8bcc48eadeab6e0aa66e04c8))

- **exceptions**: Remove unused Cloudflare error codes
  ([#71](https://github.com/MountainGod2/cb-events/pull/71),
  [`ddaace2`](https://github.com/MountainGod2/cb-events/commit/ddaace2600e220ae8bcc48eadeab6e0aa66e04c8))

- **models**: Rename TypeVar ([#71](https://github.com/MountainGod2/cb-events/pull/71),
  [`ddaace2`](https://github.com/MountainGod2/cb-events/commit/ddaace2600e220ae8bcc48eadeab6e0aa66e04c8))

- **pre-commit**: Update ruff-check args for exit code
  ([#71](https://github.com/MountainGod2/cb-events/pull/71),
  [`ddaace2`](https://github.com/MountainGod2/cb-events/commit/ddaace2600e220ae8bcc48eadeab6e0aa66e04c8))

- **router**: Remove redundant comment in dispatch example
  ([#70](https://github.com/MountainGod2/cb-events/pull/70),
  [`ea2aa56`](https://github.com/MountainGod2/cb-events/commit/ea2aa56930d6bdd31655b9f4327dd1c762a72dad))


## v6.2.0 (2026-03-26)

### Bug Fixes

- **docs**: Update error handling example for async usage
  ([#68](https://github.com/MountainGod2/cb-events/pull/68),
  [`adb2241`](https://github.com/MountainGod2/cb-events/commit/adb2241a88cf11076f85477f307bf6e82c5e43fa))

### Features

- **docs**: Add additional doc pages for config and installation
  ([#68](https://github.com/MountainGod2/cb-events/pull/68),
  [`adb2241`](https://github.com/MountainGod2/cb-events/commit/adb2241a88cf11076f85477f307bf6e82c5e43fa))


## v6.1.4 (2026-03-22)

### Bug Fixes

- **ci**: Add GPG signing to publish steps in CI/CD
  ([#64](https://github.com/MountainGod2/cb-events/pull/64),
  [`056ec1c`](https://github.com/MountainGod2/cb-events/commit/056ec1c53975bf863f15e69d1060cf8acacff1d6))


## v6.1.3 (2026-03-21)

### Bug Fixes

- **ci**: Update GitHub Actions to use GH_PAT for token
  ([#63](https://github.com/MountainGod2/cb-events/pull/63),
  [`599dece`](https://github.com/MountainGod2/cb-events/commit/599dece4b24d58f5c56aa75b5b6ffa9cfb9df4c2))

- **client**: Improve error handling and logging in EventClient
  ([#62](https://github.com/MountainGod2/cb-events/pull/62),
  [`79f9248`](https://github.com/MountainGod2/cb-events/commit/79f92487298eb6a57c531fd7fef8bc7049580066))

### Refactoring

- **config**: Remove redundant attribute documentation
  ([#62](https://github.com/MountainGod2/cb-events/pull/62),
  [`79f9248`](https://github.com/MountainGod2/cb-events/commit/79f92487298eb6a57c531fd7fef8bc7049580066))

- **docs**: Simplify docs dependency list ([#62](https://github.com/MountainGod2/cb-events/pull/62),
  [`79f9248`](https://github.com/MountainGod2/cb-events/commit/79f92487298eb6a57c531fd7fef8bc7049580066))

- **docs**: Update Sphinx configuration settings
  ([#62](https://github.com/MountainGod2/cb-events/pull/62),
  [`79f9248`](https://github.com/MountainGod2/cb-events/commit/79f92487298eb6a57c531fd7fef8bc7049580066))

- **exceptions**: Remove redundant attribute documentation
  ([#62](https://github.com/MountainGod2/cb-events/pull/62),
  [`79f9248`](https://github.com/MountainGod2/cb-events/commit/79f92487298eb6a57c531fd7fef8bc7049580066))

- **models**: Improve BaseEventModel documentation
  ([#62](https://github.com/MountainGod2/cb-events/pull/62),
  [`79f9248`](https://github.com/MountainGod2/cb-events/commit/79f92487298eb6a57c531fd7fef8bc7049580066))

- **models**: Remove redundant attribute documentation
  ([#62](https://github.com/MountainGod2/cb-events/pull/62),
  [`79f9248`](https://github.com/MountainGod2/cb-events/commit/79f92487298eb6a57c531fd7fef8bc7049580066))


## v6.1.2 (2026-03-20)

### Bug Fixes

- **semantic-release**: Update commit author for GitHub Actions
  ([`6a93c8a`](https://github.com/MountainGod2/cb-events/commit/6a93c8addc781cb461232b643d221ed6f014b6d1))


## v6.1.1 (2026-03-20)

### Bug Fixes

- **semantic-release**: Add commit author for GitHub Actions
  ([`717c94c`](https://github.com/MountainGod2/cb-events/commit/717c94c5cb5738ea3bdf314ad431757dad420fa6))


## v6.1.0 (2026-03-20)

### Features

- **pre-commit**: Add gitleaks secret scan hook
  ([#61](https://github.com/MountainGod2/cb-events/pull/61),
  [`10d5651`](https://github.com/MountainGod2/cb-events/commit/10d5651392cc71773a433451cbc3c647774113ec))

- **pre-commit**: Add redact argument to gitleaks hook
  ([#61](https://github.com/MountainGod2/cb-events/pull/61),
  [`10d5651`](https://github.com/MountainGod2/cb-events/commit/10d5651392cc71773a433451cbc3c647774113ec))

### Refactoring

- Update type annotations and immutabilty ([#59](https://github.com/MountainGod2/cb-events/pull/59),
  [`1c4f2f3`](https://github.com/MountainGod2/cb-events/commit/1c4f2f3aeafb9858734c9329de89e56faa2e663f))

- **client**: Change AUTH_ERRORS and RETRY_STATUS_CODES to frozenset
  ([#59](https://github.com/MountainGod2/cb-events/pull/59),
  [`1c4f2f3`](https://github.com/MountainGod2/cb-events/commit/1c4f2f3aeafb9858734c9329de89e56faa2e663f))

- **client**: Fully mask api token in logs
  ([#61](https://github.com/MountainGod2/cb-events/pull/61),
  [`10d5651`](https://github.com/MountainGod2/cb-events/commit/10d5651392cc71773a433451cbc3c647774113ec))

- **client**: Update docstrings for error handling and token masking
  ([#59](https://github.com/MountainGod2/cb-events/pull/59),
  [`1c4f2f3`](https://github.com/MountainGod2/cb-events/commit/1c4f2f3aeafb9858734c9329de89e56faa2e663f))

- **client, exceptions, tests**: Mask tokens fully in logs and repr
  ([#61](https://github.com/MountainGod2/cb-events/pull/61),
  [`10d5651`](https://github.com/MountainGod2/cb-events/commit/10d5651392cc71773a433451cbc3c647774113ec))

- **config**: Change model_config to use ConfigDict
  ([#59](https://github.com/MountainGod2/cb-events/pull/59),
  [`1c4f2f3`](https://github.com/MountainGod2/cb-events/commit/1c4f2f3aeafb9858734c9329de89e56faa2e663f))

- **models**: Simplify imports and type annotations
  ([#59](https://github.com/MountainGod2/cb-events/pull/59),
  [`1c4f2f3`](https://github.com/MountainGod2/cb-events/commit/1c4f2f3aeafb9858734c9329de89e56faa2e663f))

- **pytest**: Rename pytest section to ini_options
  ([#59](https://github.com/MountainGod2/cb-events/pull/59),
  [`1c4f2f3`](https://github.com/MountainGod2/cb-events/commit/1c4f2f3aeafb9858734c9329de89e56faa2e663f))

- **renovate**: Reorganize package rules ([#58](https://github.com/MountainGod2/cb-events/pull/58),
  [`e51d770`](https://github.com/MountainGod2/cb-events/commit/e51d770dc05a6253013eccce7970dff9fb17dfdf))

- **renovate**: Reorganize package rules and restore breaking update handling
  ([#58](https://github.com/MountainGod2/cb-events/pull/58),
  [`e51d770`](https://github.com/MountainGod2/cb-events/commit/e51d770dc05a6253013eccce7970dff9fb17dfdf))

- **router**: Change Handler to type alias
  ([#59](https://github.com/MountainGod2/cb-events/pull/59),
  [`1c4f2f3`](https://github.com/MountainGod2/cb-events/commit/1c4f2f3aeafb9858734c9329de89e56faa2e663f))

- **tests**: Add type hints to test parameters
  ([#57](https://github.com/MountainGod2/cb-events/pull/57),
  [`4754915`](https://github.com/MountainGod2/cb-events/commit/47549156098afaafe498c3042cb231424a951d85))

- **tests**: Consolidate and improve test structure
  ([#57](https://github.com/MountainGod2/cb-events/pull/57),
  [`4754915`](https://github.com/MountainGod2/cb-events/commit/47549156098afaafe498c3042cb231424a951d85))

- **tests**: Consolidate tests and helpers
  ([#57](https://github.com/MountainGod2/cb-events/pull/57),
  [`4754915`](https://github.com/MountainGod2/cb-events/commit/47549156098afaafe498c3042cb231424a951d85))


## v6.0.0 (2026-03-15)

### Chores

- **dependencies**: Replace tenacity with stamina for retry logic
  ([#56](https://github.com/MountainGod2/cb-events/pull/56),
  [`7f260c1`](https://github.com/MountainGod2/cb-events/commit/7f260c12fdf63e5ee20bee6836f2524a55fac3ed))

### Features

- **dependencies**: Replace tenacity with stamina for retry logic
  ([#56](https://github.com/MountainGod2/cb-events/pull/56),
  [`7f260c1`](https://github.com/MountainGod2/cb-events/commit/7f260c12fdf63e5ee20bee6836f2524a55fac3ed))

### Refactoring

- **client**: Add HTTP metadata to _TransientError
  ([#56](https://github.com/MountainGod2/cb-events/pull/56),
  [`7f260c1`](https://github.com/MountainGod2/cb-events/commit/7f260c12fdf63e5ee20bee6836f2524a55fac3ed))

- **client**: Handle None for status_code and response_text
  ([#56](https://github.com/MountainGod2/cb-events/pull/56),
  [`7f260c1`](https://github.com/MountainGod2/cb-events/commit/7f260c12fdf63e5ee20bee6836f2524a55fac3ed))


## v5.9.1 (2026-02-19)

### Bug Fixes

- **deps**: Update dependency tenacity to v9.1.4
  ([#52](https://github.com/MountainGod2/cb-events/pull/52),
  [`1296a3b`](https://github.com/MountainGod2/cb-events/commit/1296a3b37d62b68bbd543d3d768dfc48215a51b3))


## v5.9.0 (2026-01-14)

### Bug Fixes

- **models**: Change extra field behavior to ignore unknown fields
  ([`7216b19`](https://github.com/MountainGod2/cb-events/commit/7216b198dd586f292a0aaebed9c06771ad375576))

### Features

- **client**: Recreate retry logic with tenacity
  ([`34437e3`](https://github.com/MountainGod2/cb-events/commit/34437e318e514eec5993513568bd2757dba15be6))

### Refactoring

- **client**: Move _TransientError class outside EventClient
  ([`6734f53`](https://github.com/MountainGod2/cb-events/commit/6734f5323cc20f9bb49494aea091fb552bdd0b7b))

- **client**: Remove unused functions
  ([`52322d1`](https://github.com/MountainGod2/cb-events/commit/52322d12e05edfba82ae7567093e22875b0c8f74))

- **config**: Adjust message type assignment
  ([`07f6f8c`](https://github.com/MountainGod2/cb-events/commit/07f6f8cb2e62d1e55d591d5a3de8ff2aed329c9e))

- **exceptions**: Simplify attribute assignment in EventsError
  ([`94e8334`](https://github.com/MountainGod2/cb-events/commit/94e833473b5d01151dee775634ec38c17c3c553e))

- **models**: Remove unnecessary type casting in Event class
  ([`0438d18`](https://github.com/MountainGod2/cb-events/commit/0438d183b284fbc7dccbeda7c7819b8b6ae227f5))

- **router**: Simplify docstrings and variable assignments
  ([`5ff4c13`](https://github.com/MountainGod2/cb-events/commit/5ff4c13e6a4ee321cd1ba6466ea874e1aafc19db))

- **tests**: Remove unused _compose_message test
  ([`150ed63`](https://github.com/MountainGod2/cb-events/commit/150ed63b938cd8bbb0ca8d5f4c662f93a845a5d4))

- **version**: Move version logic to separate file
  ([`42a6f12`](https://github.com/MountainGod2/cb-events/commit/42a6f121e237e03aae92d166a4e8073a9d6b08fe))


## v5.8.2 (2026-01-07)

### Bug Fixes

- **python-runtime**: Update dependency aiohttp to v3.13.3
  ([#49](https://github.com/MountainGod2/cb-events/pull/49),
  [`17ce240`](https://github.com/MountainGod2/cb-events/commit/17ce240b1f92914e8bf1e8e05f0076ff433bf044))


## v5.8.1 (2025-12-26)

### Bug Fixes

- **docs**: Update html_theme_options type to include bool
  ([`9c9a3a8`](https://github.com/MountainGod2/cb-events/commit/9c9a3a894aa502ced20674336056b3342851edef))

### Refactoring

- **factory**: Change config_overrides type to object
  ([`9910083`](https://github.com/MountainGod2/cb-events/commit/99100838223692d92ac2d917191e0c0dc2c54a50))

- **models**: Cast return types for cached properties
  ([`a102e7c`](https://github.com/MountainGod2/cb-events/commit/a102e7c6b7e102ffb6156d89eda8e8d64c298dd8))

- **models**: Cast user extraction to User type
  ([`89efb87`](https://github.com/MountainGod2/cb-events/commit/89efb8775ef392475ea230330f4ac949ac0b86f2))

- **models**: Simplify user extraction logic
  ([`3991ffe`](https://github.com/MountainGod2/cb-events/commit/3991ffe3017998e61911f4eb896a9538acebe2ae))

- **router**: Update handler type
  ([`66e9c60`](https://github.com/MountainGod2/cb-events/commit/66e9c606d663ef5ce5a468c40d1dfa1124150e7f))

- **tests**: Update _FuncAttrWrapper to accept non-awaitable callable
  ([`6bfa8b9`](https://github.com/MountainGod2/cb-events/commit/6bfa8b99902caa65f6a477fee0c96d5ee735a1c8))


## v5.8.0 (2025-12-13)

### Features

- **client**: Add response snippet and host entry sanitization
  ([`a18825b`](https://github.com/MountainGod2/cb-events/commit/a18825b805db10d18a8b1ecf1264e8bb3b101408))

### Refactoring

- **client**: Improve formatting
  ([`94cadd7`](https://github.com/MountainGod2/cb-events/commit/94cadd72202435b0b07949db015eee88e133f7ad))

- **client**: Modify retry logic
  ([`c24fbbb`](https://github.com/MountainGod2/cb-events/commit/c24fbbb648e4528ae7c724971e73f0d0c35ad976))

- **example**: Simplify event handlers
  ([`93d1894`](https://github.com/MountainGod2/cb-events/commit/93d189465768393aee631ea0e737fc6c7c4679b0))


## v5.7.0 (2025-12-09)

### Features

- **client**: Enhance nextUrl validation and add jitter to retry delay
  ([`122e289`](https://github.com/MountainGod2/cb-events/commit/122e28913f4ca67c96b7da6678195ba035c57b44))


## v5.6.5 (2025-12-03)

### Bug Fixes

- **router**: Handle asyncio.CancelledError separately
  ([`8fb30bd`](https://github.com/MountainGod2/cb-events/commit/8fb30bd7a0ebd3f61b043d75107bd45252cae499))

### Refactoring

- **client**: Improve type casting in validation error logging
  ([`320f603`](https://github.com/MountainGod2/cb-events/commit/320f60352154b86413d8b110b54b02c61cd135a3))

- **client**: Simplify validation error logging
  ([`4b01b7e`](https://github.com/MountainGod2/cb-events/commit/4b01b7eb5c2e35423e6a1d090afa2db418772590))

- **examples**: Improve type hints and docstrings
  ([`fa734cd`](https://github.com/MountainGod2/cb-events/commit/fa734cdaf9849ca743040d3af2b02f30465a3dc8))

- **router**: Remove handling of asyncio.CancelledError in dispatch
  ([`debfffb`](https://github.com/MountainGod2/cb-events/commit/debfffb7f0d307c44c68ea4c1c554c221301854e))

- **tests**: Simplify event handling in tests
  ([`7bd97e7`](https://github.com/MountainGod2/cb-events/commit/7bd97e70c6789bb7576d2d170ff4a42231308708))


## v5.6.4 (2025-11-30)

### Bug Fixes

- **runtime**: Update dependency pydantic to v2.12.5
  ([#35](https://github.com/MountainGod2/cb-events/pull/35),
  [`fec4603`](https://github.com/MountainGod2/cb-events/commit/fec4603cc69d8d9f819c43a7f8fa12c5d38d40f8))


## v5.6.3 (2025-11-29)

### Bug Fixes

- **client**: Prevent redirects in session requests
  ([`80f7305`](https://github.com/MountainGod2/cb-events/commit/80f730521efa1e5d06187d938fd2738e395843dc))

### Refactoring

- **client**: Clean up comments and organization
  ([`398dadf`](https://github.com/MountainGod2/cb-events/commit/398dadf6e9fff16e25c1b006f2a431d8c6b117cb))

- **client**: Remove unused sentinel for API keys
  ([`b9126f6`](https://github.com/MountainGod2/cb-events/commit/b9126f6fc3ba84f9fe4c7a18a508b7fe8fa57456))

- **example**: Remove redundant return type annotations
  ([`87202bf`](https://github.com/MountainGod2/cb-events/commit/87202bf73ade7930e1e33ae78aa27479e8658a0f))

- **example**: Use environment variable for testbed config
  ([`832894b`](https://github.com/MountainGod2/cb-events/commit/832894b13eb2d7fe8f82630711d8c117f178e840))


## v5.6.2 (2025-11-22)

### Bug Fixes

- **deps**: Add examples group for python-dotenv and rich
  ([`07a4bfe`](https://github.com/MountainGod2/cb-events/commit/07a4bfebbd389956bc8cdcbe41deddd3014ff15c))

- **Dockerfile**: Update Python base image to 3.14
  ([`f36f456`](https://github.com/MountainGod2/cb-events/commit/f36f45655066d00a34e627e3825ea1a1c4b4308e))

- **Dockerfile**: Update uv dependency to version 0.9.11
  ([`14cfa07`](https://github.com/MountainGod2/cb-events/commit/14cfa079d8666e6cc6528679ba556f7652e6de44))

### Refactoring

- **client**: Improve type annotations
  ([`18ab44f`](https://github.com/MountainGod2/cb-events/commit/18ab44f415739dc4209dcb10870daca389f7b002))

- **client**: Improve URL handling in EventClient
  ([`ca84207`](https://github.com/MountainGod2/cb-events/commit/ca84207863b10912a0f05bb7bb29196c444fa7ed))

- **example**: Replace print statements with logging
  ([`e1a2055`](https://github.com/MountainGod2/cb-events/commit/e1a205558290986e42dbff916748bbd2366498c2))


## v5.6.1 (2025-11-16)

### Bug Fixes

- **tests**: Update coverage options to include src and omit tests
  ([`d370837`](https://github.com/MountainGod2/cb-events/commit/d370837f990988d29118b52fc574ab5af80419fd))

### Refactoring

- **init**: Add pragma comment for PackageNotFoundError
  ([`a7a7672`](https://github.com/MountainGod2/cb-events/commit/a7a7672892a86cf1c2d8505756f0d5c78f0dc2c7))

- **tests**: Remove unused pytestmark import
  ([`e25409c`](https://github.com/MountainGod2/cb-events/commit/e25409c0337ba80aeb11fe3326deeef7ac4ac6b6))


## v5.6.0 (2025-11-15)

### Features

- **config**: Add next_url_allowed_hosts to ClientConfig
  ([`acf3f4c`](https://github.com/MountainGod2/cb-events/commit/acf3f4ce213c971b5f89a14957b9e4ee56b14ad9))

### Refactoring

- **config**: Fix indentation in docstring for retry_attempts
  ([`2ec081b`](https://github.com/MountainGod2/cb-events/commit/2ec081ba9ee411d4211266d401d2887bb45a4f24))


## v5.5.1 (2025-11-15)

### Bug Fixes

- **test**: Disable coverage for end-to-end tests
  ([`d760ef6`](https://github.com/MountainGod2/cb-events/commit/d760ef6c835d54e085f7372d5ebdbdf678e1477c))


## v5.5.0 (2025-11-13)

### Features

- **models**: Improve media purchase event handling
  ([`dc5b44b`](https://github.com/MountainGod2/cb-events/commit/dc5b44ba6655ebd90a7444fe09766b458a3a027e))

### Refactoring

- **client**: Improve type handling and logging messages
  ([`6088c22`](https://github.com/MountainGod2/cb-events/commit/6088c228c67b5021aa0bae89b92c3331ce0766b4))

- **config**: Specify model_config type annotation
  ([`ee59f20`](https://github.com/MountainGod2/cb-events/commit/ee59f203e182d90c2301a81878018c9d97cb2880))

- **exceptions**: Enhance type annotations and override usage
  ([`ef4d606`](https://github.com/MountainGod2/cb-events/commit/ef4d606c106b740394128b700ea0f7de8544e745))

- **router**: Simplify async callable checks
  ([`af35cdc`](https://github.com/MountainGod2/cb-events/commit/af35cdc68c58747f7a55317b02d7d09fd02370c3))


## v5.4.0 (2025-11-12)

### Features

- **tests**: Add live testbed polling test with env credentials
  ([`e66a7ba`](https://github.com/MountainGod2/cb-events/commit/e66a7ba713bb448916f66df6bb65ae3b2aab56f4))


## v5.3.0 (2025-11-10)

### Features

- **ci**: Add grouping for GitHub Actions workflows
  ([`37646d6`](https://github.com/MountainGod2/cb-events/commit/37646d621a439484ef9e5c898ded7ff7def6c72b))

### Refactoring

- **pre-commit**: Remove doc8 rst check hook
  ([`4f2780b`](https://github.com/MountainGod2/cb-events/commit/4f2780b71ffcdfb3b2634a8e63859c8d4467512f))

- **renovate**: Adjust package rules with labels and scopes
  ([`51f690d`](https://github.com/MountainGod2/cb-events/commit/51f690db4593bf61e342d4299ffb682b3405c7ec))

- **renovate**: Remove python-semantic-release from dev group
  ([`5ad39ef`](https://github.com/MountainGod2/cb-events/commit/5ad39ef0579b691b331dbf3d750d136f7394ac7e))


## v5.2.2 (2025-11-10)

### Bug Fixes

- **renovate**: Update package name matching patterns
  ([`a4735c5`](https://github.com/MountainGod2/cb-events/commit/a4735c5dc9fb6537646df25eb7c91486d04c3df6))

### Refactoring

- **client**: Improve logging for event processing and authentication
  ([`835e121`](https://github.com/MountainGod2/cb-events/commit/835e121cd351ba54318ca0a9292f335cd6fa2fa3))

- **config**: Improve error message for retry settings
  ([`c64dbfc`](https://github.com/MountainGod2/cb-events/commit/c64dbfccd0079d3117de2521f142394a48166a73))

- **router**: Enhance logging for event dispatching
  ([`dcb13e2`](https://github.com/MountainGod2/cb-events/commit/dcb13e25d329ad492faed0b66d4e49073839b6ca))


## v5.2.1 (2025-11-09)

### Bug Fixes

- **deps**: Update dependency pydantic to v2.12.4
  ([`64c7750`](https://github.com/MountainGod2/cb-events/commit/64c7750173cf5612630aca788cf79980e44cca5d))


## v5.2.0 (2025-11-08)

### Bug Fixes

- **config**: Enforce minimum value for retry_attempts
  ([`4711e7f`](https://github.com/MountainGod2/cb-events/commit/4711e7f2e88191e41cbe1bdfdceed74c4a6302a0))

### Features

- **client**: Add validation for nextUrl in API responses
  ([`1b7e9cb`](https://github.com/MountainGod2/cb-events/commit/1b7e9cb61b4e136be0533b18d67e119418388098))

### Refactoring

- **docs**: Improve Sphinx configuration and imports
  ([`890a318`](https://github.com/MountainGod2/cb-events/commit/890a3185b045cf118830703fa11827f5ae518e8a))


## v5.1.1 (2025-11-06)

### Bug Fixes

- **client**: Handle event ID extraction for non-mapping items
  ([`96f3945`](https://github.com/MountainGod2/cb-events/commit/96f39455b8fe0459cf40f7027d33f9b88ac28301))

### Refactoring

- **client**: Improve JSON response handling and validation
  ([`b8cc680`](https://github.com/MountainGod2/cb-events/commit/b8cc68099ef61be7ba414f9b8a9b35849353280e))

- **client**: Remove redundant error handling comments
  ([`6e404a1`](https://github.com/MountainGod2/cb-events/commit/6e404a1ffc36f264607fe1ae8edf55c09886f665))

- **router**: Improve async handler error message
  ([`d11e77f`](https://github.com/MountainGod2/cb-events/commit/d11e77f21bd2f921a9696fbbabf147d33ad94d32))

- **router**: Improve handler name retrieval logic
  ([`d7b13e3`](https://github.com/MountainGod2/cb-events/commit/d7b13e3c864232c6d8109d8c9f7206c445a0b240))


## v5.1.0 (2025-11-05)

### Bug Fixes

- **auth**: Improve error messages for username and token validation
  ([`a6ea8e7`](https://github.com/MountainGod2/cb-events/commit/a6ea8e703ffd36f9beb3ce6c37d756daaa1bf11b))

### Features

- **router**: Enhance async handler registration and error handling
  ([`35dbe52`](https://github.com/MountainGod2/cb-events/commit/35dbe5217e521f4422fde4aa7940c2114564cfc4))


## v5.0.0 (2025-11-05)

### Refactoring

- **client**: Enhance type annotations
  ([`8c8d189`](https://github.com/MountainGod2/cb-events/commit/8c8d1890677c3fafd68d639272a25823ea0c5248))

- **config**: Add type annotation for message variable in validation method
  ([`1d1da0f`](https://github.com/MountainGod2/cb-events/commit/1d1da0f5abd1e46d52c30d436a4300e4d2e76440))

- **config, router**: Rename EventClientConfig to ClientConfig and EventRouter to Router
  ([`5de0bc2`](https://github.com/MountainGod2/cb-events/commit/5de0bc26b18560c3914e77e0cd1abe6199bbaf3c))

- **dependencies**: Add pyrefly package to dev dependencies and update uv.lock
  ([`a208108`](https://github.com/MountainGod2/cb-events/commit/a20810851f23f98e29dd7eaf14e3a6c907a32110))

- **docs**: Update README and example to use ClientConfig and Router
  ([`f9b59d3`](https://github.com/MountainGod2/cb-events/commit/f9b59d324d9b24795a939499332da4401dd916a2))

- **exceptions**: Clarify response_text documentation
  ([`ced8d33`](https://github.com/MountainGod2/cb-events/commit/ced8d33ef76275c015efa58640acb153df7d5b8e))

- **models**: Enhance type annotations for logger and value variables
  ([`525a19f`](https://github.com/MountainGod2/cb-events/commit/525a19fd99182a6c92c76de4b9e264d1f673e60c))

- **models**: Update field aliases
  ([`36ae5d9`](https://github.com/MountainGod2/cb-events/commit/36ae5d94ca0fd50f743190b5b085ca1d06d0f7a7))

- **router**: Enhance type annotations for logger and handlers
  ([`f058bc6`](https://github.com/MountainGod2/cb-events/commit/f058bc64c927bf647211ab520e1648aae7525de3))

- **tests**: Remove unused pyright type checking comments
  ([`7553b72`](https://github.com/MountainGod2/cb-events/commit/7553b722251689b541c683799f0d57d32d7085ab))

- **tests**: Replace EventClientConfig with ClientConfig
  ([`41aee7c`](https://github.com/MountainGod2/cb-events/commit/41aee7c7cd4105b626a66148b865e6de7daaeafc))

- **vscode**: Update extension recommendations
  ([`6b02686`](https://github.com/MountainGod2/cb-events/commit/6b02686f65653caaae9d2f81c47f30e12ca133b2))


## v4.10.1 (2025-11-04)

### Bug Fixes

- **router**: Improve handler registration and error logging in event dispatching
  ([`e42fa37`](https://github.com/MountainGod2/cb-events/commit/e42fa3778e4729695370197f5553c54f5ca13448))

- **router**: Log exceptions with handler names during event dispatching
  ([`9e37659`](https://github.com/MountainGod2/cb-events/commit/9e37659a0754abee05bc749dec774d8335526852))

### Refactoring

- **client**: Improve token masking
  ([`0cc0d9b`](https://github.com/MountainGod2/cb-events/commit/0cc0d9b107eb0c21e35d106a836ad320181a40e5))

- **client**: Remove unused client default configurations
  ([`91aaeb5`](https://github.com/MountainGod2/cb-events/commit/91aaeb565ec512cd0ce8a9c696ca497ffbb00f55))

- **client**: Reorganize constants and improve function documentation
  ([`488a21e`](https://github.com/MountainGod2/cb-events/commit/488a21ecefa58d1e833f08e5d4ae8030e4685636))

- **config**: Improve attribute descriptions
  ([`26a2188`](https://github.com/MountainGod2/cb-events/commit/26a2188793e8fcf38c58c02a4e60c9682c79b78c))

- **config**: Move default configuration values into the config file
  ([`33d4123`](https://github.com/MountainGod2/cb-events/commit/33d4123af2decf533242c8d55080dd93e29a3d56))

- **constants**: Remove obsolete constants file
  ([`d136d42`](https://github.com/MountainGod2/cb-events/commit/d136d42aeacbf65bcd81c8b17dabf53abdb057de))

- **constants**: Remove unused variables
  ([`b3434a6`](https://github.com/MountainGod2/cb-events/commit/b3434a6b89192574b2d194015465ac1c9549ce15))

- **example**: Format print statements for better readability
  ([`e7ace63`](https://github.com/MountainGod2/cb-events/commit/e7ace637c32449d358688e894de2426bd439d25f))

- **exceptions**: Remove unused repr method
  ([`25aab94`](https://github.com/MountainGod2/cb-events/commit/25aab940249b3fd41bef5e26afb98e4273a858e4))

- **init**: Add EventCallback to __all__
  ([`978e262`](https://github.com/MountainGod2/cb-events/commit/978e262325d53234cd2450f4e663ba12e7859788))

- **models**: Improve docstrings and update field types
  ([`068cca8`](https://github.com/MountainGod2/cb-events/commit/068cca84854c5064b4969a188bce6139c7ecb084))

- **models**: Improve key handling in Event class
  ([`78ee61a`](https://github.com/MountainGod2/cb-events/commit/78ee61a4d130cf7e4ba760af55b1c02e48cdad65))

- **router**: Simplify type annotations and improve docstrings
  ([`e8c0d19`](https://github.com/MountainGod2/cb-events/commit/e8c0d1946c44c3bca8288f8a5f6f4babf69a05bd))

- **style**: Reduce line length to 80
  ([`e1de966`](https://github.com/MountainGod2/cb-events/commit/e1de9668f25ecd72de35a3d006f7a79c351a3309))

- **utils**: Remove unused utility functions
  ([`73719c4`](https://github.com/MountainGod2/cb-events/commit/73719c45fb580899ad4718d8e2e7812ee692fa1c))


## v4.10.0 (2025-11-03)

### Bug Fixes

- **README**: Update event streaming method in examples and improve retry attempts description
  ([`028d287`](https://github.com/MountainGod2/cb-events/commit/028d2874f51d03be75f35ffeba7cec1802be72a2))

### Features

- Add utility functions for masking secrets and formatting validation errors
  ([`4e7d88e`](https://github.com/MountainGod2/cb-events/commit/4e7d88e4582107f51520df93fdf9aab0795bd387))

- Implement event batch processing utilities with validation
  ([`de985e1`](https://github.com/MountainGod2/cb-events/commit/de985e1fb163dcf18a6db1467c2e1abe9a415f03))

### Refactoring

- Enhance event handling with improved validation and retry logic
  ([`56d20fe`](https://github.com/MountainGod2/cb-events/commit/56d20fe55089026bd2589dd1b162905e91a0db1b))

- Improve documentation and streamline comments across modules
  ([`88fd231`](https://github.com/MountainGod2/cb-events/commit/88fd231b7f061320627eee1544965bc99ca5ca73))

- Remove unused event parsing module
  ([`50ab429`](https://github.com/MountainGod2/cb-events/commit/50ab429173824f55cc4f87f40f4595763cc18d40))

- Simplify event model parsing with shared extraction method
  ([`bb0cac7`](https://github.com/MountainGod2/cb-events/commit/bb0cac7077f5dae84b3a25698485d190d66a6625))

- Streamline event parsing and response handling in EventClient
  ([`e768170`](https://github.com/MountainGod2/cb-events/commit/e768170ed8202093f1be5797c8be9c6be5b3dd5c))

- **router**: Enhance event handler registration with normalization for sync and async support
  ([`eb4245b`](https://github.com/MountainGod2/cb-events/commit/eb4245b28709b09291342f3fde3bb1c4d19566a6))


## v4.9.2 (2025-11-02)

### Bug Fixes

- **docs**: Add new template for Python type documentation
  ([`1d34bd5`](https://github.com/MountainGod2/cb-events/commit/1d34bd5cf8f0c9dfb86d1f4f162e4135a26b9d02))

### Refactoring

- **docs**: Remove redundant error handling section and update dependencies note
  ([`9ea989f`](https://github.com/MountainGod2/cb-events/commit/9ea989f0f8c3fd01998a750c2e0191db1905c6bf))


## v4.9.1 (2025-11-02)

### Bug Fixes

- **deps**: Update dependency aiohttp to v3.13.2
  ([`b88e635`](https://github.com/MountainGod2/cb-events/commit/b88e6352c52d2d344d93dbfe9e9dcdcdd6eae2d2))


## v4.9.0 (2025-11-02)

### Bug Fixes

- **init**: Handle PackageNotFoundError when retrieving package version
  ([`b247e14`](https://github.com/MountainGod2/cb-events/commit/b247e148ca83e1d44bb11a69f5c4af6e5864c8ed))

### Features

- **tests**: Reorganize suites with typed fixtures
  ([`1ab68fd`](https://github.com/MountainGod2/cb-events/commit/1ab68fd7efc619ef2182655aeffc1b8bd597f35d))

### Refactoring

- **client**: Enhance error logging for validation failures
  ([`7bb07ae`](https://github.com/MountainGod2/cb-events/commit/7bb07ae62e9fec68559e28f3150ad54adaa334cc))

- **example**: Add exit message to main script
  ([`a11cd66`](https://github.com/MountainGod2/cb-events/commit/a11cd6646e01704e092cc50c38f9fa126c560af6))

- **models**: Improve error logging for validation failures and optimize caching
  ([`092dce2`](https://github.com/MountainGod2/cb-events/commit/092dce2105c98ee2f0fe2bc98ebd8ab52ebeaea8))


## v4.8.0 (2025-11-01)

### Bug Fixes

- **client**: Improve error handling for API requests
  ([`9799bc6`](https://github.com/MountainGod2/cb-events/commit/9799bc60cfea295ea46a94be27132711ff4306e7))

### Features

- **models**: Implement caching for event data retrieval
  ([`1e9ccaa`](https://github.com/MountainGod2/cb-events/commit/1e9ccaae491696f53326c748bda0a35244ff322e))

### Refactoring

- **tests**: Enhance type hints and improve test function signatures
  ([`395c29b`](https://github.com/MountainGod2/cb-events/commit/395c29b3a510920879e65e89aacefe61b77f692d))


## v4.7.1 (2025-10-31)

### Bug Fixes

- **docs**: Clarify behavior of event properties and update version import
  ([`35df062`](https://github.com/MountainGod2/cb-events/commit/35df062181ed21c5d764107a6b2fd17b07f2da5a))

- **models**: Enhance error handling for data validation
  ([`d24bd84`](https://github.com/MountainGod2/cb-events/commit/d24bd84f2a2d89dacfd3f45648fa32db14415214))

### Refactoring

- **client**: Remove unused ResponseStatus enum and simplify response handling
  ([`05cfec5`](https://github.com/MountainGod2/cb-events/commit/05cfec573a0bf13b74cba4a4301c504a7c91f062))

- **constants**: Simplify Cloudflare error handling
  ([`f650ce8`](https://github.com/MountainGod2/cb-events/commit/f650ce84b52f8bb9afec5d8dae241610abf5836c))


## v4.7.0 (2025-10-31)

### Features

- **validation**: Introduce strict validation for event data and update error handling
  ([`ef2fe99`](https://github.com/MountainGod2/cb-events/commit/ef2fe995d10b406aa6b69ab26c73cb1a7f75b700))

### Refactoring

- Improve field handling and logging
  ([`455099e`](https://github.com/MountainGod2/cb-events/commit/455099e35bb19f0a284d6965e2f94f6833135cab))

- **pyproject**: Remove unused pyright configuration
  ([`de12bb2`](https://github.com/MountainGod2/cb-events/commit/de12bb2699793af2f5578b0f39b527e00d72b753))


## v4.6.1 (2025-10-30)

### Bug Fixes

- **constants**: Correct initialization of CLOUDFLARE_ERROR_CODES set
  ([`3120e80`](https://github.com/MountainGod2/cb-events/commit/3120e804ed876b68144ed3af6b9fc7ccb5bb3d54))

- **event**: Handle ValidationError when retrieving user, tip, message, and room subject data
  ([`27a1c9d`](https://github.com/MountainGod2/cb-events/commit/27a1c9dfb20c715f1bd424cc56bf921a932003c6))

- **router**: Correct type hint for _handlers in EventRouter initialization
  ([`0e6dcc5`](https://github.com/MountainGod2/cb-events/commit/0e6dcc50dc3d234967d3ed12cd725bb6501858f3))

### Refactoring

- **exceptions**: Improve response_text representation in EventsError
  ([`5309193`](https://github.com/MountainGod2/cb-events/commit/53091931b11e82215a2d921e157b2d2840b254f9))


## v4.6.0 (2025-10-30)

### Bug Fixes

- **docs**: Exclude autoapi templates from doc8 rst check
  ([`f1b423e`](https://github.com/MountainGod2/cb-events/commit/f1b423e4494a2dcae1b91b32d76eaacb7f8f4ea9))

### Features

- **docs**: Add autoapi template for class documentation and update Sphinx configuration
  ([`21422fb`](https://github.com/MountainGod2/cb-events/commit/21422fb5a4df0a0362295c0a9701e55f14ae13e5))


## v4.5.2 (2025-10-28)

### Bug Fixes

- **client**: Ensure polling lock is initialized and handle uninitialized state
  ([`7216340`](https://github.com/MountainGod2/cb-events/commit/72163403ea123da786d8d89d029c8f0484489c95))

- **coverage**: Remove omitted files from coverage report
  ([`646e481`](https://github.com/MountainGod2/cb-events/commit/646e48161e50b5bdbac173eb571f213527398ebe))

### Refactoring

- **docs**: Update module docstrings
  ([`d8189d1`](https://github.com/MountainGod2/cb-events/commit/d8189d1f36e56244c19891dc5f0906a4a3e93ae3))


## v4.5.1 (2025-10-28)

### Bug Fixes

- **pyproject**: Update documentation URL to point to Read the Docs
  ([`8d2a5bc`](https://github.com/MountainGod2/cb-events/commit/8d2a5bc2bb436a116eca964d18b9c1cb75b6cdb3))


## v4.5.0 (2025-10-28)

### Features

- **pyproject**: Add fancy-pypi-readme metadata hooks for README processing
  ([`50da09d`](https://github.com/MountainGod2/cb-events/commit/50da09df0c10b57a5c153e5b959cddd4bd055702))


## v4.4.3 (2025-10-28)

### Bug Fixes

- **Dockerfile**: Update uv package version to 0.9.5
  ([`b9bb24d`](https://github.com/MountainGod2/cb-events/commit/b9bb24d27f98324531c7f769ecb6c59896c1d2c4))

### Refactoring

- **pyproject**: Remove unused dependencies and clean up metadata hooks
  ([`28bb948`](https://github.com/MountainGod2/cb-events/commit/28bb9481750dcf5ca50361a9b91f790ac2946b7d))

- **router**: Remove RouterError and update error handling in tests and documentation
  ([`cfa3510`](https://github.com/MountainGod2/cb-events/commit/cfa3510ca80d58bb142c36d3266c540a79c9d390))


## v4.4.2 (2025-10-27)

### Bug Fixes

- **client**: Add thread safety with asyncio lock for polling method
  ([`212b8d1`](https://github.com/MountainGod2/cb-events/commit/212b8d1c187ec7a4a4d992ac6c7015ff97579a7e))

- **config**: Update validation method for retry delays in EventClientConfig
  ([`e9bbe8d`](https://github.com/MountainGod2/cb-events/commit/e9bbe8d6d3af3b04a01dbbec5ca4ac5a278f1c3d))

### Refactoring

- **tests**: Enhance test descriptions and structure
  ([`fb88608`](https://github.com/MountainGod2/cb-events/commit/fb88608baa2297564fd59b682f0a2410094fd4e8))


## v4.4.1 (2025-10-26)

### Bug Fixes

- **docs**: Update links and titles for consistency
  ([`623fb25`](https://github.com/MountainGod2/cb-events/commit/623fb25d7fd832105e66d7ead110523c5de961fe))


## v4.4.0 (2025-10-26)

### Bug Fixes

- **docs**: Update description in README and pyproject.toml for consistency
  ([`03fc31d`](https://github.com/MountainGod2/cb-events/commit/03fc31d4dc23bbbc5d8b16bf99889e3851be6e6b))

### Features

- **docs**: Add html_extra_path to include LICENSE and pyproject.toml in build output
  ([`8da1ac6`](https://github.com/MountainGod2/cb-events/commit/8da1ac60bf378415284e56c8747f1e4c8d930cba))


## v4.3.0 (2025-10-26)

### Bug Fixes

- **client**: Raise EventsError on session initialization failure
  ([`449e1e8`](https://github.com/MountainGod2/cb-events/commit/449e1e89d7ebd59ced164c9d76adc26001384162))

### Features

- **exceptions**: Add detailed __repr__ methods for EventsError and RouterError
  ([`3852ccd`](https://github.com/MountainGod2/cb-events/commit/3852ccd3dfd7f8f80e75d3764f05d1053fcc35cf))


## v4.2.1 (2025-10-26)

### Bug Fixes

- **router**: Log exceptions in event handlers to improve error tracking
  ([`8c1aa7a`](https://github.com/MountainGod2/cb-events/commit/8c1aa7a8a5616b3daacf82d2729fb74220b610ba))


## v4.2.0 (2025-10-26)

### Features

- **client**: Remove global rate limiter and use instance-based limiter
  ([`b20b42c`](https://github.com/MountainGod2/cb-events/commit/b20b42cbeab6cf12254b074c7218a773491f373f))

### Refactoring

- **router**: Replace EventHandler type alias with Protocol for better type safety
  ([`73faf5c`](https://github.com/MountainGod2/cb-events/commit/73faf5cd9a62e0caf14ddc45671bad68b2264a67))


## v4.1.1 (2025-10-22)

### Bug Fixes

- **deps**: Update runtime
  ([`38d51aa`](https://github.com/MountainGod2/cb-events/commit/38d51aadeffd064756a4be9a35201850b95eef0d))


## v4.1.0 (2025-10-21)

### Bug Fixes

- **client**: Mask authentication token in logs and adjust session timeout
  ([`108b033`](https://github.com/MountainGod2/cb-events/commit/108b033b8b0ae04d0131fbafe9aff71616db1656))

- **exceptions**: Remove redundant message attribute documentation from exception classes
  ([`3a99235`](https://github.com/MountainGod2/cb-events/commit/3a992359c3ab7304efd9b8736989b08ae03c8f85))

### Features

- **constants**: Add SESSION_TIMEOUT_BUFFER
  ([`e124271`](https://github.com/MountainGod2/cb-events/commit/e1242716aae4f5cdf9715da609c850af0ce5eff9))


## v4.0.4 (2025-10-21)

### Bug Fixes

- Enhance error messages for empty and whitespace credentials in EventClient
  ([`2a3544b`](https://github.com/MountainGod2/cb-events/commit/2a3544bcab1ab18c80b29a0439ae3e33dd6c1368))

- Update __all__ declaration to use type hinting
  ([`3814db5`](https://github.com/MountainGod2/cb-events/commit/3814db5a78013f99bc63ab19c99a155a51822455))

### Refactoring

- Adjust rate limiter and improve authentication checks in EventClient
  ([`60ccbf8`](https://github.com/MountainGod2/cb-events/commit/60ccbf89315ff474a9bcf91e5c7ceaa162618806))

- Refactor error message handling in EventsError and RouterError classes
  ([`78b757e`](https://github.com/MountainGod2/cb-events/commit/78b757ece1270d518f42db62c1e621c6e1ee2840))

- **models**: Replace cached_property with property for event model attributes
  ([`ed0abe0`](https://github.com/MountainGod2/cb-events/commit/ed0abe029e6a3078951b85c07fcba9dc41c977a7))


## v4.0.3 (2025-10-20)

### Bug Fixes

- Change ValueError to AuthError for empty username and token in EventClient
  ([`d159944`](https://github.com/MountainGod2/cb-events/commit/d159944e17e0fefd88ace55c5361b7615ab96b80))

- **docs**: Improve error handling for authentication in README and index
  ([`527846c`](https://github.com/MountainGod2/cb-events/commit/527846c338af7c7a9d1f6e868526c5a2627dfe29))

### Refactoring

- **example**: Remove unused AuthError handling in main
  ([`2c70673`](https://github.com/MountainGod2/cb-events/commit/2c70673ba7db0e20160744ad1ac51afd2845d588))

- **example**: Reorganize example file layout
  ([`5e379ee`](https://github.com/MountainGod2/cb-events/commit/5e379eec2ed98be0b79a8ccdd554f6d5147c060e))


## v4.0.2 (2025-10-20)

### Bug Fixes

- **docs**: Update linked files in README and index
  ([`41e111c`](https://github.com/MountainGod2/cb-events/commit/41e111c53c5628818de6f853e51fc941c88486e2))

### Refactoring

- **client**: Simplify username and token validation and improve nextUrl extraction
  ([`55d8c77`](https://github.com/MountainGod2/cb-events/commit/55d8c777f064c88f3e9c5007e266a496b1d7c397))

- **config**: Replace model_validator with field_validator for retry_max_delay validation
  ([`9f1a488`](https://github.com/MountainGod2/cb-events/commit/9f1a488d945d0afad964ded12e5328b658929bdb))

- **constants**: Remove outdated constant
  ([`6c50842`](https://github.com/MountainGod2/cb-events/commit/6c50842d5b0643e68160dbb87bf98d3d5dad415a))

- **models**: Improve private message check
  ([`d89ca9f`](https://github.com/MountainGod2/cb-events/commit/d89ca9f5ffa609948327a48250874524e0163cc1))

- **router**: Improve error handling in event handler dispatch
  ([`c7b5372`](https://github.com/MountainGod2/cb-events/commit/c7b53725b63834bb57f446c772967bc7dfcdc273))

- **tests**: Simplify test fixtures and remove unused parameters
  ([`c2fe968`](https://github.com/MountainGod2/cb-events/commit/c2fe9681d32687e1fefec5187d07724060c5a648))


## v4.0.1 (2025-10-18)

### Bug Fixes

- **deps**: Update dependency pydantic to v2.12.2
  ([`a9c1ad3`](https://github.com/MountainGod2/cb-events/commit/a9c1ad32071690b58ea5bc5daa7d3712e9854229))


## v4.0.0 (2025-10-18)

### Refactoring

- **python-version**: Update minimum python version to 3.12
  ([`45a344e`](https://github.com/MountainGod2/cb-events/commit/45a344e8108f57bec9d109ef9d9e98db0a8b7185))


## v3.1.2 (2025-10-17)

### Bug Fixes

- **client**: Improve error handling in _parse_response_data method to raise JSONDecodeError on
  invalid JSON
  ([`1679a78`](https://github.com/MountainGod2/cb-events/commit/1679a780d42a5df179c1286748acec9eaf28005c))

- **router**: Enhance dispatch method error handling with context for RouterError
  ([`e74e5c5`](https://github.com/MountainGod2/cb-events/commit/e74e5c5f01e492d46aa2d711d3a290572887ad6b))

### Refactoring

- **exceptions**: Remove __repr__ methods from EventsError and RouterError classes
  ([`1e83de3`](https://github.com/MountainGod2/cb-events/commit/1e83de32198c76d352bc3ddba2dac9671e2c16c0))

- **models**: Replace @property with @cached_property for improved performance in Event class
  ([`af3b311`](https://github.com/MountainGod2/cb-events/commit/af3b311b8b0b9f4a98481364c779d466f6864f6e))

- **tests**: Remove repr tests for EventsError, AuthError, and RouterError classes
  ([`4ebeaf1`](https://github.com/MountainGod2/cb-events/commit/4ebeaf1bafc0b5fb89e6a6cc210d833a1f57a58a))


## v3.1.1 (2025-10-17)

### Bug Fixes

- **models**: Ensure user, tip, and message data checks are explicit for None
  ([`81830c9`](https://github.com/MountainGod2/cb-events/commit/81830c9df7b2619df10f2c4764e08cd1a5fa7f32))

- **router**: Simplify exception handling in dispatch method documentation
  ([`47a302f`](https://github.com/MountainGod2/cb-events/commit/47a302f1ba46685dc147388bd9cac86a6c3ff5a0))

### Refactoring

- **client**: Consolidate rate limiter management
  ([`edd891d`](https://github.com/MountainGod2/cb-events/commit/edd891d2e755c4371568a8ff7025183809362923))

- **client**: Move rate limiter initialization to instance level and remove class-level reset
  fixture
  ([`352c04a`](https://github.com/MountainGod2/cb-events/commit/352c04a1ea0a4958c05b748569e1255db87b88a9))

- **Makefile**: Remove redundant docs-clean target
  ([`7786698`](https://github.com/MountainGod2/cb-events/commit/7786698740385b3a5765862dad47dc41e6ea7305))

- **tests**: Rename and simplify rate limiter fixture
  ([`7c3a38a`](https://github.com/MountainGod2/cb-events/commit/7c3a38a7a6dcb3ea4a0a6fbcaa58bbe3c9ce555c))


## v3.1.0 (2025-10-14)

### Features

- Add Codecov test results action to CI workflow
  ([`915386d`](https://github.com/MountainGod2/cb-events/commit/915386d159069129186a0418f04d357aceddfade))

### Refactoring

- **renovate**: Rename pre-commit group to pre-commit-hooks
  ([`3e2f51a`](https://github.com/MountainGod2/cb-events/commit/3e2f51abadc891c510f635abb7b9d45dadd1d680))


## v3.0.5 (2025-10-14)

### Bug Fixes

- **deps**: Update dependency pydantic to v2.12.0
  ([#24](https://github.com/MountainGod2/cb-events/pull/24),
  [`f8e50e7`](https://github.com/MountainGod2/cb-events/commit/f8e50e7a8e1fa6d585d7e49a9cbaf7659a24c8a2))


## v3.0.4 (2025-10-13)

### Bug Fixes

- **deps**: Update dependency aiohttp to v3.13.0
  ([`e035676`](https://github.com/MountainGod2/cb-events/commit/e035676aa192ff96869a62d26083fa2b1e980007))


## v3.0.3 (2025-10-12)

### Bug Fixes

- **deps**: Update dependency pydantic to v2.11.10
  ([`e436274`](https://github.com/MountainGod2/cb-events/commit/e4362744b9e36cb4c8345f66582fa484b1f48b05))


## v3.0.2 (2025-10-11)

### Bug Fixes

- **client**: Improve JSON parsing error handling in EventClient
  ([`2f4572e`](https://github.com/MountainGod2/cb-events/commit/2f4572e5d4d7267e3b3016fff45f55514e08a55a))

### Refactoring

- **client**: Simplify return logic in data handling
  ([`37726d2`](https://github.com/MountainGod2/cb-events/commit/37726d253339bbe4b4bb721dd9ff190b8bff428d))

- **config**: Use Self type hint in validate_retry_delays method
  ([`b9bf527`](https://github.com/MountainGod2/cb-events/commit/b9bf52773e9c8c9cce62d34180bc70f70258a20e))

- **exceptions**: Enhance error messages and add string representations
  ([`62278a2`](https://github.com/MountainGod2/cb-events/commit/62278a299b313de4e0cc7a9a630c4a3d1a6e6c3a))

- **router**: Enhance error handling in dispatch method and improve docstrings
  ([`5502196`](https://github.com/MountainGod2/cb-events/commit/5502196ebedbb555ead8f2d08a0ce7843398ddee))

- **router**: Remove handling of SystemExit and KeyboardInterrupt in dispatch method
  ([`fc8a98a`](https://github.com/MountainGod2/cb-events/commit/fc8a98ac2b07433aa15f1935d1d8fc1387dc9322))


## v3.0.1 (2025-10-10)

### Bug Fixes

- **docs**: Corrected event handling examples and descriptions
  ([`82c148f`](https://github.com/MountainGod2/cb-events/commit/82c148f10aa5b65e30c6e300c42c614d186cfb7c))


## v3.0.0 (2025-10-09)

### Bug Fixes

- **config**: Add validation for retry max delay against retry backoff
  ([`58bd2b2`](https://github.com/MountainGod2/cb-events/commit/58bd2b277569f9ed085b7707d94cebc15c4b3083))

### Refactoring

- **client**: Implement shared rate limiters for event handling and clear them before tests
  ([`f8ae923`](https://github.com/MountainGod2/cb-events/commit/f8ae923cd1a815b554635ba8a0ebd9b59787dae5))

- **client**: Remove redundant comments and streamline initialization in EventClient
  ([`724271a`](https://github.com/MountainGod2/cb-events/commit/724271a4cf7ae18ea8b20f5f23ac35039fd0caf2))

- **client**: Streamline error handling by consolidating response status checks and utilizing
  CLOUDFLARE_ERROR_CODES
  ([`966bbe4`](https://github.com/MountainGod2/cb-events/commit/966bbe48f01fde52ffc4f723ad237f888d58e971))

- **config**: Migrate EventClientConfig to use Pydantic for improved validation and configuration
  management
  ([`2e6ba15`](https://github.com/MountainGod2/cb-events/commit/2e6ba15bd20eb07d7c097d656ed92de89242c92c))

- **constants**: Remove unnecessary comments and streamline constant definitions
  ([`0931794`](https://github.com/MountainGod2/cb-events/commit/09317943079e0c729049c564dc7a26cee815f782))

- **example**: Simplify event dispatching by removing error handling logic
  ([`247287d`](https://github.com/MountainGod2/cb-events/commit/247287d0b2ce0e3abb31689a2bbc2852173637a4))

- **exceptions**: Simplify RouterError class by removing unnecessary attributes and improving
  documentation
  ([`1f97a21`](https://github.com/MountainGod2/cb-events/commit/1f97a21af60bd1db9fee7ff1181760304545d3b2))

- **models**: Remove redundant comments in EventType and Message classes
  ([`d189568`](https://github.com/MountainGod2/cb-events/commit/d1895684e784ff99902ffc87283e385b32f99506))

- **models**: Simplify boolean checks and optimize membership testing in Message and Event classes
  ([`809af39`](https://github.com/MountainGod2/cb-events/commit/809af39ebf2d6786546e3b86bc4f6805399edffd))

- **router**: Remove unnecessary comments
  ([`bad3bad`](https://github.com/MountainGod2/cb-events/commit/bad3bad7bae43beb8dd6e84c6f638271fcd55d6e))

- **router**: Simplify event dispatching and improve error handling with RouterError
  ([`c7b5318`](https://github.com/MountainGod2/cb-events/commit/c7b5318b627a016af852718af8ed46d00292a634))

- **router**: Unify handler registry and improve event dispatching logic
  ([`64386cf`](https://github.com/MountainGod2/cb-events/commit/64386cf65c4a06ed579f94203824f6f196acf4bc))

- **tests**: Enhance validation error handling in EventClientConfig tests
  ([`0665c8e`](https://github.com/MountainGod2/cb-events/commit/0665c8e0333fae463f5a6061f521236c9b2cc11c))

- **tests**: Update global handler assertion to use None key in EventRouter tests
  ([`20cfbce`](https://github.com/MountainGod2/cb-events/commit/20cfbce297216012924742196d1d09737f4b2017))

- **tests**: Update RouterError tests to use EventType constants and remove redundant cases
  ([`4a0f7fb`](https://github.com/MountainGod2/cb-events/commit/4a0f7fb2b4d2721b8c44eb80151e5996aa175799))


## v2.5.0 (2025-10-08)

### Features

- Add error handling modes and RouterError for event dispatching
  ([`e1999cc`](https://github.com/MountainGod2/cb-events/commit/e1999ccb0cf5f48de3e2b7e3ec88e2dbc0a0782b))

### Refactoring

- Enhance event router documentation and improve error handling logic
  ([`d98aabd`](https://github.com/MountainGod2/cb-events/commit/d98aabdca1ffe1336cd024d09b74d0de697c156c))


## v2.4.3 (2025-10-07)

### Bug Fixes

- **docs**: Suppress duplicate object warnings in AutoAPI configuration
  ([`65c5978`](https://github.com/MountainGod2/cb-events/commit/65c597844ba13b69cc3e077a8c53edc8bac89992))


## v2.4.2 (2025-10-07)

### Bug Fixes

- **docs**: Update build command to allow AutoAPI duplicate warnings
  ([`caf9c15`](https://github.com/MountainGod2/cb-events/commit/caf9c1511cf9bcb06f6959b233a3e42a7c76af8f))

### Refactoring

- **docs**: Enhance documentation across modules with detailed descriptions and examples
  ([`b63effe`](https://github.com/MountainGod2/cb-events/commit/b63effe8af7943a5e6fe93783c3ff055fac6d326))

- **docs**: Suppress duplicate object warnings and additional autoapi warnings
  ([`2688f95`](https://github.com/MountainGod2/cb-events/commit/2688f95c932c481bd7a3c58e6b83a1a939356dc1))


## v2.4.1 (2025-10-07)

### Bug Fixes

- **client**: Improve resource cleanup in close method with locking mechanism
  ([`ff71761`](https://github.com/MountainGod2/cb-events/commit/ff71761ba2443347c3d71cd44fffc0b3bbe1ec75))

- **pylint**: Increase max attributes limit from 10 to 12
  ([`f26817e`](https://github.com/MountainGod2/cb-events/commit/f26817e514f2c31686a396d1a7fbf14420d1cbf8))

### Refactoring

- **imports**: Consolidate exception imports
  ([`04fa725`](https://github.com/MountainGod2/cb-events/commit/04fa725e1ec65d3456acd7f76d6e2b4f8b5f4172))


## v2.4.0 (2025-10-05)

### Features

- **ci-cd**: Add attestations permissions and step for build provenance
  ([`e3a58c0`](https://github.com/MountainGod2/cb-events/commit/e3a58c03144b80cd50f2e67c8d37eab32f9e3967))

### Refactoring

- **ci-cd**: Improve job descriptions and steps
  ([`5698980`](https://github.com/MountainGod2/cb-events/commit/56989807b9083a123c132978f0d9f8816b00e5af))

- **ci-cd**: Modify workflow structure and update job definitions
  ([`bb1d04a`](https://github.com/MountainGod2/cb-events/commit/bb1d04a651f1360086a4f304db6ed25a8fe491cc))

- **ci-cd**: Streamline workflow jobs and improve naming conventions
  ([`4702b90`](https://github.com/MountainGod2/cb-events/commit/4702b9069f8aadcd3ff612e412c82b58437b65dc))


## v2.3.7 (2025-10-04)

### Bug Fixes

- **docs**: Update license links to use absolute URLs
  ([`d1da265`](https://github.com/MountainGod2/cb-events/commit/d1da26582b61b97eb1679d124317057220f6d1b4))

### Refactoring

- **config**: Simplify EventClientConfig docstring
  ([`ccc7fb5`](https://github.com/MountainGod2/cb-events/commit/ccc7fb59fe5c241ade6e827a6daf87bd2ca666d0))


## v2.3.6 (2025-10-03)

### Bug Fixes

- Update project URLs to reflect the correct repository name
  ([`d45d2e9`](https://github.com/MountainGod2/cb-events/commit/d45d2e98626f009b096c21fe3cbc613df8b0e503))


## v2.3.5 (2025-10-03)

### Bug Fixes

- **ci/cd**: Update SARIF upload action to a newer version
  ([`5fd1e0a`](https://github.com/MountainGod2/cb-events/commit/5fd1e0a9fc3197969cf17e33fedafd307014fbcc))


## v2.3.4 (2025-10-03)

### Bug Fixes

- **ci/cd**: Remove unnecessary setup and conditions
  ([`c5df60b`](https://github.com/MountainGod2/cb-events/commit/c5df60be6a99c160a674f7dfa61db1c904a5ece1))

- **ci/cd**: Update SARIF upload action and improve artifact handling
  ([`7706b3b`](https://github.com/MountainGod2/cb-events/commit/7706b3be0a464857ac9b70d4d6b8970109fd3369))


## v2.3.3 (2025-10-03)

### Bug Fixes

- **ci/cd**: Remove environment variables for package and wheel names in deployment steps
  ([`f95180d`](https://github.com/MountainGod2/cb-events/commit/f95180d4a586d82414dacf92b00ac60106f8ff23))


## v2.3.2 (2025-10-03)

### Bug Fixes

- **ci/cd**: Use environment variables for package and wheel names in install and deploy steps
  ([`ab2a7b4`](https://github.com/MountainGod2/cb-events/commit/ab2a7b4760ad5da274cecdb07130f9030e8aaf81))


## v2.3.1 (2025-10-03)

### Bug Fixes

- **ci/cd**: Add read permission for actions in security scan job
  ([`07b5cd0`](https://github.com/MountainGod2/cb-events/commit/07b5cd046ae8b34b6f03a40665a8a45c6ddd2f26))


## v2.3.0 (2025-10-03)

### Bug Fixes

- **ci/cd**: Consolidate permissions for security events and contents in CI/CD workflow
  ([`96e5f4e`](https://github.com/MountainGod2/cb-events/commit/96e5f4ecfa74b140dcbe624a486d8ddf9abb0483))

- **ci/cd**: Update permissions and enhance security scanning steps in CI/CD workflow
  ([`000ad71`](https://github.com/MountainGod2/cb-events/commit/000ad71f0172cd24a49a78f5117453a5dd36fc47))

- **ci/cd**: Update permissions to allow write access for contents and security events
  ([`3f88370`](https://github.com/MountainGod2/cb-events/commit/3f883702fc3329af2619b0fce976b799a80075f3))

### Features

- **security**: Add Trivy vulnerability scanning to CI/CD pipeline and Makefile
  ([`d36299d`](https://github.com/MountainGod2/cb-events/commit/d36299d4e5a90d00a572a94ba20e0c895b53710a))

- **security**: Integrate Bandit for security scanning and upload SARIF results
  ([`0d9a319`](https://github.com/MountainGod2/cb-events/commit/0d9a3199fe7bd537efefc7433814b0905b378663))

### Refactoring

- **lint**: Remove specific ruff ignores from example script and update per-file ignores
  ([`5cffc8e`](https://github.com/MountainGod2/cb-events/commit/5cffc8ee887aba17b1d04e59f2cf3b3f0c1a2d87))


## v2.2.0 (2025-10-02)

### Features

- **security**: Add bandit for security scanning
  ([`67ac009`](https://github.com/MountainGod2/cb-events/commit/67ac009f48ea9d0076cc0ba32a5fb09f7fba612c))


## v2.1.0 (2025-10-02)

### Features

- **deps**: Add pylint-pydantic for enhanced linting support
  ([`93daedb`](https://github.com/MountainGod2/cb-events/commit/93daedb79010f40b81c02068d4d048054cc8627b))

### Refactoring

- **models**: Remove pylint disable comments for user data access
  ([`60cee53`](https://github.com/MountainGod2/cb-events/commit/60cee53242180c40081928ebe339e9303d96fc62))

- **pylint**: Remove unused message control settings and adjust max attributes
  ([`1045f54`](https://github.com/MountainGod2/cb-events/commit/1045f54079e27e480b9402be76445ad9b088939a))


## v2.0.0 (2025-10-02)

### Refactoring

- **client**: Improve error handling in EventClient response processing
  ([`ee104ab`](https://github.com/MountainGod2/cb-events/commit/ee104abd409562202724492fde52153e8767d220))

- **client**: Improve logging configuration
  ([`2e270c6`](https://github.com/MountainGod2/cb-events/commit/2e270c6460499dfe6388eb0ad53c461030731a76))

- **client**: Improve logging configuration
  ([`eacbf8c`](https://github.com/MountainGod2/cb-events/commit/eacbf8c1478ec1c1eecdbc2072e1658795504a8d))

- **client**: Simplify error handling and JSON parsing in EventClient
  ([`de72f0d`](https://github.com/MountainGod2/cb-events/commit/de72f0d55ca5ec6a15f7855edf568bfa16038093))

- **config**: Make EventClientConfig dataclass immutable
  ([`cd63846`](https://github.com/MountainGod2/cb-events/commit/cd63846db0cd2ef456ef08b72ac88646d411170c))

- **constants**: Update HTTP status codes for error handling
  ([`dfd3f4a`](https://github.com/MountainGod2/cb-events/commit/dfd3f4a89e20b572135ad2560aa2af82525ce31b))

- **example**: Enhance event handling and improve documentation in example.py
  ([`f3bc6d0`](https://github.com/MountainGod2/cb-events/commit/f3bc6d07320de2f7283b06e9685ff1290038c91a))

- **init**: Add EventHandler to module exports
  ([`56c7388`](https://github.com/MountainGod2/cb-events/commit/56c7388bd2b4155968de1f9748f733a8e7788702))

- **logging**: Standardize logger usage in EventClient and EventRouter
  ([`496a8b0`](https://github.com/MountainGod2/cb-events/commit/496a8b0bf81fbf3bc581835a2957556b8ed7ac17))

- **models**: Remove pylint disable comments for member access
  ([`9447fa2`](https://github.com/MountainGod2/cb-events/commit/9447fa2b33913623d5caf7e5918a322af0c748ff))

- **pre-commit**: Replace pip-audit repo with local configuration
  ([`9693f8f`](https://github.com/MountainGod2/cb-events/commit/9693f8f931f1061023933897719608332373bab2))

- **router**: Add stricter event type handling
  ([`1998d65`](https://github.com/MountainGod2/cb-events/commit/1998d65a510465c13325f08808b67bd526e36db8))

- **tests**: Add e2e marker to TestIntegration class
  ([`ed0a919`](https://github.com/MountainGod2/cb-events/commit/ed0a919dc7d4d46da02afd0515ca014c722daf99))

- **tests**: Remove obsolete test_config.py, enhance test_e2e.py, add test_exceptions.py, and
  streamline model tests
  ([`abf4538`](https://github.com/MountainGod2/cb-events/commit/abf45380b483ef395e5e94ea4373623f5332440e))

- **tests**: Remove redundant server error handling test from TestEventClient
  ([`7428912`](https://github.com/MountainGod2/cb-events/commit/7428912c4711784cf238836989dea9fadf55f1b2))

- **tests**: Remove redundant tests from TestEventClientConfig
  ([`d451a9a`](https://github.com/MountainGod2/cb-events/commit/d451a9a643b877595fb4b874bfed67bbe96ab6c1))

- **tests**: Update per-file ignores and adjust coverage fail threshold
  ([`bbdf5aa`](https://github.com/MountainGod2/cb-events/commit/bbdf5aa0119170fff80c36b61b7cc061e6195555))

- **tests**: Update rate limit handling test
  ([`4e1cee3`](https://github.com/MountainGod2/cb-events/commit/4e1cee3191b7a2767b6853ee16d9520557029c4a))


## v1.13.0 (2025-09-29)

### Features

- **router**: Add logging for event dispatching
  ([`47754e9`](https://github.com/MountainGod2/cb-events/commit/47754e9f5a1b0d95948da5033282f4575b79ed4a))

### Refactoring

- **constants**: Reorganize retry attributes
  ([`cd7eabb`](https://github.com/MountainGod2/cb-events/commit/cd7eabb067e80e5d1c33c3eac2bd8f6568c2417a))


## v1.12.0 (2025-09-29)

### Features

- **models**: Add is_private property to determine message type
  ([`ae04d36`](https://github.com/MountainGod2/cb-events/commit/ae04d366f2efc2a9ce7d5a36a7bd1ebdb47c9b7d))


## v1.11.1 (2025-09-28)

### Bug Fixes

- Update references from 'chaturbate-events' to 'cb-events'
  ([`bdcb541`](https://github.com/MountainGod2/cb-events/commit/bdcb54126c5bb8187b794a91dc80abb5026dc41e))

- **semantic-release**: Add patterns for docs and initial commit to exclude commit patterns
  ([`859dd31`](https://github.com/MountainGod2/cb-events/commit/859dd3114c696a9a9b93e52615b9e650c41c865f))

### Refactoring

- **all**: Change project name from 'chaturbate-events' to 'cb-events'
  ([`877355a`](https://github.com/MountainGod2/cb-events/commit/877355a8d4f7b756cc44ad25665f1eec8b5ff3c9))


## v1.11.0 (2025-09-27)

### Bug Fixes

- **Dockerfile**: Add '-u' flag to python entrypoint for unbuffered output
  ([`8984894`](https://github.com/MountainGod2/cb-events/commit/898489447b3c941767c49c45fb441d8e965c812b))

### Features

- **config**: Add example environment file for Chaturbate API credentials
  ([`c607eda`](https://github.com/MountainGod2/cb-events/commit/c607eda015f0ce40bf0dbfcd381545ddf51d9f74))

### Refactoring

- **client**: Remove redundant asterisk in EventClient constructor parameters
  ([`2376cdd`](https://github.com/MountainGod2/cb-events/commit/2376cdd8c557c7cffe68795c610a2a916c82d3f9))


## v1.10.0 (2025-09-26)

### Features

- Add Cloudflare error handling and retry tests in EventClient
  ([`4025f06`](https://github.com/MountainGod2/cb-events/commit/4025f06f313c368c023e7d071de7c1a2e55ce878))

- Introduce EventClientConfig for improved configuration management
  ([`d72090f`](https://github.com/MountainGod2/cb-events/commit/d72090f33489ed026437eec1b97b4129a4e3b655))

- Refactor EventClient initialization to use EventClientConfig for improved configuration management
  ([`6047035`](https://github.com/MountainGod2/cb-events/commit/60470353be78730b198392a69211be9171dae6f1))


## v1.9.0 (2025-09-24)

### Bug Fixes

- Update uv dependency to version 0.8.22 in Dockerfile
  ([`b7356c0`](https://github.com/MountainGod2/cb-events/commit/b7356c023bfd6b1c555abd84c8eb8224e2a9e27d))

### Features

- Add Dockerfile and .dockerignore for containerization
  ([`60b691b`](https://github.com/MountainGod2/cb-events/commit/60b691bfa9607e90ff2d8843ceb5804c6d89e247))

- Add python-version configuration for pyrefly tool
  ([`6abab23`](https://github.com/MountainGod2/cb-events/commit/6abab23d4da331b99452265e3be044708099b875))

### Refactoring

- Enhance test coverage for Event models and EventRouter functionality
  ([`24878f1`](https://github.com/MountainGod2/cb-events/commit/24878f1316d36291ed006f69a56727bdb3537182))

- Improve graceful shutdown handling in example script
  ([`df5d02f`](https://github.com/MountainGod2/cb-events/commit/df5d02f766f4f708fe087ef4229442323e0a94b4))

- Move create_url_pattern function to test_client.py and remove unused import from conftest.py
  ([`32c7ab3`](https://github.com/MountainGod2/cb-events/commit/32c7ab3aef339875334526b0a1d737aa51f2b59c))

- Remove is_private property from Message model
  ([`0bf2fb0`](https://github.com/MountainGod2/cb-events/commit/0bf2fb07855306b6fc2f542d90ef7858664ba954))

- Update default retry attempts to 8 and adjust documentation accordingly
  ([`a878d1c`](https://github.com/MountainGod2/cb-events/commit/a878d1c13a97953a1e3a19556698f6188f0c98d1))


## v1.8.0 (2025-09-22)

### Features

- Enhance EventClient with configurable retry logic for network errors
  ([`bcd4b38`](https://github.com/MountainGod2/cb-events/commit/bcd4b384ee148a99abb900038e8fc0ca482d6de9))

### Refactoring

- Formatted to conform with updated line length settings
  ([`2240311`](https://github.com/MountainGod2/cb-events/commit/224031147e6ca5af764f2d3ee5006b2ac7eba062))

- Improve event handling messages and clarify credential validation
  ([`05af4c6`](https://github.com/MountainGod2/cb-events/commit/05af4c60fe4353f891221bd9cbbfce040f2ccac4))

- Remove obsolete Python version and funding link from pyproject.toml
  ([`b84da0a`](https://github.com/MountainGod2/cb-events/commit/b84da0adf3e8327eabb9134a19965c7fe812b502))


## v1.7.0 (2025-09-20)

### Bug Fixes

- Update CI/CD workflow and Makefile to use 'make test-e2e' for end-to-end tests
  ([`f5e3379`](https://github.com/MountainGod2/cb-events/commit/f5e3379e7312791d895e4f274730abd582f44404))

### Features

- Refactor EventClient and introduce constants for improved configuration and error handling
  ([`0c6576d`](https://github.com/MountainGod2/cb-events/commit/0c6576d7d2b7b2b44d27687b23884cf2c4f4b72c))

### Refactoring

- Remove test_config.py
  ([`0918753`](https://github.com/MountainGod2/cb-events/commit/091875360a4491641b6145f81dfdc285b9ed48ca))

- **tests**: Move e2e tests into main test module
  ([`d390688`](https://github.com/MountainGod2/cb-events/commit/d390688b2c15746f54906cd99f4cd3faa2183603))


## v1.6.1 (2025-09-20)

### Bug Fixes

- **deps**: Update dependency pydantic to v2.11.9
  ([#13](https://github.com/MountainGod2/cb-events/pull/13),
  [`87459bd`](https://github.com/MountainGod2/cb-events/commit/87459bd6d00ff585cbd3dd63a3fc31c2ebc5c20d))

### Refactoring

- **ci-cd**: Update end-to-end test command to filter by e2e marker
  ([`4f13743`](https://github.com/MountainGod2/cb-events/commit/4f137433f5a0844e40b47a097fed441d6a618ad6))

- **client**: Include event types in debug output
  ([`01b9dbd`](https://github.com/MountainGod2/cb-events/commit/01b9dbd187cca76962226d86f2d232c5576f7de9))

- **client**: Replace aiohttp references with specific imports and add rate limiter to polling
  ([`49fda32`](https://github.com/MountainGod2/cb-events/commit/49fda328bd31843de46c85234bca37ce7fc45ad6))

- **example**: Remove unused __init__.py file from examples directory
  ([`9c58f84`](https://github.com/MountainGod2/cb-events/commit/9c58f8401804a6108d174a9d1cdffe42c8123281))

- **example**: Simplify tip event handler and remove message handlers
  ([`314085e`](https://github.com/MountainGod2/cb-events/commit/314085e02c75ff2e5f4b7a8746fee1556b325bc7))

- **exceptions**: Remove extra_info parameter from EventsError initialization
  ([`cacb857`](https://github.com/MountainGod2/cb-events/commit/cacb8575bdda43b631c714fbf1f1522f412c7937))

- **pyproject**: Update Python classifiers and ruff linting rules, enhance pytest options
  ([`566d270`](https://github.com/MountainGod2/cb-events/commit/566d270083d270d54645b65f4b4fd3e011d2b621))

- **tests**: Add missing e2e marker to test functions in test_e2e.py
  ([`2e0e41e`](https://github.com/MountainGod2/cb-events/commit/2e0e41e926ac2969b853a6364e660585d0671104))

- **tests**: Remove obsolete integration test for EventClient and EventRouter
  ([`74187df`](https://github.com/MountainGod2/cb-events/commit/74187dfffa02ae91e5203062e4209d51cde429ee))


## v1.6.0 (2025-09-16)

### Bug Fixes

- Reorganize imports for consistency across test files
  ([`f0fd75c`](https://github.com/MountainGod2/cb-events/commit/f0fd75c11b7e9f666e48bf20ed180901dfa0ee86))

- **docs**: Update deployment environment name to match GitHub Pages convention
  ([`c3709c6`](https://github.com/MountainGod2/cb-events/commit/c3709c69355f2bdcadb29fcc5e15ec3cfd8028b0))

### Features

- **docs**: Added sphinx auto-doc pipeline
  ([`da2ddf4`](https://github.com/MountainGod2/cb-events/commit/da2ddf4f7677377503a153cc988fdf26754c5464))

### Refactoring

- **client**: Simplify error handling in nextUrl extraction
  ([`06887e4`](https://github.com/MountainGod2/cb-events/commit/06887e4f47b98d54c3ec30a6e96ef034b2b9abbf))

- **exceptions**: Simplify exception class documentation and imports
  ([`76653d7`](https://github.com/MountainGod2/cb-events/commit/76653d7276a5be54fc64ad3d9dc550cc6b070d77))

- **tests**: Improve test function names and remove unused tests
  ([`81ca969`](https://github.com/MountainGod2/cb-events/commit/81ca969717110a90462302261c3b47b252f18fd7))


## v1.5.0 (2025-09-13)

### Features

- **pyproject**: Update project metadata with additional keywords and URLs
  ([`daa2dbb`](https://github.com/MountainGod2/cb-events/commit/daa2dbb33a6309994bb9c830b0a2928745561971))


## v1.4.1 (2025-09-13)

### Bug Fixes

- **pyproject**: Add additional classifiers for improved package metadata
  ([`2cebae1`](https://github.com/MountainGod2/cb-events/commit/2cebae14f1ce754727c2f2ce701831b826d337e6))


## v1.4.0 (2025-09-13)

### Features

- **pyproject**: Add classifiers and project URLs for better package metadata
  ([`fed8e20`](https://github.com/MountainGod2/cb-events/commit/fed8e20a2104c802eaf11b8399e4dbc064e7d18f))

### Refactoring

- **ci-cd**: Update runner version from ubuntu-latest to ubuntu-24.04
  ([`ae30cf3`](https://github.com/MountainGod2/cb-events/commit/ae30cf3409ccdc125decc99c36056bee3461b18e))

- **tests**: Split and reorganize test cases
  ([`7776d0d`](https://github.com/MountainGod2/cb-events/commit/7776d0d12b0a3f10990aea352611a5b084a33a76))


## v1.3.2 (2025-09-11)

### Bug Fixes

- **renovate**: Update minimum release age from 14 days to 7 days
  ([`7923a7d`](https://github.com/MountainGod2/cb-events/commit/7923a7d956a12a982311d50d06efc8b1dae67887))

### Refactoring

- **.gitignore**: Refine IDE settings and ensure ruff cache is ignored
  ([`89faec8`](https://github.com/MountainGod2/cb-events/commit/89faec83d27bd1c9e28f9ffdb43c0bba3b980791))

- **extensions**: Add newline at end of file
  ([`ff6c9e6`](https://github.com/MountainGod2/cb-events/commit/ff6c9e61218118f229c52c8ed1dbeb303864328c))

- **Makefile**: Enhance organization and improve help output
  ([`4b32f94`](https://github.com/MountainGod2/cb-events/commit/4b32f94d446abcb4695483c09153830c99498723))

- **renovate**: Add 'pyright' to dev tools package grouping
  ([`e71957a`](https://github.com/MountainGod2/cb-events/commit/e71957a9ee8faf04b1e60affad83a56ec4aa220d))

- **renovate**: Update schedule and descriptions in package rules
  ([`eb40292`](https://github.com/MountainGod2/cb-events/commit/eb4029287ab5486c01543ea847c0d0c1dbe0ca3e))

- **verify_upstream**: Ensure newline at end of file
  ([`b84df2b`](https://github.com/MountainGod2/cb-events/commit/b84df2bd8aa22bf7a124929965f3ad994a0efc77))


## v1.3.1 (2025-09-09)

### Bug Fixes

- **client**: Correct syntax for aiohttp.ClientSession and logging error message
  ([`62b92d7`](https://github.com/MountainGod2/cb-events/commit/62b92d75cb4de11c9d85c13705a8520929dbb6fb))

- **example**: Add type hints to event handler functions
  ([`0429c45`](https://github.com/MountainGod2/cb-events/commit/0429c451b94747f4bb331092a9651264c2a5d868))

### Refactoring

- **dependencies**: Add aioresponses to development dependencies
  ([`de28201`](https://github.com/MountainGod2/cb-events/commit/de28201cd0a0b43186073de0188accb52658fcde))

- **lint**: Expand per-file ignores for test files
  ([`16cca90`](https://github.com/MountainGod2/cb-events/commit/16cca9074daf0416719648f87e95caf8e83ddb90))

- **pyproject**: Clean up lint ignore rules and remove unnecessary mypy override
  ([`ba15efb`](https://github.com/MountainGod2/cb-events/commit/ba15efb85d98eef31a2bd5cb0fb56902d808ecc9))

- **tests**: Add tests for additional scenarios
  ([`b11ff73`](https://github.com/MountainGod2/cb-events/commit/b11ff735d3b4dabc2ac7be429938ce05fc1db1c4))

- **tests**: Correct URL pattern usage in client error handling test
  ([`c1ba9f2`](https://github.com/MountainGod2/cb-events/commit/c1ba9f2e2b4b8e691443ed2f4e11745232866061))

- **tests**: Improve readability by formatting function parameters and return values
  ([`5e44f83`](https://github.com/MountainGod2/cb-events/commit/5e44f83ec33f2c554079f9f3f9a14a5b133365ff))

- **tests**: Remove noqa comments from assertions in test_router_registration
  ([`4e1f4b3`](https://github.com/MountainGod2/cb-events/commit/4e1f4b35613930fc221133645ffbc8303c4a1bb8))


## v1.3.0 (2025-09-09)

### Features

- **vscode**: Add extensions.json for recommended VS Code extensions
  ([`80ae65c`](https://github.com/MountainGod2/cb-events/commit/80ae65c166bf06cc7de40d89c35cc5bc4bbb84b5))

### Refactoring

- **example**: Simplify example file
  ([`124472b`](https://github.com/MountainGod2/cb-events/commit/124472b14e0bf030d4124446aa08886804b344f7))

- **lint**: Streamline per-file ignores for examples and tests, add Pyright overrides
  ([`3f45237`](https://github.com/MountainGod2/cb-events/commit/3f452370151ca747e593061fba113851b14e4f39))

- **tests**: Enhance type hints and docstrings in test fixtures and functions
  ([`e8fe2f2`](https://github.com/MountainGod2/cb-events/commit/e8fe2f20f29b3e2e7db0f8f01be529381534d619))


## v1.2.0 (2025-09-07)

### Bug Fixes

- **example**: Add credential validation in main function
  ([`a387849`](https://github.com/MountainGod2/cb-events/commit/a38784920d232d5a948206b504695f710b3b1a60))

### Features

- **client**: Enhance error logging and handling for authentication and JSON response
  ([`4725aab`](https://github.com/MountainGod2/cb-events/commit/4725aab592d7bbedd24b8094c511258cd0390ff0))

### Refactoring

- **client**: Improve session initialization for EventClient
  ([`3859630`](https://github.com/MountainGod2/cb-events/commit/38596302110385ff40e55b3b349d740cba4d3cb1))

- **exceptions**: Enhance EventsError class with detailed attributes and representation
  ([`59001ac`](https://github.com/MountainGod2/cb-events/commit/59001acb1c94f02673c40acca56f268229a56ce2))

- **renovate**: Update description to include digest updates for automerge
  ([`ec19380`](https://github.com/MountainGod2/cb-events/commit/ec193802e384f32602bf6783867214c7a42e9d77))

- **router**: Simplify event handler type definitions
  ([`ec5f4ba`](https://github.com/MountainGod2/cb-events/commit/ec5f4baf77038d6683cfa7a3c4cfd0c85ff7b457))


## v1.1.4 (2025-09-04)

### Bug Fixes

- **lint**: Add new ignore patterns for examples and tests
  ([`0efaa4f`](https://github.com/MountainGod2/cb-events/commit/0efaa4fd5db80e758d0f626a725827cf685ed188))

### Refactoring

- **ci**: Improve job naming conventions
  ([`124fd8d`](https://github.com/MountainGod2/cb-events/commit/124fd8d5d36a4f4b08474d8b8132138120cb3461))

- **ci**: Update uv cache references in workflow
  ([`14e1935`](https://github.com/MountainGod2/cb-events/commit/14e19352fb8fae9639aaafa3606f7553d3485157))

- **docs**: Update docstrings across modules
  ([`339299b`](https://github.com/MountainGod2/cb-events/commit/339299bc6fd2edb9c814f139f5ee5195842e6b0e))

- **example**: Remove imports and use standard library tools instead
  ([`7e28d36`](https://github.com/MountainGod2/cb-events/commit/7e28d365afe254941cfadfe24c08200b5a543ef0))


## v1.1.3 (2025-09-04)

### Bug Fixes

- **ci**: Ensure 'build' job is a dependency for 'deploy to PyPI'
  ([`0aa98c5`](https://github.com/MountainGod2/cb-events/commit/0aa98c5eba68bca31763c017f3ba6452a5db53e6))


## v1.1.2 (2025-09-04)

### Bug Fixes

- **ci**: Enhance CI/CD workflow structure and naming conventions
  ([`177c65b`](https://github.com/MountainGod2/cb-events/commit/177c65b35630b3ae377e9eb43dc969e56d8bb2e7))


## v1.1.1 (2025-09-04)

### Bug Fixes

- **ci**: Update artifact download path for PyPI publishing
  ([`330c1ba`](https://github.com/MountainGod2/cb-events/commit/330c1ba9af1f52d29c2cc16ab80b77ba8813dd4d))


## v1.1.0 (2025-09-04)

### Features

- **client**: Enhance logging and token masking in EventClient
  ([`ba225ed`](https://github.com/MountainGod2/cb-events/commit/ba225ed41c5fb80617a8371d2d499c8a1a6d8d49))

### Refactoring

- **ci**: Update naming throughout CI/CD workflow
  ([`d56f5af`](https://github.com/MountainGod2/cb-events/commit/d56f5af20bb7c3d501d8f3120703aca9a2b3c695))


## v1.0.3 (2025-08-27)

### Bug Fixes

- **renovate**: Format schedule and managerFilePatterns for consistency
  ([`33568cd`](https://github.com/MountainGod2/cb-events/commit/33568cdb94486ed5347b900dabde08759ab92dea))

### Refactoring

- **renovate**: Update merge schedule
  ([`3126de1`](https://github.com/MountainGod2/cb-events/commit/3126de1ec91aa87ae8653ffe0471b5e6139607b2))


## v1.0.2 (2025-08-27)

### Bug Fixes

- **example**: Add mypy override to ignore errors in example module
  ([`c74cc44`](https://github.com/MountainGod2/cb-events/commit/c74cc44b72f47aadce21f479bce4d1bf215da477))


## v1.0.1 (2025-08-27)

### Bug Fixes

- **example**: Replace logging with print statements and add PEP 723 inline deps
  ([`ab90396`](https://github.com/MountainGod2/cb-events/commit/ab90396aa5a3f16b9ded5511f7b4f243fcb25949))

### Refactoring

- **pyproject**: Remove unused examples dependency and update lint ignores
  ([`e8e8ae4`](https://github.com/MountainGod2/cb-events/commit/e8e8ae4b60f91a844a7651c07c0e234a68add8d1))

- **router**: Improve type annotations and enhance handler registration logic
  ([`37a61bf`](https://github.com/MountainGod2/cb-events/commit/37a61bfe132b6b2fd2654b3b270408faded31f89))


## v1.0.0 (2025-08-26)

- Initial Release
