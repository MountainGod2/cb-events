# CHANGELOG

<!-- version list -->

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


## v8.0.2 (2026-04-20)

### Bug Fixes

- **semantic_release**: Update commit patterns for changelog
  ([`5b0c8e1`](https://github.com/MountainGod2/cb-events/commit/5b0c8e1916288c1c7fea6e52a13f65e590d5f0ec))


## v8.0.1 (2026-04-18)

### Bug Fixes

- **models**: Improve handling of empty string subgender
  ([#115](https://github.com/MountainGod2/cb-events/pull/115),
  [`f1f0ece`](https://github.com/MountainGod2/cb-events/commit/f1f0ece80e7e7ffb7d87472811454c94b8df65cf))


## v8.0.0 (2026-04-18)

### Refactoring

- Removed option to extend additional URLs
  ([#114](https://github.com/MountainGod2/cb-events/pull/114),
  [`a9534fb`](https://github.com/MountainGod2/cb-events/commit/a9534fb54ab7c5efed9182bf2625470632dc2328))

### Breaking Changes

- `next_url_allowed_hosts` has been removed and hosts are now limited to only the main API and
  testbed endpoints


## v7.1.2 (2026-04-13)

### Bug Fixes

- **security**: Update dependency pytest to v9.0.3 [security]
  ([#104](https://github.com/MountainGod2/cb-events/pull/104),
  [`0fc4480`](https://github.com/MountainGod2/cb-events/commit/0fc4480d73e65466ac37e314e8edc0ca52ad9c7f))


## v7.1.1 (2026-04-13)

### Bug Fixes

- Update admonitions pattern ([#102](https://github.com/MountainGod2/cb-events/pull/102),
  [`51eac6c`](https://github.com/MountainGod2/cb-events/commit/51eac6c5d9f1c268a58dc58931f51808b5e44491))

- **pyproject**: Update admonitions pattern
  ([#102](https://github.com/MountainGod2/cb-events/pull/102),
  [`51eac6c`](https://github.com/MountainGod2/cb-events/commit/51eac6c5d9f1c268a58dc58931f51808b5e44491))


## v7.1.0 (2026-04-11)

### Features

- Convert next_url_allowed_hosts to tuple and reorganize constants
  ([#100](https://github.com/MountainGod2/cb-events/pull/100),
  [`57ea719`](https://github.com/MountainGod2/cb-events/commit/57ea7190ea266668d4bfc97a5a92577a2b55de30))


## v7.0.1 (2026-04-09)

### Bug Fixes

- Handle status_code check for None ([#93](https://github.com/MountainGod2/cb-events/pull/93),
  [`b02019e`](https://github.com/MountainGod2/cb-events/commit/b02019e8c47d2073a3e2bc3e49c0785ca3ed4f5a))

- **exceptions**: Handle status_code check for None
  ([#93](https://github.com/MountainGod2/cb-events/pull/93),
  [`b02019e`](https://github.com/MountainGod2/cb-events/commit/b02019e8c47d2073a3e2bc3e49c0785ca3ed4f5a))


## v7.0.0 (2026-04-08)

### Refactoring

- **config**: Change `strict_validation` default to false
  ([#92](https://github.com/MountainGod2/cb-events/pull/92),
  [`eb3ab1c`](https://github.com/MountainGod2/cb-events/commit/eb3ab1ceaa9465069b0790e254f6aef2bd3c3f7e))


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


## v6.0.0 (2026-03-15)

### Chores

- **dependencies**: Replace tenacity with stamina for retry logic
  ([#56](https://github.com/MountainGod2/cb-events/pull/56),
  [`7f260c1`](https://github.com/MountainGod2/cb-events/commit/7f260c12fdf63e5ee20bee6836f2524a55fac3ed))

### Features

- **dependencies**: Replace tenacity with stamina for retry logic
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


## v5.8.2 (2026-01-07)

### Bug Fixes

- **python-runtime**: Update dependency aiohttp to v3.13.3
  ([#49](https://github.com/MountainGod2/cb-events/pull/49),
  [`17ce240`](https://github.com/MountainGod2/cb-events/commit/17ce240b1f92914e8bf1e8e05f0076ff433bf044))


## v5.8.1 (2025-12-26)

### Bug Fixes

- **docs**: Update html_theme_options type to include bool
  ([`9c9a3a8`](https://github.com/MountainGod2/cb-events/commit/9c9a3a894aa502ced20674336056b3342851edef))


## v5.8.0 (2025-12-13)

### Features

- **client**: Add response snippet and host entry sanitization
  ([`a18825b`](https://github.com/MountainGod2/cb-events/commit/a18825b805db10d18a8b1ecf1264e8bb3b101408))


## v5.7.0 (2025-12-09)

### Features

- **client**: Enhance nextUrl validation and add jitter to retry delay
  ([`122e289`](https://github.com/MountainGod2/cb-events/commit/122e28913f4ca67c96b7da6678195ba035c57b44))


## v5.6.5 (2025-12-03)

### Bug Fixes

- **router**: Handle asyncio.CancelledError separately
  ([`8fb30bd`](https://github.com/MountainGod2/cb-events/commit/8fb30bd7a0ebd3f61b043d75107bd45252cae499))


## v5.6.4 (2025-11-30)

### Bug Fixes

- **runtime**: Update dependency pydantic to v2.12.5
  ([#35](https://github.com/MountainGod2/cb-events/pull/35),
  [`fec4603`](https://github.com/MountainGod2/cb-events/commit/fec4603cc69d8d9f819c43a7f8fa12c5d38d40f8))


## v5.6.3 (2025-11-29)

### Bug Fixes

- **client**: Prevent redirects in session requests
  ([`80f7305`](https://github.com/MountainGod2/cb-events/commit/80f730521efa1e5d06187d938fd2738e395843dc))


## v5.6.2 (2025-11-22)

### Bug Fixes

- **deps**: Add examples group for python-dotenv and rich
  ([`07a4bfe`](https://github.com/MountainGod2/cb-events/commit/07a4bfebbd389956bc8cdcbe41deddd3014ff15c))

- **Dockerfile**: Update Python base image to 3.14
  ([`f36f456`](https://github.com/MountainGod2/cb-events/commit/f36f45655066d00a34e627e3825ea1a1c4b4308e))

- **Dockerfile**: Update uv dependency to version 0.9.11
  ([`14cfa07`](https://github.com/MountainGod2/cb-events/commit/14cfa079d8666e6cc6528679ba556f7652e6de44))


## v5.6.1 (2025-11-16)

### Bug Fixes

- **tests**: Update coverage options to include src and omit tests
  ([`d370837`](https://github.com/MountainGod2/cb-events/commit/d370837f990988d29118b52fc574ab5af80419fd))


## v5.6.0 (2025-11-15)

### Features

- **config**: Add next_url_allowed_hosts to ClientConfig
  ([`acf3f4c`](https://github.com/MountainGod2/cb-events/commit/acf3f4ce213c971b5f89a14957b9e4ee56b14ad9))


## v5.5.1 (2025-11-15)

### Bug Fixes

- **test**: Disable coverage for end-to-end tests
  ([`d760ef6`](https://github.com/MountainGod2/cb-events/commit/d760ef6c835d54e085f7372d5ebdbdf678e1477c))


## v5.5.0 (2025-11-13)

### Features

- **models**: Improve media purchase event handling
  ([`dc5b44b`](https://github.com/MountainGod2/cb-events/commit/dc5b44ba6655ebd90a7444fe09766b458a3a027e))


## v5.4.0 (2025-11-12)

### Features

- **tests**: Add live testbed polling test with env credentials
  ([`e66a7ba`](https://github.com/MountainGod2/cb-events/commit/e66a7ba713bb448916f66df6bb65ae3b2aab56f4))


## v5.3.0 (2025-11-10)

### Features

- **ci**: Add grouping for GitHub Actions workflows
  ([`37646d6`](https://github.com/MountainGod2/cb-events/commit/37646d621a439484ef9e5c898ded7ff7def6c72b))


## v5.2.2 (2025-11-10)

### Bug Fixes

- **renovate**: Update package name matching patterns
  ([`a4735c5`](https://github.com/MountainGod2/cb-events/commit/a4735c5dc9fb6537646df25eb7c91486d04c3df6))


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


## v5.1.1 (2025-11-06)

### Bug Fixes

- **client**: Handle event ID extraction for non-mapping items
  ([`96f3945`](https://github.com/MountainGod2/cb-events/commit/96f39455b8fe0459cf40f7027d33f9b88ac28301))


## v5.1.0 (2025-11-05)

### Bug Fixes

- **auth**: Improve error messages for username and token validation
  ([`a6ea8e7`](https://github.com/MountainGod2/cb-events/commit/a6ea8e703ffd36f9beb3ce6c37d756daaa1bf11b))

### Features

- **router**: Enhance async handler registration and error handling
  ([`35dbe52`](https://github.com/MountainGod2/cb-events/commit/35dbe5217e521f4422fde4aa7940c2114564cfc4))


## v5.0.0 (2025-11-05)

### Refactoring

- **docs**: Update README and example to use ClientConfig and Router
  ([`f9b59d3`](https://github.com/MountainGod2/cb-events/commit/f9b59d324d9b24795a939499332da4401dd916a2))


## v4.10.1 (2025-11-04)

### Bug Fixes

- **router**: Improve handler registration and error logging in event dispatching
  ([`e42fa37`](https://github.com/MountainGod2/cb-events/commit/e42fa3778e4729695370197f5553c54f5ca13448))

- **router**: Log exceptions with handler names during event dispatching
  ([`9e37659`](https://github.com/MountainGod2/cb-events/commit/9e37659a0754abee05bc749dec774d8335526852))


## v4.10.0 (2025-11-03)

### Bug Fixes

- **README**: Update event streaming method in examples and improve retry attempts description
  ([`028d287`](https://github.com/MountainGod2/cb-events/commit/028d2874f51d03be75f35ffeba7cec1802be72a2))

### Features

- Add utility functions for masking secrets and formatting validation errors
  ([`4e7d88e`](https://github.com/MountainGod2/cb-events/commit/4e7d88e4582107f51520df93fdf9aab0795bd387))

- Implement event batch processing utilities with validation
  ([`de985e1`](https://github.com/MountainGod2/cb-events/commit/de985e1fb163dcf18a6db1467c2e1abe9a415f03))


## v4.9.2 (2025-11-02)

### Bug Fixes

- **docs**: Add new template for Python type documentation
  ([`1d34bd5`](https://github.com/MountainGod2/cb-events/commit/1d34bd5cf8f0c9dfb86d1f4f162e4135a26b9d02))


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


## v4.8.0 (2025-11-01)

### Bug Fixes

- **client**: Improve error handling for API requests
  ([`9799bc6`](https://github.com/MountainGod2/cb-events/commit/9799bc60cfea295ea46a94be27132711ff4306e7))

### Features

- **models**: Implement caching for event data retrieval
  ([`1e9ccaa`](https://github.com/MountainGod2/cb-events/commit/1e9ccaae491696f53326c748bda0a35244ff322e))


## v4.7.1 (2025-10-31)

### Bug Fixes

- **docs**: Clarify behavior of event properties and update version import
  ([`35df062`](https://github.com/MountainGod2/cb-events/commit/35df062181ed21c5d764107a6b2fd17b07f2da5a))

- **models**: Enhance error handling for data validation
  ([`d24bd84`](https://github.com/MountainGod2/cb-events/commit/d24bd84f2a2d89dacfd3f45648fa32db14415214))


## v4.7.0 (2025-10-31)

### Features

- **validation**: Introduce strict validation for event data and update error handling
  ([`ef2fe99`](https://github.com/MountainGod2/cb-events/commit/ef2fe995d10b406aa6b69ab26c73cb1a7f75b700))


## v4.6.1 (2025-10-30)

### Bug Fixes

- **constants**: Correct initialization of CLOUDFLARE_ERROR_CODES set
  ([`3120e80`](https://github.com/MountainGod2/cb-events/commit/3120e804ed876b68144ed3af6b9fc7ccb5bb3d54))

- **event**: Handle ValidationError when retrieving user, tip, message, and room subject data
  ([`27a1c9d`](https://github.com/MountainGod2/cb-events/commit/27a1c9dfb20c715f1bd424cc56bf921a932003c6))

- **router**: Correct type hint for _handlers in EventRouter initialization
  ([`0e6dcc5`](https://github.com/MountainGod2/cb-events/commit/0e6dcc50dc3d234967d3ed12cd725bb6501858f3))


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


## v4.4.2 (2025-10-27)

### Bug Fixes

- **client**: Add thread safety with asyncio lock for polling method
  ([`212b8d1`](https://github.com/MountainGod2/cb-events/commit/212b8d1c187ec7a4a4d992ac6c7015ff97579a7e))

- **config**: Update validation method for retry delays in EventClientConfig
  ([`e9bbe8d`](https://github.com/MountainGod2/cb-events/commit/e9bbe8d6d3af3b04a01dbbec5ca4ac5a278f1c3d))


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


## v4.0.3 (2025-10-20)

### Bug Fixes

- Change ValueError to AuthError for empty username and token in EventClient
  ([`d159944`](https://github.com/MountainGod2/cb-events/commit/d159944e17e0fefd88ace55c5361b7615ab96b80))

- **docs**: Improve error handling for authentication in README and index
  ([`527846c`](https://github.com/MountainGod2/cb-events/commit/527846c338af7c7a9d1f6e868526c5a2627dfe29))


## v4.0.2 (2025-10-20)

### Bug Fixes

- **docs**: Update linked files in README and index
  ([`41e111c`](https://github.com/MountainGod2/cb-events/commit/41e111c53c5628818de6f853e51fc941c88486e2))


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


## v3.1.1 (2025-10-17)

### Bug Fixes

- **models**: Ensure user, tip, and message data checks are explicit for None
  ([`81830c9`](https://github.com/MountainGod2/cb-events/commit/81830c9df7b2619df10f2c4764e08cd1a5fa7f32))

- **router**: Simplify exception handling in dispatch method documentation
  ([`47a302f`](https://github.com/MountainGod2/cb-events/commit/47a302f1ba46685dc147388bd9cac86a6c3ff5a0))


## v3.1.0 (2025-10-14)

### Features

- Add Codecov test results action to CI workflow
  ([`915386d`](https://github.com/MountainGod2/cb-events/commit/915386d159069129186a0418f04d357aceddfade))


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


## v3.0.1 (2025-10-10)

### Bug Fixes

- **docs**: Corrected event handling examples and descriptions
  ([`82c148f`](https://github.com/MountainGod2/cb-events/commit/82c148f10aa5b65e30c6e300c42c614d186cfb7c))


## v3.0.0 (2025-10-09)

### Bug Fixes

- **config**: Add validation for retry max delay against retry backoff
  ([`58bd2b2`](https://github.com/MountainGod2/cb-events/commit/58bd2b277569f9ed085b7707d94cebc15c4b3083))

### Refactoring

- **router**: Unify handler registry and improve event dispatching logic
  ([`64386cf`](https://github.com/MountainGod2/cb-events/commit/64386cf65c4a06ed579f94203824f6f196acf4bc))


## v2.5.0 (2025-10-08)

### Features

- Add error handling modes and RouterError for event dispatching
  ([`e1999cc`](https://github.com/MountainGod2/cb-events/commit/e1999ccb0cf5f48de3e2b7e3ec88e2dbc0a0782b))


## v2.4.3 (2025-10-07)

### Bug Fixes

- **docs**: Suppress duplicate object warnings in AutoAPI configuration
  ([`65c5978`](https://github.com/MountainGod2/cb-events/commit/65c597844ba13b69cc3e077a8c53edc8bac89992))


## v2.4.2 (2025-10-07)

### Bug Fixes

- **docs**: Update build command to allow AutoAPI duplicate warnings
  ([`caf9c15`](https://github.com/MountainGod2/cb-events/commit/caf9c1511cf9bcb06f6959b233a3e42a7c76af8f))


## v2.4.1 (2025-10-07)

### Bug Fixes

- **client**: Improve resource cleanup in close method with locking mechanism
  ([`ff71761`](https://github.com/MountainGod2/cb-events/commit/ff71761ba2443347c3d71cd44fffc0b3bbe1ec75))

- **pylint**: Increase max attributes limit from 10 to 12
  ([`f26817e`](https://github.com/MountainGod2/cb-events/commit/f26817e514f2c31686a396d1a7fbf14420d1cbf8))


## v2.4.0 (2025-10-05)

### Features

- **ci-cd**: Add attestations permissions and step for build provenance
  ([`e3a58c0`](https://github.com/MountainGod2/cb-events/commit/e3a58c03144b80cd50f2e67c8d37eab32f9e3967))


## v2.3.7 (2025-10-04)

### Bug Fixes

- **docs**: Update license links to use absolute URLs
  ([`d1da265`](https://github.com/MountainGod2/cb-events/commit/d1da26582b61b97eb1679d124317057220f6d1b4))


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


## v2.2.0 (2025-10-02)

### Features

- **security**: Add bandit for security scanning
  ([`67ac009`](https://github.com/MountainGod2/cb-events/commit/67ac009f48ea9d0076cc0ba32a5fb09f7fba612c))


## v2.1.0 (2025-10-02)

### Features

- **deps**: Add pylint-pydantic for enhanced linting support
  ([`93daedb`](https://github.com/MountainGod2/cb-events/commit/93daedb79010f40b81c02068d4d048054cc8627b))


## v2.0.0 (2025-10-02)

### Refactoring

- **client**: Improve error handling in EventClient response processing
  ([`ee104ab`](https://github.com/MountainGod2/cb-events/commit/ee104abd409562202724492fde52153e8767d220))


## v1.13.0 (2025-09-29)

### Features

- **router**: Add logging for event dispatching
  ([`47754e9`](https://github.com/MountainGod2/cb-events/commit/47754e9f5a1b0d95948da5033282f4575b79ed4a))


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


## v1.11.0 (2025-09-27)

### Bug Fixes

- **Dockerfile**: Add '-u' flag to python entrypoint for unbuffered output
  ([`8984894`](https://github.com/MountainGod2/cb-events/commit/898489447b3c941767c49c45fb441d8e965c812b))

### Features

- **config**: Add example environment file for Chaturbate API credentials
  ([`c607eda`](https://github.com/MountainGod2/cb-events/commit/c607eda015f0ce40bf0dbfcd381545ddf51d9f74))


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


## v1.8.0 (2025-09-22)

### Features

- Enhance EventClient with configurable retry logic for network errors
  ([`bcd4b38`](https://github.com/MountainGod2/cb-events/commit/bcd4b384ee148a99abb900038e8fc0ca482d6de9))


## v1.7.0 (2025-09-20)

### Bug Fixes

- Update CI/CD workflow and Makefile to use 'make test-e2e' for end-to-end tests
  ([`f5e3379`](https://github.com/MountainGod2/cb-events/commit/f5e3379e7312791d895e4f274730abd582f44404))

### Features

- Refactor EventClient and introduce constants for improved configuration and error handling
  ([`0c6576d`](https://github.com/MountainGod2/cb-events/commit/0c6576d7d2b7b2b44d27687b23884cf2c4f4b72c))


## v1.6.1 (2025-09-20)

### Bug Fixes

- **deps**: Update dependency pydantic to v2.11.9
  ([#13](https://github.com/MountainGod2/cb-events/pull/13),
  [`87459bd`](https://github.com/MountainGod2/cb-events/commit/87459bd6d00ff585cbd3dd63a3fc31c2ebc5c20d))


## v1.6.0 (2025-09-16)

### Bug Fixes

- Reorganize imports for consistency across test files
  ([`f0fd75c`](https://github.com/MountainGod2/cb-events/commit/f0fd75c11b7e9f666e48bf20ed180901dfa0ee86))

- **docs**: Update deployment environment name to match GitHub Pages convention
  ([`c3709c6`](https://github.com/MountainGod2/cb-events/commit/c3709c69355f2bdcadb29fcc5e15ec3cfd8028b0))

### Features

- **docs**: Added sphinx auto-doc pipeline
  ([`da2ddf4`](https://github.com/MountainGod2/cb-events/commit/da2ddf4f7677377503a153cc988fdf26754c5464))


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


## v1.3.2 (2025-09-11)

### Bug Fixes

- **renovate**: Update minimum release age from 14 days to 7 days
  ([`7923a7d`](https://github.com/MountainGod2/cb-events/commit/7923a7d956a12a982311d50d06efc8b1dae67887))


## v1.3.1 (2025-09-09)

### Bug Fixes

- **client**: Correct syntax for aiohttp.ClientSession and logging error message
  ([`62b92d7`](https://github.com/MountainGod2/cb-events/commit/62b92d75cb4de11c9d85c13705a8520929dbb6fb))

- **example**: Add type hints to event handler functions
  ([`0429c45`](https://github.com/MountainGod2/cb-events/commit/0429c451b94747f4bb331092a9651264c2a5d868))


## v1.3.0 (2025-09-09)

### Features

- **vscode**: Add extensions.json for recommended VS Code extensions
  ([`80ae65c`](https://github.com/MountainGod2/cb-events/commit/80ae65c166bf06cc7de40d89c35cc5bc4bbb84b5))


## v1.2.0 (2025-09-07)

### Bug Fixes

- **example**: Add credential validation in main function
  ([`a387849`](https://github.com/MountainGod2/cb-events/commit/a38784920d232d5a948206b504695f710b3b1a60))

### Features

- **client**: Enhance error logging and handling for authentication and JSON response
  ([`4725aab`](https://github.com/MountainGod2/cb-events/commit/4725aab592d7bbedd24b8094c511258cd0390ff0))


## v1.1.4 (2025-09-04)

### Bug Fixes

- **lint**: Add new ignore patterns for examples and tests
  ([`0efaa4f`](https://github.com/MountainGod2/cb-events/commit/0efaa4fd5db80e758d0f626a725827cf685ed188))


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


## v1.0.3 (2025-08-27)

### Bug Fixes

- **renovate**: Format schedule and managerFilePatterns for consistency
  ([`33568cd`](https://github.com/MountainGod2/cb-events/commit/33568cdb94486ed5347b900dabde08759ab92dea))


## v1.0.2 (2025-08-27)

### Bug Fixes

- **example**: Add mypy override to ignore errors in example module
  ([`c74cc44`](https://github.com/MountainGod2/cb-events/commit/c74cc44b72f47aadce21f479bce4d1bf215da477))


## v1.0.1 (2025-08-27)

### Bug Fixes

- **example**: Replace logging with print statements and add PEP 723 inline deps
  ([`ab90396`](https://github.com/MountainGod2/cb-events/commit/ab90396aa5a3f16b9ded5511f7b4f243fcb25949))


## v1.0.0 (2025-08-26)

- Initial Release
