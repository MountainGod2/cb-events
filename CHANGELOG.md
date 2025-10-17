# CHANGELOG

<!-- version list -->

## v3.1.1 (2025-10-17)

### Bug Fixes

- **models**: Ensure user, tip, and message data checks are explicit for None
  ([`81830c9`](https://github.com/MountainGod2/cb-events/commit/81830c9df7b2619df10f2c4764e08cd1a5fa7f32))

- **router**: Simplify exception handling in dispatch method documentation
  ([`47a302f`](https://github.com/MountainGod2/cb-events/commit/47a302f1ba46685dc147388bd9cac86a6c3ff5a0))

### Chores

- **deps**: Pin codecov/test-results-action action to 47f89e9
  ([#27](https://github.com/MountainGod2/cb-events/pull/27),
  [`93bc44e`](https://github.com/MountainGod2/cb-events/commit/93bc44ee14d5997dbd74d4b309a750c6e536a1c4))

- **deps**: Update astral-sh/setup-uv digest to b7bf789
  ([`6988c13`](https://github.com/MountainGod2/cb-events/commit/6988c13262b172b12a66f1d9e02e420577592104))

- **deps**: Update dependency sphinx-autodoc-typehints to v3.5.1
  ([`99f506d`](https://github.com/MountainGod2/cb-events/commit/99f506d928e4397745309f4ce3dd1b55dd949878))

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

### Chores

- Add junit.xml output to test coverage reports
  ([`999f029`](https://github.com/MountainGod2/cb-events/commit/999f029d4342fde889eba90970618181ad341824))

- Add junit.xml to .gitignore
  ([`7630ed3`](https://github.com/MountainGod2/cb-events/commit/7630ed3cec3aba4f2933680aa326d2d7c3d88810))

- **deps**: Reduce minimum release age from 7 days to 4 days
  ([`c6bcf49`](https://github.com/MountainGod2/cb-events/commit/c6bcf49d2b087fce928294cf2cdb1df47029a288))

- **deps**: Reorganize renovate package rules
  ([`a63da64`](https://github.com/MountainGod2/cb-events/commit/a63da64de9267dd364761b990b77d13c8486fdc6))

- **deps**: Tighten constraints for pylint versions
  ([`de3a18b`](https://github.com/MountainGod2/cb-events/commit/de3a18b6356ef8824f8ecc55a030226fdeb68b29))

- **deps**: Update dependency ruff to v0.14.0
  ([`074b7cb`](https://github.com/MountainGod2/cb-events/commit/074b7cb4a7a0f8bc679c37a9cd9aebe2d7b7a115))

- **deps**: Update dependency sphinx-autoapi to v3.6.1
  ([#22](https://github.com/MountainGod2/cb-events/pull/22),
  [`bb2d5c9`](https://github.com/MountainGod2/cb-events/commit/bb2d5c981b1df1ef759c2b74802e5f0bb447c753))

- **deps**: Update pre-commit
  ([`0151055`](https://github.com/MountainGod2/cb-events/commit/0151055968e0372333f50e6e9326eddf4ea16148))

- **deps**: Update pre-commit hook astral-sh/ruff-pre-commit to v0.14.0
  ([`6c3cca5`](https://github.com/MountainGod2/cb-events/commit/6c3cca5640497b795389d936d57e7f5f4ef1b54a))

- **deps**: Update pre-commit package rules
  ([`cb41f5e`](https://github.com/MountainGod2/cb-events/commit/cb41f5e0068892919f19d3c4d0c0c81aef6ba3b3))

- **deps**: Update pylint versioning constraints
  ([`0d7394e`](https://github.com/MountainGod2/cb-events/commit/0d7394eaf7866f5f5242a4dbc733542cab224d52))

- **deps**: Update uv dependency to version 0.9.2 in Dockerfile
  ([`d956ee6`](https://github.com/MountainGod2/cb-events/commit/d956ee6324d915b1612018139269839a9aca3d61))

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

### Chores

- **deps**: Update astral-sh/setup-uv digest to 3ccd0fd
  ([`c412300`](https://github.com/MountainGod2/cb-events/commit/c412300deed9fe4abf4933d0b31f6682ea60a8f5))

- **deps**: Update dependency pylint to v4
  ([#23](https://github.com/MountainGod2/cb-events/pull/23),
  [`8e8577b`](https://github.com/MountainGod2/cb-events/commit/8e8577be4d03fc48feeab10c0f3fc93350aa2683))

- **deps**: Update dependency pylint-pydantic to v0.4.0
  ([#25](https://github.com/MountainGod2/cb-events/pull/25),
  [`b2b0e6e`](https://github.com/MountainGod2/cb-events/commit/b2b0e6e33480559a38e62d69a4189462280a0fa8))

- **deps**: Update pre-commit hook adhtruong/mirrors-typos to v1.38.0
  ([`cc6ea5e`](https://github.com/MountainGod2/cb-events/commit/cc6ea5e6f86978ffd8696f750e9f003de614bb2c))


## v3.0.4 (2025-10-13)

### Bug Fixes

- **deps**: Update dependency aiohttp to v3.13.0
  ([`e035676`](https://github.com/MountainGod2/cb-events/commit/e035676aa192ff96869a62d26083fa2b1e980007))

### Chores

- **deps**: Lock file maintenance
  ([`001bbe6`](https://github.com/MountainGod2/cb-events/commit/001bbe62d6cf1e9cf3720c0a8d39c0b35fd92fee))

- **deps**: Update astral-sh/setup-uv digest to 2382069
  ([`67616f4`](https://github.com/MountainGod2/cb-events/commit/67616f4206a5f3c4bc492280986aa91088c8d399))

- **deps**: Update astral-sh/setup-uv digest to 3259c62
  ([`22e9405`](https://github.com/MountainGod2/cb-events/commit/22e9405514ab060cee073829822390662b2073e8))

- **deps**: Update dependency pylint to v3.3.9
  ([`65b746d`](https://github.com/MountainGod2/cb-events/commit/65b746d89debead3de57468282be0ac83af91dc2))


## v3.0.3 (2025-10-12)

### Bug Fixes

- **deps**: Update dependency pydantic to v2.11.10
  ([`e436274`](https://github.com/MountainGod2/cb-events/commit/e4362744b9e36cb4c8345f66582fa484b1f48b05))

### Chores

- **deps**: Update astral-sh/setup-uv digest to 9c6b5e9
  ([`ef54921`](https://github.com/MountainGod2/cb-events/commit/ef549215905ada16018af963c0aa779c732f5ac7))


## v3.0.2 (2025-10-11)

### Bug Fixes

- **client**: Improve JSON parsing error handling in EventClient
  ([`2f4572e`](https://github.com/MountainGod2/cb-events/commit/2f4572e5d4d7267e3b3016fff45f55514e08a55a))

### Chores

- **deps**: Add 'ty' package version 0.0.1a22 to dev dependencies
  ([`bc36a9d`](https://github.com/MountainGod2/cb-events/commit/bc36a9ddaa104f4d3063ab3e3e02759e92f441f0))

- **deps**: Update astral-sh/setup-uv digest to 1a91c38
  ([`63160be`](https://github.com/MountainGod2/cb-events/commit/63160be95a31da8c8948d6aa996fdd2bd7f23344))

- **deps**: Update dependency ruff to v0.13.3
  ([`f578eca`](https://github.com/MountainGod2/cb-events/commit/f578eca009328edd862354e960707bf74e302b1f))

- **deps**: Update github/codeql-action digest to 17783bf
  ([`de93a9c`](https://github.com/MountainGod2/cb-events/commit/de93a9cde26df999820c9143eac2924de1e2ba50))

- **deps**: Update pre-commit hook adhtruong/mirrors-typos to v1.37.2
  ([`0293300`](https://github.com/MountainGod2/cb-events/commit/029330025cd80c3b2b4b531892d3a4580c8f4ff2))

- **deps**: Update pre-commit hook astral-sh/ruff-pre-commit to v0.13.3
  ([`6aa5514`](https://github.com/MountainGod2/cb-events/commit/6aa55140f0f1275815e42940685b370482f527ec))

- **example**: Remove unnecessary docstring from main function
  ([`6fb644b`](https://github.com/MountainGod2/cb-events/commit/6fb644bc710e550a101fe7ad08bcb61c22cb1e4b))

### Documentation

- **__init__**: Update example to include config parameter as a keyword argument
  ([`ec18d4b`](https://github.com/MountainGod2/cb-events/commit/ec18d4bdcd4de258cb6585f8c2ed68cc3b3643ce))

- **constants**: Add additional docstrings
  ([`829f40b`](https://github.com/MountainGod2/cb-events/commit/829f40be5c117c3cf2b4ac2f4a21dfb9fe178684))

- **copilot**: Refine Chaturbate Events API instructions
  ([`c8b584f`](https://github.com/MountainGod2/cb-events/commit/c8b584f13bd3cd47340358b27240ca674dc7aad6))

- **README**: Clarify that the config parameter must be passed as a keyword argument
  ([`e243099`](https://github.com/MountainGod2/cb-events/commit/e243099a5354b569ea563d6165a532260e36da16))

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

### Testing

- Enhance error handling in EventClient tests and add new exception tests
  ([`ba0ceb1`](https://github.com/MountainGod2/cb-events/commit/ba0ceb1336f562558b1035a89f159fbcbb0e2407))


## v3.0.1 (2025-10-10)

### Bug Fixes

- **docs**: Corrected event handling examples and descriptions
  ([`82c148f`](https://github.com/MountainGod2/cb-events/commit/82c148f10aa5b65e30c6e300c42c614d186cfb7c))

### Chores

- **deps**: Update astral-sh/setup-uv digest to 3495667
  ([`88dfaf1`](https://github.com/MountainGod2/cb-events/commit/88dfaf1331ae3b7be696e91b1c9daf0a4e597f82))

- **deps**: Update astral-sh/setup-uv digest to 6d2eb15
  ([`43e466f`](https://github.com/MountainGod2/cb-events/commit/43e466f8cf8f612cb9167bbef2c5bd1e76a8d39b))

- **deps**: Update dependency pyright to v1.1.406
  ([`d3c6a54`](https://github.com/MountainGod2/cb-events/commit/d3c6a54d52c9d6fd6e649ae3bb692e690f0f2d67))

- **deps**: Update github/codeql-action digest to 6fd4ceb
  ([#20](https://github.com/MountainGod2/cb-events/pull/20),
  [`143f801`](https://github.com/MountainGod2/cb-events/commit/143f801eef6ff35252a5cafed2da5652c718a1ec))

- **deps**: Update pre-commit hook adhtruong/mirrors-typos to v1.37.0
  ([#21](https://github.com/MountainGod2/cb-events/pull/21),
  [`c4370ac`](https://github.com/MountainGod2/cb-events/commit/c4370accde13abd74494645534340cc72504e8c3))

- **deps**: Update pre-commit hook adhtruong/mirrors-typos to v1.37.1
  ([`d4e1d3d`](https://github.com/MountainGod2/cb-events/commit/d4e1d3d96edb26345987862a301124c44d40dfb7))


## v3.0.0 (2025-10-09)

### Bug Fixes

- **config**: Add validation for retry max delay against retry backoff
  ([`58bd2b2`](https://github.com/MountainGod2/cb-events/commit/58bd2b277569f9ed085b7707d94cebc15c4b3083))

### Chores

- **deps**: Update astral-sh/setup-uv digest to eb1897b
  ([#19](https://github.com/MountainGod2/cb-events/pull/19),
  [`a6b30e0`](https://github.com/MountainGod2/cb-events/commit/a6b30e0da3e82d01a1fa5285bd354b8285d9fa38))

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

### Chores

- **deps**: Update astral-sh/setup-uv digest to f610be5
  ([`192a753`](https://github.com/MountainGod2/cb-events/commit/192a7530152f33c03cbd4e13d74f4e0e121fdad6))

- **deps**: Update github/codeql-action digest to 5528384
  ([`d9e86d7`](https://github.com/MountainGod2/cb-events/commit/d9e86d755c80ab6be6b19e90ddaac28e556af47a))

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

### Chores

- **clean**: Remove SARIF files during cleanup
  ([`aae48a6`](https://github.com/MountainGod2/cb-events/commit/aae48a6727eb4321a1d28a52b8e1fa8e2da6e862))

- **deps**: Lock file maintenance
  ([`3c57df3`](https://github.com/MountainGod2/cb-events/commit/3c57df3724ffeafe1c54397530b441efadf1f97d))

- **deps**: Update actions/attest-build-provenance digest to 3752c92
  ([`87804c2`](https://github.com/MountainGod2/cb-events/commit/87804c2a100003a7f63c5d17077fa13372fc29ed))

- **deps**: Update actions/attest-build-provenance digest to bed76f6
  ([`6809828`](https://github.com/MountainGod2/cb-events/commit/6809828480e9799fc56edec7256370578d1bb0f5))

### Refactoring

- **imports**: Consolidate exception imports
  ([`04fa725`](https://github.com/MountainGod2/cb-events/commit/04fa725e1ec65d3456acd7f76d6e2b4f8b5f4172))


## v2.4.0 (2025-10-05)

### Chores

- **deps**: Update actions/checkout digest to ff7abcd
  ([#14](https://github.com/MountainGod2/cb-events/pull/14),
  [`0ae19ac`](https://github.com/MountainGod2/cb-events/commit/0ae19acf5603ab9f9e88e32dcc25b98ff6ebd5da))

- **deps**: Update actions/download-artifact digest to 4a24838
  ([#15](https://github.com/MountainGod2/cb-events/pull/15),
  [`538a229`](https://github.com/MountainGod2/cb-events/commit/538a2290b92bba27e306a72a02ac854ac2b1903b))

- **deps**: Update actions/upload-artifact digest to 2848b2c
  ([#16](https://github.com/MountainGod2/cb-events/pull/16),
  [`28852d3`](https://github.com/MountainGod2/cb-events/commit/28852d39e9ded40d80a9520340583d7ee3f6f54c))

- **deps**: Update astral-sh/setup-uv digest to d9ee7e2
  ([#17](https://github.com/MountainGod2/cb-events/pull/17),
  [`61a4db0`](https://github.com/MountainGod2/cb-events/commit/61a4db0cf493292e8a98c5a547d26b03956779b7))

- **deps**: Update github/codeql-action digest to 065c6cf
  ([#18](https://github.com/MountainGod2/cb-events/pull/18),
  [`5a97c5f`](https://github.com/MountainGod2/cb-events/commit/5a97c5f5e29f95277739ae2ca52107eaa1c74c04))

- **deps**: Update pypa/gh-action-pypi-publish digest to ab69e43
  ([`db639b9`](https://github.com/MountainGod2/cb-events/commit/db639b91d61db0bf603b792fdb3f9de69638ad48))

### Documentation

- **copilot**: Enhance commit message guidelines with specific examples and actionable verbs
  ([`518dd5e`](https://github.com/MountainGod2/cb-events/commit/518dd5e0c76c2f8062faefeab16396e4ace2989b))

- **copilot**: Enhance documentation with development standards and usage patterns
  ([`44d88e3`](https://github.com/MountainGod2/cb-events/commit/44d88e3277bf56d744fc483af3f7b7d5077bf1ca))

- **copilot**: Refine commit message guidelines to discourage vague terms
  ([`7565a8a`](https://github.com/MountainGod2/cb-events/commit/7565a8a64a9a901789fc6c0c61c6396329c58942))

- **copilot**: Update commit message guidelines to avoid vague terms
  ([`3932231`](https://github.com/MountainGod2/cb-events/commit/3932231cb86774fbf49f338f6f170af2fb1216fb))

- **copilot**: Update commit message guidelines to specify language usage
  ([`155a803`](https://github.com/MountainGod2/cb-events/commit/155a803f1fdc96e986cd3a5e641322c0845809d1))

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

### Chores

- **docs**: Remove unused autodoc Pydantic configuration
  ([`b0da7e8`](https://github.com/MountainGod2/cb-events/commit/b0da7e8bd9f3a3317049219e7236df81f13ea55b))

### Documentation

- **conf**: Remove unused sphinxcontrib.autodoc_pydantic extension
  ([`377f3d4`](https://github.com/MountainGod2/cb-events/commit/377f3d49c19efb106e4988d0f6c607234a611d5c))

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

### Chores

- **deps**: Update github/codeql-action digest to 64d10c1
  ([`35272ec`](https://github.com/MountainGod2/cb-events/commit/35272ec6e51a6c16738d92af16231e55caccfc2c))

- **deps**: Update pre-commit hook adhtruong/mirrors-typos to v1.36.3
  ([`60a84b5`](https://github.com/MountainGod2/cb-events/commit/60a84b56b45884f15b60664d11cf5c97966c180d))


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

### Chores

- **deps**: Remove autodoc-pydantic dependency from docs requirements
  ([`9eafc61`](https://github.com/MountainGod2/cb-events/commit/9eafc61ea81d67514633b112740a66e7f008ea12))

- **deps**: Update dependency furo to v2025.9.25
  ([`349c50b`](https://github.com/MountainGod2/cb-events/commit/349c50b606896af43cd3b81614030bd25ed8f168))

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

### Chores

- **deps**: Update dependency ruff to v0.13.2
  ([`4c13ae1`](https://github.com/MountainGod2/cb-events/commit/4c13ae18dd96cb93c8867d5ac9d36b6fdffa9a05))

- **deps**: Update pre-commit hook astral-sh/ruff-pre-commit to v0.13.2
  ([`12af5ca`](https://github.com/MountainGod2/cb-events/commit/12af5ca78f449d00381a0570c27fdd36dd6147e5))

### Features

- **deps**: Add pylint-pydantic for enhanced linting support
  ([`93daedb`](https://github.com/MountainGod2/cb-events/commit/93daedb79010f40b81c02068d4d048054cc8627b))

### Refactoring

- **models**: Remove pylint disable comments for user data access
  ([`60cee53`](https://github.com/MountainGod2/cb-events/commit/60cee53242180c40081928ebe339e9303d96fc62))

- **pylint**: Remove unused message control settings and adjust max attributes
  ([`1045f54`](https://github.com/MountainGod2/cb-events/commit/1045f54079e27e480b9402be76445ad9b088939a))


## v2.0.0 (2025-10-02)

### Chores

- **deps**: Update astral-sh/setup-uv digest to d0cc045
  ([`bc47524`](https://github.com/MountainGod2/cb-events/commit/bc4752451746e5994b7c029a41280110d463f613))

### Documentation

- **example**: Update docstring
  ([`29aa02e`](https://github.com/MountainGod2/cb-events/commit/29aa02ebd190361c7c7ebbbd989ee9227aba76a1))

- **index**: Updated to match README
  ([`a8a4c52`](https://github.com/MountainGod2/cb-events/commit/a8a4c52b0e36047b57147ffe9d62663b27abbe65))

- **pyproject**: Increase max-attributes limit
  ([`a67407d`](https://github.com/MountainGod2/cb-events/commit/a67407d64d41d174843fb0aa1a58463d044fce35))

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

### Chores

- **deps**: Lock file maintenance
  ([`23e82c5`](https://github.com/MountainGod2/cb-events/commit/23e82c5c7edff080423ea458c277d047c05e6c82))

### Documentation

- **config**: Update docstring to clarify attributes of EventClientConfig
  ([`678ed15`](https://github.com/MountainGod2/cb-events/commit/678ed158295048e58f342929c856d02cee24298e))

- **README**: Update usage instructions
  ([`8a67c9e`](https://github.com/MountainGod2/cb-events/commit/8a67c9e208c5cb922c63aae3dbb69d18f8675331))

### Features

- **router**: Add logging for event dispatching
  ([`47754e9`](https://github.com/MountainGod2/cb-events/commit/47754e9f5a1b0d95948da5033282f4575b79ed4a))

### Refactoring

- **constants**: Reorganize retry attributes
  ([`cd7eabb`](https://github.com/MountainGod2/cb-events/commit/cd7eabb067e80e5d1c33c3eac2bd8f6568c2417a))

### Testing

- **client**: Add tests for session management and timeout response handling
  ([`7b6b5f2`](https://github.com/MountainGod2/cb-events/commit/7b6b5f225c38c19b2768786daac244e366ffa80c))


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
  ([`8984894`](https://github.com/MountainGod2/chaturbate-events/commit/898489447b3c941767c49c45fb441d8e965c812b))

### Chores

- **pyproject**: Update organization
  ([`8c3a264`](https://github.com/MountainGod2/chaturbate-events/commit/8c3a26491ebf989a79128b75a2f473d414c355cf))

### Features

- **config**: Add example environment file for Chaturbate API credentials
  ([`c607eda`](https://github.com/MountainGod2/chaturbate-events/commit/c607eda015f0ce40bf0dbfcd381545ddf51d9f74))

### Refactoring

- **client**: Remove redundant asterisk in EventClient constructor parameters
  ([`2376cdd`](https://github.com/MountainGod2/chaturbate-events/commit/2376cdd8c557c7cffe68795c610a2a916c82d3f9))


## v1.10.0 (2025-09-26)

### Chores

- **deps**: Update dev-tools
  ([`50adc7e`](https://github.com/MountainGod2/chaturbate-events/commit/50adc7e8cc6a9c18f3efce3b3153bd8d0b321d25))

### Documentation

- Add autodoc-pydantic and settings
  ([`7972be7`](https://github.com/MountainGod2/chaturbate-events/commit/7972be7ab233aaee2a300b6faae12756c94b0d6f))

- **README**: Refactor error handling in example
  ([`867bd48`](https://github.com/MountainGod2/chaturbate-events/commit/867bd48d7bce3358aad824fc2606d14dcdd45134))

### Features

- Add Cloudflare error handling and retry tests in EventClient
  ([`4025f06`](https://github.com/MountainGod2/chaturbate-events/commit/4025f06f313c368c023e7d071de7c1a2e55ce878))

- Introduce EventClientConfig for improved configuration management
  ([`d72090f`](https://github.com/MountainGod2/chaturbate-events/commit/d72090f33489ed026437eec1b97b4129a4e3b655))

- Refactor EventClient initialization to use EventClientConfig for improved configuration management
  ([`6047035`](https://github.com/MountainGod2/chaturbate-events/commit/60470353be78730b198392a69211be9171dae6f1))

### Testing

- Add tests for EventClientConfig validation
  ([`9d2eb63`](https://github.com/MountainGod2/chaturbate-events/commit/9d2eb63408485e2ac1f0ad3fba30ee5ab92157d6))


## v1.9.0 (2025-09-24)

### Bug Fixes

- Update uv dependency to version 0.8.22 in Dockerfile
  ([`b7356c0`](https://github.com/MountainGod2/chaturbate-events/commit/b7356c023bfd6b1c555abd84c8eb8224e2a9e27d))

### Chores

- **deps**: Update dependency pytest-mock to v3.15.1
  ([`47b38c5`](https://github.com/MountainGod2/chaturbate-events/commit/47b38c5a49094f36836427a0aca0ee70511bbb4c))

- **deps**: Update pre-commit hook versions for ruff, mypy, and check-jsonschema
  ([`6f9476a`](https://github.com/MountainGod2/chaturbate-events/commit/6f9476abe3c636413b5872e38dc1cc0ddc2d9b03))

### Features

- Add Dockerfile and .dockerignore for containerization
  ([`60b691b`](https://github.com/MountainGod2/chaturbate-events/commit/60b691bfa9607e90ff2d8843ceb5804c6d89e247))

- Add python-version configuration for pyrefly tool
  ([`6abab23`](https://github.com/MountainGod2/chaturbate-events/commit/6abab23d4da331b99452265e3be044708099b875))

### Refactoring

- Enhance test coverage for Event models and EventRouter functionality
  ([`24878f1`](https://github.com/MountainGod2/chaturbate-events/commit/24878f1316d36291ed006f69a56727bdb3537182))

- Improve graceful shutdown handling in example script
  ([`df5d02f`](https://github.com/MountainGod2/chaturbate-events/commit/df5d02f766f4f708fe087ef4229442323e0a94b4))

- Move create_url_pattern function to test_client.py and remove unused import from conftest.py
  ([`32c7ab3`](https://github.com/MountainGod2/chaturbate-events/commit/32c7ab3aef339875334526b0a1d737aa51f2b59c))

- Remove is_private property from Message model
  ([`0bf2fb0`](https://github.com/MountainGod2/chaturbate-events/commit/0bf2fb07855306b6fc2f542d90ef7858664ba954))

- Update default retry attempts to 8 and adjust documentation accordingly
  ([`a878d1c`](https://github.com/MountainGod2/chaturbate-events/commit/a878d1c13a97953a1e3a19556698f6188f0c98d1))


## v1.8.0 (2025-09-22)

### Chores

- **deps**: Lock file maintenance
  ([`5a20dea`](https://github.com/MountainGod2/chaturbate-events/commit/5a20dea6cf61fba522e06b7b0654f1955a5720e0))

### Features

- Enhance EventClient with configurable retry logic for network errors
  ([`bcd4b38`](https://github.com/MountainGod2/chaturbate-events/commit/bcd4b384ee148a99abb900038e8fc0ca482d6de9))

### Refactoring

- Formatted to conform with updated line length settings
  ([`2240311`](https://github.com/MountainGod2/chaturbate-events/commit/224031147e6ca5af764f2d3ee5006b2ac7eba062))

- Improve event handling messages and clarify credential validation
  ([`05af4c6`](https://github.com/MountainGod2/chaturbate-events/commit/05af4c60fe4353f891221bd9cbbfce040f2ccac4))

- Remove obsolete Python version and funding link from pyproject.toml
  ([`b84da0a`](https://github.com/MountainGod2/chaturbate-events/commit/b84da0adf3e8327eabb9134a19965c7fe812b502))


## v1.7.0 (2025-09-20)

### Bug Fixes

- Update CI/CD workflow and Makefile to use 'make test-e2e' for end-to-end tests
  ([`f5e3379`](https://github.com/MountainGod2/chaturbate-events/commit/f5e3379e7312791d895e4f274730abd582f44404))

### Features

- Refactor EventClient and introduce constants for improved configuration and error handling
  ([`0c6576d`](https://github.com/MountainGod2/chaturbate-events/commit/0c6576d7d2b7b2b44d27687b23884cf2c4f4b72c))

### Refactoring

- Remove test_config.py
  ([`0918753`](https://github.com/MountainGod2/chaturbate-events/commit/091875360a4491641b6145f81dfdc285b9ed48ca))

- **tests**: Move e2e tests into main test module
  ([`d390688`](https://github.com/MountainGod2/chaturbate-events/commit/d390688b2c15746f54906cd99f4cd3faa2183603))

### Testing

- **lint**: Add rules for logging exceptions and hardcoded credentials in tests
  ([`e13cb6c`](https://github.com/MountainGod2/chaturbate-events/commit/e13cb6c007e3e8273e53a7b3eefea6334feed83f))


## v1.6.1 (2025-09-20)

### Bug Fixes

- **deps**: Update dependency pydantic to v2.11.9
  ([#13](https://github.com/MountainGod2/chaturbate-events/pull/13),
  [`87459bd`](https://github.com/MountainGod2/chaturbate-events/commit/87459bd6d00ff585cbd3dd63a3fc31c2ebc5c20d))

### Chores

- **deps**: Lock file maintenance
  ([`bcb49da`](https://github.com/MountainGod2/chaturbate-events/commit/bcb49da0b71f061d1111aa8e446d7bdacb11283f))

- **deps**: Update dependency mypy to v1.18.1
  ([`c3fe901`](https://github.com/MountainGod2/chaturbate-events/commit/c3fe901241590323f172e52535243baf689e5a63))

- **deps**: Update dependency pytest-asyncio to v1.2.0
  ([`56971c7`](https://github.com/MountainGod2/chaturbate-events/commit/56971c72cd63a96d320fb2e797d4977c6de77e86))

- **deps**: Update dependency python-semantic-release to v10.4.1
  ([`1f2cad7`](https://github.com/MountainGod2/chaturbate-events/commit/1f2cad7ebd0fc656ec9d1fbc8f08b2be15ddc5d6))

- **deps**: Update dependency ruff to v0.13.0
  ([`ea9f0da`](https://github.com/MountainGod2/chaturbate-events/commit/ea9f0da5ea21ff1dcd748ac79d56c9299db44153))

- **deps**: Update pre-commit hook pre-commit/mirrors-mypy to v1.18.1
  ([`b48f664`](https://github.com/MountainGod2/chaturbate-events/commit/b48f6640b861df1b7f1e81e282dc5e01ea8e2ab0))

- **docs**: Remove unused sphinx-copybutton and sphinx-design dependencies
  ([`fe12847`](https://github.com/MountainGod2/chaturbate-events/commit/fe12847d69f6f1e05fc976d210cf59c60717be1d))

### Refactoring

- **ci-cd**: Update end-to-end test command to filter by e2e marker
  ([`4f13743`](https://github.com/MountainGod2/chaturbate-events/commit/4f137433f5a0844e40b47a097fed441d6a618ad6))

- **client**: Include event types in debug output
  ([`01b9dbd`](https://github.com/MountainGod2/chaturbate-events/commit/01b9dbd187cca76962226d86f2d232c5576f7de9))

- **client**: Replace aiohttp references with specific imports and add rate limiter to polling
  ([`49fda32`](https://github.com/MountainGod2/chaturbate-events/commit/49fda328bd31843de46c85234bca37ce7fc45ad6))

- **example**: Remove unused __init__.py file from examples directory
  ([`9c58f84`](https://github.com/MountainGod2/chaturbate-events/commit/9c58f8401804a6108d174a9d1cdffe42c8123281))

- **example**: Simplify tip event handler and remove message handlers
  ([`314085e`](https://github.com/MountainGod2/chaturbate-events/commit/314085e02c75ff2e5f4b7a8746fee1556b325bc7))

- **exceptions**: Remove extra_info parameter from EventsError initialization
  ([`cacb857`](https://github.com/MountainGod2/chaturbate-events/commit/cacb8575bdda43b631c714fbf1f1522f412c7937))

- **pyproject**: Update Python classifiers and ruff linting rules, enhance pytest options
  ([`566d270`](https://github.com/MountainGod2/chaturbate-events/commit/566d270083d270d54645b65f4b4fd3e011d2b621))

- **tests**: Add missing e2e marker to test functions in test_e2e.py
  ([`2e0e41e`](https://github.com/MountainGod2/chaturbate-events/commit/2e0e41e926ac2969b853a6364e660585d0671104))

- **tests**: Remove obsolete integration test for EventClient and EventRouter
  ([`74187df`](https://github.com/MountainGod2/chaturbate-events/commit/74187dfffa02ae91e5203062e4209d51cde429ee))


## v1.6.0 (2025-09-16)

### Bug Fixes

- Reorganize imports for consistency across test files
  ([`f0fd75c`](https://github.com/MountainGod2/chaturbate-events/commit/f0fd75c11b7e9f666e48bf20ed180901dfa0ee86))

- **docs**: Update deployment environment name to match GitHub Pages convention
  ([`c3709c6`](https://github.com/MountainGod2/chaturbate-events/commit/c3709c69355f2bdcadb29fcc5e15ec3cfd8028b0))

### Chores

- Remove obsolete documentation workflow
  ([`b44b425`](https://github.com/MountainGod2/chaturbate-events/commit/b44b4258fbc3c5bd01fb915e08ebd26939af055a))

- **deps**: Update astral-sh/setup-uv digest to b75a909
  ([`cc10b6d`](https://github.com/MountainGod2/chaturbate-events/commit/cc10b6d70864d9eab33fa9f0d8ccdfc0d886b94e))

- **deps**: Update dependency pytest-cov to v6.3.0
  ([`81696dc`](https://github.com/MountainGod2/chaturbate-events/commit/81696dcec549e99fdc4e62dff183afea89916488))

- **deps**: Update dependency pytest-cov to v7
  ([#10](https://github.com/MountainGod2/chaturbate-events/pull/10),
  [`96be89f`](https://github.com/MountainGod2/chaturbate-events/commit/96be89fa75f0179e57832f8a6366258beeb24100))

- **deps**: Update dependency python-semantic-release to v10.3.2
  ([`06a7995`](https://github.com/MountainGod2/chaturbate-events/commit/06a79950012963f417fd2c8d38b20911cd8f9aec))

- **deps**: Update dependency python-semantic-release to v10.4.0
  ([`4ae3c90`](https://github.com/MountainGod2/chaturbate-events/commit/4ae3c90234eca1ed0cd51472087b388e803c7f1b))

- **gitignore**: Expanded ignored files
  ([`5e09024`](https://github.com/MountainGod2/chaturbate-events/commit/5e09024e166525c3fe66b1b368495f3b17813c7b))

### Features

- **docs**: Added sphinx auto-doc pipeline
  ([`da2ddf4`](https://github.com/MountainGod2/chaturbate-events/commit/da2ddf4f7677377503a153cc988fdf26754c5464))

### Refactoring

- **client**: Simplify error handling in nextUrl extraction
  ([`06887e4`](https://github.com/MountainGod2/chaturbate-events/commit/06887e4f47b98d54c3ec30a6e96ef034b2b9abbf))

- **exceptions**: Simplify exception class documentation and imports
  ([`76653d7`](https://github.com/MountainGod2/chaturbate-events/commit/76653d7276a5be54fc64ad3d9dc550cc6b070d77))

- **tests**: Improve test function names and remove unused tests
  ([`81ca969`](https://github.com/MountainGod2/chaturbate-events/commit/81ca969717110a90462302261c3b47b252f18fd7))


## v1.5.0 (2025-09-13)

### Features

- **pyproject**: Update project metadata with additional keywords and URLs
  ([`daa2dbb`](https://github.com/MountainGod2/chaturbate-events/commit/daa2dbb33a6309994bb9c830b0a2928745561971))


## v1.4.1 (2025-09-13)

### Bug Fixes

- **pyproject**: Add additional classifiers for improved package metadata
  ([`2cebae1`](https://github.com/MountainGod2/chaturbate-events/commit/2cebae14f1ce754727c2f2ce701831b826d337e6))


## v1.4.0 (2025-09-13)

### Chores

- **deps**: Update dependency pyright to v1.1.405
  ([`9c31fff`](https://github.com/MountainGod2/chaturbate-events/commit/9c31fff16ed6f416e1414effdfc5d87608a24317))

- **deps**: Update dependency pytest-mock to v3.15.0
  ([`d6e8016`](https://github.com/MountainGod2/chaturbate-events/commit/d6e80163e00f43849d295afd50517c3fe5751572))

- **deps**: Update dependency ruff to v0.12.11
  ([`645e8ca`](https://github.com/MountainGod2/chaturbate-events/commit/645e8ca74f9f6f1057b6987f07199166773cf774))

- **deps**: Update dev-tools
  ([`651dc2e`](https://github.com/MountainGod2/chaturbate-events/commit/651dc2eb2b4c47e4879f2beb29c4640ed898e52c))

### Documentation

- **README**: Add environment variable setup and error handling sections
  ([`45d5b79`](https://github.com/MountainGod2/chaturbate-events/commit/45d5b79dc60c6041feb858580634e8ade0354e3d))

### Features

- **pyproject**: Add classifiers and project URLs for better package metadata
  ([`fed8e20`](https://github.com/MountainGod2/chaturbate-events/commit/fed8e20a2104c802eaf11b8399e4dbc064e7d18f))

### Refactoring

- **ci-cd**: Update runner version from ubuntu-latest to ubuntu-24.04
  ([`ae30cf3`](https://github.com/MountainGod2/chaturbate-events/commit/ae30cf3409ccdc125decc99c36056bee3461b18e))

- **tests**: Split and reorganize test cases
  ([`7776d0d`](https://github.com/MountainGod2/chaturbate-events/commit/7776d0d12b0a3f10990aea352611a5b084a33a76))


## v1.3.2 (2025-09-11)

### Bug Fixes

- **renovate**: Update minimum release age from 14 days to 7 days
  ([`7923a7d`](https://github.com/MountainGod2/chaturbate-events/commit/7923a7d956a12a982311d50d06efc8b1dae67887))

### Chores

- **deps**: Remove outdated 'ty' dependency from development requirements
  ([`2ca470a`](https://github.com/MountainGod2/chaturbate-events/commit/2ca470a5918339fdbfeac476715bba090a1aec68))

- **deps**: Remove outdated dependency from dev requirements
  ([`2b69943`](https://github.com/MountainGod2/chaturbate-events/commit/2b699437e22e818b4be500656d3c0e7d01eeb694))

- **deps**: Update dependency aioresponses to v0.7.8
  ([`46c64a8`](https://github.com/MountainGod2/chaturbate-events/commit/46c64a8b8f5c164eb687c5143e3f23bafcb526e9))

- **instructions**: Remove trailing whitespace in custom exceptions guideline
  ([`9d597ec`](https://github.com/MountainGod2/chaturbate-events/commit/9d597ece666e1ca5111dda2290764e4cf8fe821f))

- **pre-commit**: Update configuration and add new hooks for additional checks
  ([`9f3b181`](https://github.com/MountainGod2/chaturbate-events/commit/9f3b18174161ad2c7615afe03db6cab8581e1866))

- **pyproject**: Add Bandit configuration to exclude directories and skip specific checks
  ([`4d6a7d8`](https://github.com/MountainGod2/chaturbate-events/commit/4d6a7d811e48e775ba0f9ebdab25b05bfa3054ac))

### Refactoring

- **.gitignore**: Refine IDE settings and ensure ruff cache is ignored
  ([`89faec8`](https://github.com/MountainGod2/chaturbate-events/commit/89faec83d27bd1c9e28f9ffdb43c0bba3b980791))

- **extensions**: Add newline at end of file
  ([`ff6c9e6`](https://github.com/MountainGod2/chaturbate-events/commit/ff6c9e61218118f229c52c8ed1dbeb303864328c))

- **Makefile**: Enhance organization and improve help output
  ([`4b32f94`](https://github.com/MountainGod2/chaturbate-events/commit/4b32f94d446abcb4695483c09153830c99498723))

- **renovate**: Add 'pyright' to dev tools package grouping
  ([`e71957a`](https://github.com/MountainGod2/chaturbate-events/commit/e71957a9ee8faf04b1e60affad83a56ec4aa220d))

- **renovate**: Update schedule and descriptions in package rules
  ([`eb40292`](https://github.com/MountainGod2/chaturbate-events/commit/eb4029287ab5486c01543ea847c0d0c1dbe0ca3e))

- **verify_upstream**: Ensure newline at end of file
  ([`b84df2b`](https://github.com/MountainGod2/chaturbate-events/commit/b84df2bd8aa22bf7a124929965f3ad994a0efc77))


## v1.3.1 (2025-09-09)

### Bug Fixes

- **client**: Correct syntax for aiohttp.ClientSession and logging error message
  ([`62b92d7`](https://github.com/MountainGod2/chaturbate-events/commit/62b92d75cb4de11c9d85c13705a8520929dbb6fb))

- **example**: Add type hints to event handler functions
  ([`0429c45`](https://github.com/MountainGod2/chaturbate-events/commit/0429c451b94747f4bb331092a9651264c2a5d868))

### Documentation

- **README**: Add license section to README.md
  ([`849421c`](https://github.com/MountainGod2/chaturbate-events/commit/849421c3cecac3bdd4112706790cd37b4c43f3df))

### Refactoring

- **dependencies**: Add aioresponses to development dependencies
  ([`de28201`](https://github.com/MountainGod2/chaturbate-events/commit/de28201cd0a0b43186073de0188accb52658fcde))

- **lint**: Expand per-file ignores for test files
  ([`16cca90`](https://github.com/MountainGod2/chaturbate-events/commit/16cca9074daf0416719648f87e95caf8e83ddb90))

- **pyproject**: Clean up lint ignore rules and remove unnecessary mypy override
  ([`ba15efb`](https://github.com/MountainGod2/chaturbate-events/commit/ba15efb85d98eef31a2bd5cb0fb56902d808ecc9))

- **tests**: Add tests for additional scenarios
  ([`b11ff73`](https://github.com/MountainGod2/chaturbate-events/commit/b11ff735d3b4dabc2ac7be429938ce05fc1db1c4))

- **tests**: Correct URL pattern usage in client error handling test
  ([`c1ba9f2`](https://github.com/MountainGod2/chaturbate-events/commit/c1ba9f2e2b4b8e691443ed2f4e11745232866061))

- **tests**: Improve readability by formatting function parameters and return values
  ([`5e44f83`](https://github.com/MountainGod2/chaturbate-events/commit/5e44f83ec33f2c554079f9f3f9a14a5b133365ff))

- **tests**: Remove noqa comments from assertions in test_router_registration
  ([`4e1f4b3`](https://github.com/MountainGod2/chaturbate-events/commit/4e1f4b35613930fc221133645ffbc8303c4a1bb8))

### Testing

- Consolidate and refactor tests to use aioresponses
  ([`16cd577`](https://github.com/MountainGod2/chaturbate-events/commit/16cd5778245d1ee19ee98f51ad9082498054cc5f))

- Reformat parameterized test cases for improved readability
  ([`5c89365`](https://github.com/MountainGod2/chaturbate-events/commit/5c89365b12f4a9d4bf7295166662f113900adb74))

- **conftest**: Update mock_http_get to use aioresponses for HTTP interactions
  ([`f679c76`](https://github.com/MountainGod2/chaturbate-events/commit/f679c76d06b4978c05baddd9fb6417fec290738e))


## v1.3.0 (2025-09-09)

### Features

- **vscode**: Add extensions.json for recommended VS Code extensions
  ([`80ae65c`](https://github.com/MountainGod2/chaturbate-events/commit/80ae65c166bf06cc7de40d89c35cc5bc4bbb84b5))

### Refactoring

- **example**: Simplify example file
  ([`124472b`](https://github.com/MountainGod2/chaturbate-events/commit/124472b14e0bf030d4124446aa08886804b344f7))

- **lint**: Streamline per-file ignores for examples and tests, add Pyright overrides
  ([`3f45237`](https://github.com/MountainGod2/chaturbate-events/commit/3f452370151ca747e593061fba113851b14e4f39))

- **tests**: Enhance type hints and docstrings in test fixtures and functions
  ([`e8fe2f2`](https://github.com/MountainGod2/chaturbate-events/commit/e8fe2f20f29b3e2e7db0f8f01be529381534d619))


## v1.2.0 (2025-09-07)

### Bug Fixes

- **example**: Add credential validation in main function
  ([`a387849`](https://github.com/MountainGod2/chaturbate-events/commit/a38784920d232d5a948206b504695f710b3b1a60))

### Chores

- **deps**: Lock file maintenance
  ([`6b66eeb`](https://github.com/MountainGod2/chaturbate-events/commit/6b66eeb57763ddb9127a7f4776b1bde6b27b3f2f))

- **deps**: Update codecov/codecov-action digest to 5a10915
  ([#9](https://github.com/MountainGod2/chaturbate-events/pull/9),
  [`c03cfda`](https://github.com/MountainGod2/chaturbate-events/commit/c03cfdacce18e8a072ef2aa57299349da7d15295))

- **deps**: Update setup-uv action version
  ([`7606372`](https://github.com/MountainGod2/chaturbate-events/commit/760637203649cbd68fb5b6be2794b691c4dc628e))

- **docs**: Refactor README.md layout
  ([`9d022c3`](https://github.com/MountainGod2/chaturbate-events/commit/9d022c31026f8fd83efc9b3f04c321fbe0d0a16d))

- **workflows**: Remove legacy CI and CD workflow files
  ([`c65dc18`](https://github.com/MountainGod2/chaturbate-events/commit/c65dc18c800e4cadd1815ac76c68a9fe9e520a9c))

### Documentation

- Consolidate and update Copilot instructions
  ([`d585411`](https://github.com/MountainGod2/chaturbate-events/commit/d58541153c680794955c62f52fd0567d15e27b0a))

### Features

- **client**: Enhance error logging and handling for authentication and JSON response
  ([`4725aab`](https://github.com/MountainGod2/chaturbate-events/commit/4725aab592d7bbedd24b8094c511258cd0390ff0))

### Refactoring

- **client**: Improve session initialization for EventClient
  ([`3859630`](https://github.com/MountainGod2/chaturbate-events/commit/38596302110385ff40e55b3b349d740cba4d3cb1))

- **exceptions**: Enhance EventsError class with detailed attributes and representation
  ([`59001ac`](https://github.com/MountainGod2/chaturbate-events/commit/59001acb1c94f02673c40acca56f268229a56ce2))

- **renovate**: Update description to include digest updates for automerge
  ([`ec19380`](https://github.com/MountainGod2/chaturbate-events/commit/ec193802e384f32602bf6783867214c7a42e9d77))

- **router**: Simplify event handler type definitions
  ([`ec5f4ba`](https://github.com/MountainGod2/chaturbate-events/commit/ec5f4baf77038d6683cfa7a3c4cfd0c85ff7b457))

### Testing

- **e2e**: Update end-to-end tests for EventClient functionality and validation
  ([`c3f009f`](https://github.com/MountainGod2/chaturbate-events/commit/c3f009fc8e5779c4767e5ddd1a41658e7cf2d061))


## v1.1.4 (2025-09-04)

### Bug Fixes

- **lint**: Add new ignore patterns for examples and tests
  ([`0efaa4f`](https://github.com/MountainGod2/chaturbate-events/commit/0efaa4fd5db80e758d0f626a725827cf685ed188))

### Chores

- **deps**: Update dependency chaturbate-events to v1.1.3
  ([`d093519`](https://github.com/MountainGod2/chaturbate-events/commit/d093519834eab7afc8c4821eb616119bb81eaee5))

### Refactoring

- **ci**: Improve job naming conventions
  ([`124fd8d`](https://github.com/MountainGod2/chaturbate-events/commit/124fd8d5d36a4f4b08474d8b8132138120cb3461))

- **ci**: Update uv cache references in workflow
  ([`14e1935`](https://github.com/MountainGod2/chaturbate-events/commit/14e19352fb8fae9639aaafa3606f7553d3485157))

- **docs**: Update docstrings across modules
  ([`339299b`](https://github.com/MountainGod2/chaturbate-events/commit/339299bc6fd2edb9c814f139f5ee5195842e6b0e))

- **example**: Remove imports and use standard library tools instead
  ([`7e28d36`](https://github.com/MountainGod2/chaturbate-events/commit/7e28d365afe254941cfadfe24c08200b5a543ef0))


## v1.1.3 (2025-09-04)

### Bug Fixes

- **ci**: Ensure 'build' job is a dependency for 'deploy to PyPI'
  ([`0aa98c5`](https://github.com/MountainGod2/chaturbate-events/commit/0aa98c5eba68bca31763c017f3ba6452a5db53e6))


## v1.1.2 (2025-09-04)

### Bug Fixes

- **ci**: Enhance CI/CD workflow structure and naming conventions
  ([`177c65b`](https://github.com/MountainGod2/chaturbate-events/commit/177c65b35630b3ae377e9eb43dc969e56d8bb2e7))


## v1.1.1 (2025-09-04)

### Bug Fixes

- **ci**: Update artifact download path for PyPI publishing
  ([`330c1ba`](https://github.com/MountainGod2/chaturbate-events/commit/330c1ba9af1f52d29c2cc16ab80b77ba8813dd4d))


## v1.1.0 (2025-09-04)

### Chores

- **ci**: Enhance lint-and-test workflow with permissions and step clarifications
  ([`c32be1f`](https://github.com/MountainGod2/chaturbate-events/commit/c32be1fd7a90e9c37b25098703f2963199b4f868))

- **ci**: Merge CI and CD workflows into a single file
  ([`bb9f5bf`](https://github.com/MountainGod2/chaturbate-events/commit/bb9f5bf9045719890b9573f55ba71b0620311a0f))

- **ci**: Update workflow name
  ([`1bfdfff`](https://github.com/MountainGod2/chaturbate-events/commit/1bfdfff90ad4c58c83b18890130b2ee5bf05b57b))

- **deps**: Lock file maintenance
  ([`bfbbc02`](https://github.com/MountainGod2/chaturbate-events/commit/bfbbc024de4bd4d7a3d696d9ebf69954803b7d7e))

- **deps**: Lock file maintenance
  ([`9d6b7f8`](https://github.com/MountainGod2/chaturbate-events/commit/9d6b7f86495d9938dd0a9e6d8938313bfad23b47))

- **deps**: Pin codecov/codecov-action action to b9fd7d1
  ([#5](https://github.com/MountainGod2/chaturbate-events/pull/5),
  [`db0c723`](https://github.com/MountainGod2/chaturbate-events/commit/db0c7230c423bd56185383d5f434f59fea8e7d1e))

- **deps**: Update astral-sh/setup-uv digest to 557e51d
  ([#7](https://github.com/MountainGod2/chaturbate-events/pull/7),
  [`e02df5d`](https://github.com/MountainGod2/chaturbate-events/commit/e02df5d09416d2afa473f2c0738c35df1bbfd686))

- **deps**: Update codecov/codecov-action action to v5
  ([#6](https://github.com/MountainGod2/chaturbate-events/pull/6),
  [`9b93cf5`](https://github.com/MountainGod2/chaturbate-events/commit/9b93cf5831f36807274b03c1492596467e769d9a))

- **deps**: Update dependency chaturbate-events to v1.0.3
  ([`e3e5047`](https://github.com/MountainGod2/chaturbate-events/commit/e3e50478d2f46e8d0b4c9b7c9a1b60e4b5f4528e))

- **examples**: Update example.py dependencies
  ([`34eee53`](https://github.com/MountainGod2/chaturbate-events/commit/34eee53afed2a59a8fb654df732167f61620174e))

- **pyproject**: Update fancy-pypi-readme substitutions to use correct pattern and replacement
  ([`f4ad9a2`](https://github.com/MountainGod2/chaturbate-events/commit/f4ad9a25aec3f6a44eb92f324a7e68e90ec009a9))

- **renovate**: Add ignorePaths for dependency management
  ([`ae17812`](https://github.com/MountainGod2/chaturbate-events/commit/ae178128a6dae6ea86a86e76c8dc9be2878738e8))

- **renovate**: Enable pep723 manager for dependency management
  ([`06e5a6f`](https://github.com/MountainGod2/chaturbate-events/commit/06e5a6fd919cac02264367ef38ee895ece52ca55))

- **renovate**: Refine configuration and update package rules
  ([`2a7b4cb`](https://github.com/MountainGod2/chaturbate-events/commit/2a7b4cbdb2b01a39f10dcce46a3e685fcfea3019))

- **renovate**: Update managerFilePatterns for pep723 to use regex format
  ([`2fe9c26`](https://github.com/MountainGod2/chaturbate-events/commit/2fe9c26e65cd7cc7d544c6be6976d6fcd3aae79a))

- **renovate**: Update pep723 configuration to use fileMatch instead of managerFilePatterns
  ([`c445e68`](https://github.com/MountainGod2/chaturbate-events/commit/c445e680937fc930e073d2079514a40906759313))

- **renovate**: Update pep723 configuration to use managerFilePatterns for Python files
  ([`b544a90`](https://github.com/MountainGod2/chaturbate-events/commit/b544a909ec6a6a3c2f56b8edec1b19f1bdd78461))

### Features

- **client**: Enhance logging and token masking in EventClient
  ([`ba225ed`](https://github.com/MountainGod2/chaturbate-events/commit/ba225ed41c5fb80617a8371d2d499c8a1a6d8d49))

### Refactoring

- **ci**: Update naming throughout CI/CD workflow
  ([`d56f5af`](https://github.com/MountainGod2/chaturbate-events/commit/d56f5af20bb7c3d501d8f3120703aca9a2b3c695))


## v1.0.3 (2025-08-27)

### Bug Fixes

- **renovate**: Format schedule and managerFilePatterns for consistency
  ([`33568cd`](https://github.com/MountainGod2/chaturbate-events/commit/33568cdb94486ed5347b900dabde08759ab92dea))

### Build System

- **cd**: Ensure build job runs only on successful workflow completion
  ([`68f5f97`](https://github.com/MountainGod2/chaturbate-events/commit/68f5f970512db0aacd1d12bdab91ffe3be8f5604))

### Chores

- **deps**: Lock file maintenance
  ([`d9bff53`](https://github.com/MountainGod2/chaturbate-events/commit/d9bff53b27da3cf468f370274f509aab7586cee9))

- **deps**: Update actions/checkout action to v5
  ([#3](https://github.com/MountainGod2/chaturbate-events/pull/3),
  [`2184e34`](https://github.com/MountainGod2/chaturbate-events/commit/2184e34719474b25f9f8fe2ee298c65de2850910))

- **deps**: Update dependency ruff to v0.12.10
  ([`3cbadc1`](https://github.com/MountainGod2/chaturbate-events/commit/3cbadc1e4684ec659c8ce08ef11824665cb95b28))

- **deps**: Update pre-commit hook astral-sh/ruff-pre-commit to v0.12.10
  ([`e781044`](https://github.com/MountainGod2/chaturbate-events/commit/e78104464cdc3fb8c4a3ebcae2295eb150ac3669))

### Refactoring

- **renovate**: Update merge schedule
  ([`3126de1`](https://github.com/MountainGod2/chaturbate-events/commit/3126de1ec91aa87ae8653ffe0471b5e6139607b2))


## v1.0.2 (2025-08-27)

### Bug Fixes

- **example**: Add mypy override to ignore errors in example module
  ([`c74cc44`](https://github.com/MountainGod2/chaturbate-events/commit/c74cc44b72f47aadce21f479bce4d1bf215da477))


## v1.0.1 (2025-08-27)

### Bug Fixes

- **example**: Replace logging with print statements and add PEP 723 inline deps
  ([`ab90396`](https://github.com/MountainGod2/chaturbate-events/commit/ab90396aa5a3f16b9ded5511f7b4f243fcb25949))

### Chores

- **renovate**: Update minimum release age to 4 days
  ([`2e97d19`](https://github.com/MountainGod2/chaturbate-events/commit/2e97d198aa7f6d8485b7403e571efa22b2823e2c))

### Refactoring

- **pyproject**: Remove unused examples dependency and update lint ignores
  ([`e8e8ae4`](https://github.com/MountainGod2/chaturbate-events/commit/e8e8ae4b60f91a844a7651c07c0e234a68add8d1))

- **router**: Improve type annotations and enhance handler registration logic
  ([`37a61bf`](https://github.com/MountainGod2/chaturbate-events/commit/37a61bfe132b6b2fd2654b3b270408faded31f89))


## v1.0.0 (2025-08-26)

- Initial Release
