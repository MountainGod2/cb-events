# CHANGELOG

<!-- version list -->

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
