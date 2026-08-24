# Modifications copyright 2026 Forward Research. Apache-2.0.

from ragger.conftest import configuration

TEST_SEED = (
    "glory promote mansion idle axis finger extra february uncover one trip "
    "resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
)

configuration.OPTIONAL.APP_NAME = "Permaweb"
configuration.OPTIONAL.CUSTOM_SEED = TEST_SEED

pytest_plugins = ("ragger.conftest.base_conftest",)
