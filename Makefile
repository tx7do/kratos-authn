APP_VERSION=v0.0.1

PACKAGE_LIST = engine/presharedkey/ engine/noop/ engine/oidc/ engine/jwt/ authn/

.PHONY: tag
tag:
	git tag -f $(APP_VERSION) && $(foreach item, $(PACKAGE_LIST), git tag -f $(item)$(APP_VERSION) && ) git push --tags --force
