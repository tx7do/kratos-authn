APP_VERSION=v0.0.4

.PHONY: tag
tag:
	git tag -f $(APP_VERSION) && git tag -f engine/presharedkey/$(APP_VERSION) && git tag -f engine/noop/$(APP_VERSION) && git tag -f engine/oidc/$(APP_VERSION) && git tag -f engine/jwt/$(APP_VERSION) && git tag -f authn/$(APP_VERSION) && git push --tags --force
