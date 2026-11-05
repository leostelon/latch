#!/usr/bin/env python3
"""Validate narrowly scoped signing entitlements against both supplied profiles."""

import datetime
import pathlib
import plistlib
import sys


def prepare(profile_path, template_path, bundle_id):
    with open(profile_path, "rb") as source:
        profile = plistlib.load(source)
    expiry = profile.get("ExpirationDate")
    if expiry and expiry < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        raise ValueError(f"Provisioning profile for {bundle_id} has expired.")
    allowed = profile.get("Entitlements", {})
    teams = profile.get("TeamIdentifier", [])
    if len(teams) != 1:
        raise ValueError(f"Expected one signing team for {bundle_id}.")
    team = teams[0]
    identifier_key = "com.apple.application-identifier"
    actual_identifier = allowed.get(identifier_key)
    if actual_identifier is None:
        identifier_key = "application-identifier"
        actual_identifier = allowed.get(identifier_key)
    prefixes = profile.get("ApplicationIdentifierPrefix", [team])
    valid_identifiers = [prefix + "." + bundle_id for prefix in prefixes]
    if actual_identifier not in valid_identifiers:
        raise ValueError(f"Use an explicit profile for {bundle_id}; wildcard or mismatched App IDs are not supported.")
    if allowed.get("com.apple.developer.team-identifier") != team:
        raise ValueError(f"Team identifier mismatch for {bundle_id}.")
    with open(template_path, "rb") as source:
        entitlements = plistlib.load(source)
    for key, desired in entitlements.items():
        if key.startswith("com.apple.security."):
            continue  # Sandbox entitlements are not profile-granted capabilities.
        permitted = allowed.get(key)
        if isinstance(desired, list):
            if not isinstance(permitted, list) or not set(desired).issubset(permitted):
                raise ValueError(f"Profile for {bundle_id} does not grant {key}: {desired}.")
        elif permitted != desired:
            raise ValueError(f"Profile for {bundle_id} does not grant {key}.")
    entitlements[identifier_key] = actual_identifier
    entitlements["com.apple.developer.team-identifier"] = team
    return team, entitlements


def main():
    if len(sys.argv) != 4:
        raise ValueError("Usage: signing-entitlements.py APP_PROFILE FILTER_PROFILE OUTPUT_DIR")
    app_team, app = prepare(sys.argv[1], "Packaging/App.entitlements", "dev.ensurevpn.app")
    filter_team, extension = prepare(sys.argv[2], "Packaging/Filter.entitlements", "dev.ensurevpn.app.filter")
    if app_team != filter_team:
        raise ValueError("App and extension must be signed by the same team.")
    output = pathlib.Path(sys.argv[3])
    for filename, value in [("App.entitlements", app), ("Filter.entitlements", extension)]:
        with (output / filename).open("wb") as destination:
            plistlib.dump(value, destination)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, plistlib.InvalidFileException) as error:
        sys.exit(str(error))
