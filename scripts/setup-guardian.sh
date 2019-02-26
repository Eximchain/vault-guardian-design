#!/bin/bash

set -eu pipefail

PLUGIN_CONFIG_PATH="/etc/vault/config.d/plugins.hcl"
PLUGIN_PATH="../plugin/ethereum"

cd $PLUGIN_PATH

