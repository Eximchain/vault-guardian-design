path "auth/okta/users/*" {
    capabilities = ["read", "create"]
}

path "auth/token/lookup" {
    capabilities = ["read"]
}

path "keys" {
    capabilities = ["read", "create"]
}