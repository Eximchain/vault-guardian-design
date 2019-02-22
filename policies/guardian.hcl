path "auth/okta/users/*" {
    capabilities = ["read", "create"]
}

path "keys" {
    capabilities = ["read", "create"]
}