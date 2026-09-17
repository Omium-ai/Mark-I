resource "random_password" "db" {
  for_each = toset(["controld_app", "adjudicator_app", "intel_app", "mark1_federation_worker"])
  length   = 32
  special  = false
}

resource "random_password" "clickhouse" {
  for_each = toset(["ingest", "query", "offboard", "ddl"])
  length   = 32
  special  = false
}

resource "random_bytes" "seed" {
  for_each = toset(["device_token_seed", "server_chain_seed", "bundle_section_seed", "pepper"])
  length   = 32
}

resource "random_password" "service_token" {
  length  = 48
  special = false
}

locals {
  secrets = {
    "mark1-db-service-credentials" = { for k, v in random_password.db : k => v.result }
    "mark1-clickhouse" = merge(
      { for k, v in random_password.clickhouse : "${k}_password" => v.result },
      { for k, v in random_password.clickhouse : "${k}_sha256" => sha256(v.result) },
      { host = var.clickhouse_host, port = "9000" },
    )
    "mark1-signing-seeds" = {
      device_token_seed   = random_bytes.seed["device_token_seed"].hex
      server_chain_seed   = random_bytes.seed["server_chain_seed"].hex
      bundle_section_seed = random_bytes.seed["bundle_section_seed"].hex
    }
    "mark1-hmac-pepper"   = { pepper = random_bytes.seed["pepper"].hex }
    "mark1-service-token" = { token = random_password.service_token.result }
  }
}

resource "aws_secretsmanager_secret" "mark1" {
  for_each = local.secrets
  name     = "omium/prod/${each.key}"

  tags = {
    Service = "secrets"
    Purpose = "Mark 1 secret ${each.key} - synced into omium-mark1 by External Secrets - contents owned by whoever last rotated them"
  }
}

resource "aws_secretsmanager_secret_version" "mark1" {
  for_each      = local.secrets
  secret_id     = aws_secretsmanager_secret.mark1[each.key].id
  secret_string = jsonencode(each.value)

  lifecycle {
    ignore_changes = [secret_string]
  }
}
