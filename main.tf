terraform {
  required_version = ">= 1.0.0"

  required_providers {
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = ">= 1.14.0"
    }
  }
}

provider "kubectl" {
  config_path = "~/.kube/config"
}

module "kerberos_local_dev" {
  source = "./terraform/environments/dev"
}
