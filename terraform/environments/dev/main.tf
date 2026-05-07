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

data "kubectl_path_documents" "manifests" {
    pattern = "${path.module}/../../../k8s/base/*.yaml"
}

resource "kubectl_manifest" "apply_manifests" {
    for_each  = toset(data.kubectl_path_documents.manifests.documents)
    yaml_body = each.value
    wait_for_rollout = false
}
