job "pkgdash-web" {
  # Define the target datacenter(s) for this job
  datacenters = ["dc1"]
  type        = "service"

  # Rolling update strategy
  update {
    max_parallel      = 1
    min_healthy_time  = "10s"
    healthy_deadline  = "3m"
    progress_deadline = "10m"
    auto_revert       = true
  }

  group "web" {
    # Number of application instances (containers) to run
    count = 1

    # Graceful shutdown delay to allow proxy/load balancer deregistration
    shutdown_delay = "15s"

    # Restart policy for task failures
    restart {
      attempts = 2
      interval = "30m"
      delay    = "15s"
      mode     = "fail"
    }

    network {
      # Map an external port to the internal container port 8080
      port "http" {
        to = 8080
      }
    }

    # Service registration for Consul or Nomad service discovery
    service {
      name     = "pkgdash-web"
      port     = "http"
      provider = "nomad" # Set to "consul" if using HashiCorp Consul

      # Optional Traefik reverse proxy configuration (uncomment to enable)
      # tags = [
      #   "traefik.enable=true",
      #   "traefik.http.routers.pkgdash-web.entrypoints=https",
      #   "traefik.http.routers.pkgdash-web.rule=Host(`pkgdash-web.example.com`)",
      # ]

      # Health check configuration
      check {
        name     = "pkgdash-web HTTP Check"
        type     = "http"
        path     = "/"
        interval = "10s"
        timeout  = "2s"
      }
    }

    task "pkgdash-web" {
      # Run the application inside a Docker container
      driver = "docker"

      config {
        # Target the image built by your GitHub Actions workflow
        image = "ghcr.io/chrisvanmeer/pkgdash-web:latest"

        # Ensure Nomad always pulls the latest image tag upon deployment/restart
        force_pull = true

        ports = ["http"]
      }

      # --- Option A: Static Environment Variables + Nomad Variables (Default) ---
      env {
        PKGDASH_WEB_PORT = ":8080"
        TZ               = "Europe/Amsterdam"
        PKGDASH_SERVERS  = "https://pkgdashd.internal.domain:9876"
      }

      template {
        data        = <<EOH
{{- with nomadVar "nomad/jobs/pkgdash-web" -}}
PKGDASH_PSK="{{ .psk }}"
{{- end -}}
EOH
        destination = "secrets/env"
        env         = true
      }

      # --- Option B: Vault Integration via Workload Identity ---
      # Uncomment the vault stanza and template block below if pulling all environment variables and secrets directly from Vault KV v2:
      #
      # vault {
      #   role = "pkgdash-web" # Vault role configured for Nomad Workload Identity / JWT auth
      # }
      #
      # template {
      #   data        = <<EOH
      # {{- with secret "secret/data/pkgdash-web" -}}
      # PKGDASH_WEB_PORT="{{ .Data.data.PKGDASH_WEB_PORT }}"
      # TZ="{{ .Data.data.TZ }}"
      # PKGDASH_SERVERS="{{ .Data.data.PKGDASH_SERVERS }}"
      # PKGDASH_PSK="{{ .Data.data.PKGDASH_PSK }}"
      # {{- end -}}
      # EOH
      #   destination = "secrets/env"
      #   env         = true
      # }

      # Resource allocation
      resources {
        cpu    = 100 # MHz limit
        memory = 64  # Memory limit in MB
      }
    }
  }
}
