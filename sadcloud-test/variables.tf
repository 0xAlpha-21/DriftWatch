variable "enable_vulnerabilities" {
  description = "Toggle to true to simulate configuration drift, or false to enforce secure baseline."
  type        = bool
  default     = false
}