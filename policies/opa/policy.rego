package seim_ai

default allow = false

deny[msg] {
  not startswith(input.meta.inventory, "inventories/lab")
  msg := "inventory not in allowed scope"
}

allow {
  input.meta.severity != "high"
  input.meta.check_mode == true
}

allow {
  input.meta.severity == "high"
  input.meta.cab_approved == true
  input.meta.dual_control == true
}
