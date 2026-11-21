# One kernel argument per record. Retain only the entry and its operation.
NR == 1 {
  name = $0
  sub(/^.*\//, "", name)
  if (name ~ /^(node|nodejs)$/) { node = 1; next }
  if (name ~ /^(sh|dash|bash|zsh)$/) next
}
!entry {
  if (node && !options_done) {
    if ($0 ~ /^(--no-warnings|--enable-source-maps|--trace-warnings)$/) next
    if ($0 == "--") { options_done = 1; next }
  }
  if ($0 == "" || $0 ~ /^-/ || $0 ~ /[[:cntrl:]]/ || index($0, ENVIRON["PAIR_PREFIX"]) == 1) exit
  entry = $0
  name = entry
  sub(/^.*\//, "", name)
  next
}
{ args[++count] = $0; if (count == 2) exit }
END {
  if (name ~ /^agent-bot([.]mjs)?$/ && args[1] ~ /^(daemon|broker)$/ && args[2] == "run") print entry, args[1], "run"
  if (name ~ /^agent-comms([.]mjs)?$/ && args[1] == "broker" && args[2] == "run") print entry, "broker run"
  if (name ~ /^(agent-daemon[.]mjs|agent-comms-broker)$/ && args[1] == "run") print entry, "run"
  if (name ~ /^(agent-comms-broker|owner-supervised-broker[.]mjs)$/ && entry && !count) print entry
}
