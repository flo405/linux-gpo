package status

import (
  "encoding/json"
  "os"
  "time"
)

type Status struct {
  LastApply string `json:"lastApply"`
  Result    string `json:"result"`
  Changed   int    `json:"changed"`
  Failed    int    `json:"failed"`
  Commit    string `json:"commit"`
}

func Write(path string, s Status) error {
  if s.LastApply == "" { s.LastApply = time.Now().UTC().Format(time.RFC3339) }
  b, _ := json.MarshalIndent(s, "", "  ")
  return os.WriteFile(path, b, 0o644)
}

func Read(path string) (Status, error) {
  var s Status
  b, err := os.ReadFile(path)
  if err != nil { return s, err }
  err = json.Unmarshal(b, &s)
  return s, err
}
