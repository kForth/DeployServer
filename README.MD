This is a simple server to run pre-configured commands when a github webhook is received.

Sample config.json:
```json
{
  "kestin": {
    "github-secret":  "SomethingSecretHopefully",
    "folder-path":    "/var/www/Kestin",
    "command":        "git pull"
  },
  "clooney": {
    "github-secret":  "SomethingElseSecretHopefully",
    "folder-path":    "/var/www/Clooney",
    "command":        ["git pull", "echo Done!"]
  }
}
```