This is a simple server to run pre-configured commands when a github webhook is received.

It currently doesn't verify the request beyond checking the UserAgent, but if you provide a secret for the webhook it will eventually verify it.

Sample config.json:
```json
{
  "kestin": {
    "github-secret":  "SomethingSecretHopefully",
    "folder-path":    "/var/www/Kestin",
    "command":        "git pull"
  },
  "clooney": {
    "folder-path":    "/var/www/Clooney",
    "command":        ["git pull", "echo Done!"]
  }
}
```