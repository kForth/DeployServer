This is a simple server to run pre-configured commands when a github webhook is received.

The server currently verifies that the UserAgent matches Github and the updated branch matches the one you specified (if you don't specify one it just accepts pushes to any branch).
One day it will verify your secret key against the request's signature but I'm having issues for some reason.

Sample config.json:
```json
{
  "kestin": {
    "github-secret":  "SomethingSecretHopefully",
    "folder-path":    "/var/www/Kestin",
    "command":        "git pull"
  },
  "clooney": {
    "branch":         "restructure",
    "folder-path":    "/var/www/Clooney",
    "command":        ["git pull", "echo Done!"]
  }
}
```