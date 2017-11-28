This is a simple server to run pre-configured commands when a github webhook is received.

The server currently verifies that the UserAgent matches Github, one day it will verify your secret key against the request's signature but I'm having issues for some reason.

Options:

| Key             | Description
| :---            | :------------------------------------------------------------------------------------------------------------------------------------------- |
| *folder-path*   | The absolute path for where you want the commands run.                                                                                |
| *command*       | The commands you want to run. Use a list for multiple commands. These commands should appear exactly as you'd enter then in the shell." |
| *branch*        | If present, it will verify the branch pushed to otherwise it will run the commands for any push event.                                     |
| *github-secret* | If present, it will verify Github's provided signature before running the commands.                                                  |
| *save-packets*  | If present and true, packets will be saved to packets.json. This is useful for debugging.                                            |


Sample config.json:
```json
{
  "kestin": {
    "github-secret":  "SomethingSecretHopefully",
    "folder-path":    "/var/www/Kestin",
    "save-packets":   true,
    "command":        "git pull"
  },
  "clooney": {
    "branch":         "restructure",
    "folder-path":    "/var/www/Clooney",
    "command":        ["echo 'I've been hooked!'"]
  }
}
```

If you need help setting it up check out [this](https://github.com/kForth/SimpleWsgiFlask/) crude guide/example.