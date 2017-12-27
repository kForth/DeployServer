This is a simple server to run pre-configured commands when a github webhook is received.

Options:

| Key             | Description
| :---            | :------------------------------------------------------------------------------------------------------------------------------------------- |
| *name*          | The target repository's name.                                     |
| *branch*        | If present, it will verify the branch pushed to otherwise it will run the commands for any push event.                                     |
| *folder-path*   | The absolute path for where you want the commands run.                                                                                |
| *command*       | The commands you want to run. Use a list for multiple commands. These commands should appear exactly as you'd enter then in the shell." |
| *github-secret* | If present, it will verify Github's provided signature before running the commands.                                                  |
| *save-packets*  | If present and true, packets will be saved to packets.json. This is useful for debugging.                                            |


Sample config.json:
```json
[
  {
    "name":           "Kest.in",
    "github-secret":  "SomethingSecretHopefully",
    "folder-path":    "/var/www/Kestin",
    "save-packets":   true,
    "command":        ["echo Pulling", "git pull"]
  },
  {
    "name":           "ClooneyWebAnalysis",
    "branch":         "restructure",
    "folder-path":    "/var/www/Clooney",
    "command":        "echo 'I've been hooked!'"
  }
]
```

Then point a your github webhook to whatever ip and port your server runs on.

If you need help setting it up check out [this](https://github.com/kForth/SimpleWsgiFlask/) crude guide/example.