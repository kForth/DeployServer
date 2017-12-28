import hmac
import json
import subprocess
from hashlib import sha1
from os import path

from flask import Flask, abort, jsonify, make_response, request

app = Flask(__name__)

if not path.isfile(app.root_path + "/config.json"):
    open(app.root_path + "/config.json", "w+").write("[]")
if not path.isfile(app.root_path + "/packets.json"):
    open(app.root_path + "/packets.json", "w+").write("[]")

config = json.load(open(app.root_path + '/config.json'))
packets = json.load(open(app.root_path + '/packets.json'))


def save_packet(headers, data):
    global packets
    if len(packets) > 10:
        packets = []
    packets.append({'headers': headers, 'data': data})
    json.dump(packets, open(app.root_path + '/packets.json', "w+"))


def verify_github_signature(key, data, signature):
    digester = hmac.new(key.encode('UTF-8'), msg=data, digestmod=sha1)
    digested = "sha1=" + digester.hexdigest()
    return hmac.compare_digest(str(digested), str(signature))


@app.route('/', methods=('POST',))
def handle_request():
    if request.json:
        repo_name = request.json['repository']['name']
        headers = request.headers
        conf = [e for e in config if e['name'] == repo_name][-1]
        if 'save-packets' in conf.keys() and conf['save-packets']:
            save_packet(headers, request.json)
        verified = False
        if False and 'github-secret' in conf.keys() and conf['github-secret']:
            verified = verify_github_signature(conf['github-secret'], request.data, request.headers.get('X-Hub-Signature'))
        elif 'User-Agent' in headers.keys():
            verified = 'GitHub-Hookshot' in str(headers['User-Agent'])

        if verified and 'branch' in conf.keys():
            branch = conf['branch']
            verified = request.json['ref'][-len(branch):] == branch

        if verified and 'command' in conf.keys() and 'folder-path' in conf.keys():
            command = conf['command']
            if type(command) is not list:
                command = [command]
            for cmd in command:
                subprocess.Popen(cmd.split(" "), cwd=conf['folder-path']).wait()
            return make_response(jsonify({'success': True}), 200, {'ContentType': 'application/json'})
    return abort(400)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5050, debug=True)
