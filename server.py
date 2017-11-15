import hmac
import json
import subprocess
from hashlib import sha1

from flask import Flask, abort, jsonify, make_response, request

app = Flask(__name__)

config = json.load(open(app.root_path + '/config.json'))
packets = json.load(open(app.root_path + '/packets.json'))


def add_url_rule(route, func, methods=('POST',), url_prefix=""):
    app.add_url_rule(url_prefix + route, route, view_func=func, methods=methods)


def commit_packets():
    global packets
    json.dump(packets, open(app.root_path + '/packets.json', "w+"))


def save_packet(headers, data):
    global packets
    if len(packets) > 10:
        packets = []
    packets.append({'headers': headers, 'data': data})
    commit_packets()


def handle_site_update_request(key):
    conf = config[key]
    headers = dict(request.headers)
    if request.json:
        if 'save-packets' in conf.keys() and conf['save-packets']:
            save_packet(headers, request.json)
        verified = False
        if 'github-secret' in conf.keys() and conf['github-secret']:
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


def verify_github_signature(key, data, signature):
    digester = hmac.new(key.encode('UTF-8'), msg=data, digestmod=sha1)
    digested = "sha1=" + digester.hexdigest()
    return hmac.compare_digest(str(digested), str(signature))


@app.route('/test/')
def test():
    return "<b>It Works!</b>"


for site_key in config.keys():
    add_url_rule('/update_{}'.format(site_key), lambda: handle_site_update_request(site_key))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5050, debug=True)
