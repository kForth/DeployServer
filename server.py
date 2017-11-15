import hashlib
import hmac
import json
import subprocess

from flask import Flask, abort, jsonify, make_response, request

app = Flask(__name__)

config = json.load(open(app.root_path + '/config.json'))
packets = json.load(open(app.root_path + '/packets.json'))


def add_url_rule(route, func, methods=('POST',), url_prefix=""):
    app.add_url_rule(url_prefix + route, route, view_func=func, methods=methods)


def commit_packets():
    json.dump(packets, open(app.root_path + '/packets.json', "w+"))


def save_packet(headers, data):
    packets.append({'headers': headers, 'data': data})
    commit_packets()


def handle_site_update_request(key):
    conf = config[key]
    headers = dict(request.headers)
    if request.json:
        if 'save-packets' in conf.keys() and conf['save-packets']:
            save_packet(headers, request.json)
        verified = False
        # This doesn't work right now so don't bother.
        if False and 'github-secret' in conf.keys() and conf['github-secret']:
            verified = verify_github_signature(conf['github-secret'], request.data, str(headers['X-Hub-Signature']))
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


def verify_github_signature(key, payload, signature):
    digester = hmac.new(key.encode('utf-8'), digestmod=hashlib.sha1)
    digester.update(payload)
    digested = digester.hexdigest()  # Currently doesn't resolve properly or something
    return hmac.compare_digest(digested, str(signature).split('=')[1])


@app.route('/test/')
def test():
    return "<b>It Works!</b>"

for site_key in config.keys():
    add_url_rule('/update_{}'.format(site_key), lambda: handle_site_update_request(site_key))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5050, debug=True)
