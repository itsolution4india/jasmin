import json
from twisted.web.resource import Resource

class Users(Resource):
    isLeaf = True

    def __init__(self, RouterPB, log):
        Resource.__init__(self)
        self.RouterPB = RouterPB
        self.log = log

    def render_GET(self, request):
        self.log.debug("Rendering /users response from %s", request.getClientIP())
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")

        try:
            users = self.RouterPB.list_users()
            usernames = [user.uid for user in users]

            return json.dumps({'users': usernames}).encode()

        except Exception as e:
            self.log.error("Unexpected error: %s", e)
            request.setResponseCode(500)
            return json.dumps({'error': str(e)}).encode()