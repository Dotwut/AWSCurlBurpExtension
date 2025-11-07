# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JOptionPane
from java.util import ArrayList
from java.awt.event import ActionListener
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.lang import String as JString
from java.io import OutputStreamWriter
import json
import xml.etree.ElementTree as ET
import re


def getBurpFrame():
    from javax.swing import JFrame
    for frame in JFrame.getFrames():
        if "Burp Suite" in frame.getTitle():
            return frame
    return None


class _IO(object):
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._stdout = callbacks.getStdout()
        self._writer = OutputStreamWriter(self._stdout, "UTF-8")

    def log(self, msg):
        try:
            self._callbacks.printOutput(JString(msg))
        except:
            try:
                self._writer.write(JString(msg) + JString("\n"))
                self._writer.flush()
            except:
                pass

    def err(self, msg):
        try:
            self._callbacks.printError(JString(msg))
        except:
            try:
                self._writer.write(JString("[ERR] ") + JString(msg) + JString("\n"))
                self._writer.flush()
            except:
                pass

    def to_clipboard(self, text):
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            StringSelection(JString(text)), None
        )


# ---------- Small helpers ----------
def _ci_get(headers, name):
    low = name.lower()
    for h in headers:
        if h.lower().startswith(low + ":"):
            return h.split(":", 1)[1].strip()
    return ""


def _shell_sq(s):
    return u"'" + s.replace(u"'", u"'\"'\"'") + u"'"


def _detect_charset(content_type):
    m = re.search(r"charset\s*=\s*([^\s;]+)", content_type or "", re.I)
    if m:
        return m.group(1).strip().strip('"').lower()
    return None


def _decode_body_utf8_first(byte_arr, content_type):
    cs = _detect_charset(content_type or "")
    if cs in (None, "utf-8", "utf8"):
        try:
            return JString(byte_arr, "UTF-8")
        except:
            try:
                return JString(byte_arr, "ISO-8859-1")
            except:
                return u"".join(chr(b & 0xFF) for b in byte_arr)
    else:
        try:
            return JString(byte_arr, cs.upper())
        except:
            try:
                return JString(byte_arr, "UTF-8")
            except:
                try:
                    return JString(byte_arr, "ISO-8859-1")
                except:
                    return u"".join(chr(b & 0xFF) for b in byte_arr)


# ---------- Robust SigV4 extraction ----------
class AwsSigV4(object):
    CRED_RE = re.compile(r'Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request', re.I)

    @classmethod
    def from_request(cls, headers, host):
        auth = _ci_get(headers, "authorization")
        m = cls.CRED_RE.search(auth)
        if m:
            region = m.group(3)
            service = m.group(4)
            if region and service:
                return (service, region)

        h = (host or "").lower()

        m = re.search(r'\.lambda-url\.([^.]+)\.on\.aws$', h)
        if m:
            return ("lambda", m.group(1))

        m = re.search(r'\.execute-api\.([^.]+)\.amazonaws\.(com|com\.cn)$', h)
        if m:
            return ("execute-api", m.group(1))

        m = re.search(r'\.([a-z0-9-]+)\.([a-z0-9-]+)\.vpce\.amazonaws\.(com|com\.cn)$', h)
        if m:
            return (m.group(1), m.group(2))

        m = re.search(r'^([a-z0-9-]+?)(?:-fips|\.dualstack)?\.([a-z0-9-]+)\.amazonaws\.(com|com\.cn)$', h)
        if m:
            return (m.group(1), m.group(2))

        m = re.search(r'^s3[.-]([a-z0-9-]+)\.amazonaws\.(com|com\.cn)$', h)
        if m:
            return ("s3", m.group(1))
        m = re.search(r'\.s3[.-]([a-z0-9-]+)\.amazonaws\.(com|com\.cn)$', h)
        if m:
            return ("s3", m.group(1))

        m = re.search(r'^([a-z0-9-]+)\.amazonaws\.com\.cn$', h)
        if m:
            region = _ci_get(headers, "x-amz-region") or _ci_get(headers, "x-amz-bucket-region") or "cn-north-1"
            return (m.group(1), region)

        region = _ci_get(headers, "x-amz-bucket-region") or _ci_get(headers, "x-amz-region")
        if region:
            svc_guess = h.split(".")[0] if "." in h else "execute-api"
            return (svc_guess, region)

        return ("execute-api", "us-east-1")


# ---------- Burp Extension ----------
class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._io = _IO(callbacks)
        callbacks.setExtensionName("AWS Curl Commands")
        callbacks.registerContextMenuFactory(self)
        self._io.log("Loaded: AWS Curl Commands")

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages or len(messages) != 1:
            return None

        msg = messages[0]
        svc = msg.getHttpService()
        req = msg.getRequest()
        if svc is None or req is None or len(req) == 0:
            return None

        menu_items = ArrayList()

        awscurl_item = JMenuItem("Copy as awscURL Command")
        awscurl_item.addActionListener(AwscurlActionListener(self, msg))
        menu_items.add(awscurl_item)

        sigv4_item = JMenuItem("Copy as cURL Command with AWS SigV4")
        sigv4_item.addActionListener(CurlActionListener(self, msg))
        menu_items.add(sigv4_item)

        return menu_items


class AwscurlActionListener(ActionListener):
    def __init__(self, extender, msg):
        self._helpers = extender._helpers
        self._callbacks = extender._callbacks
        self._io = extender._io
        self._msg = msg

    def actionPerformed(self, event):
        try:
            info = self._helpers.analyzeRequest(self._msg)
            method = info.getMethod()
            url = unicode(info.getUrl().toString())
            headers = info.getHeaders()

            body_off = info.getBodyOffset()
            req_bytes = self._msg.getRequest()
            body_bytes = req_bytes[body_off:] if len(req_bytes) > body_off else bytearray()

            ctype = _ci_get(headers, "content-type")
            body = _decode_body_utf8_first(body_bytes, ctype)

            service, region = AwsSigV4.from_request(headers, self._msg.getHttpService().getHost())
            payload = self._process_body(body, ctype)

            parts = [
                u"awscurl --service {} --region {}".format(service, region),
                u"-X {}".format(method)
            ]
            for h in headers[1:]:
                if not h.lower().startswith("authorization:"):
                    parts.append(u"-H {}".format(_shell_sq(h)))
            if payload:
                parts.append(u"-d {}".format(_shell_sq(payload)))
            parts.append(_shell_sq(url))
            cmd = u" \\\n".join(parts)

            self._copyToClipboard(cmd, u"awscurl command copied:\n" + cmd, u"awscurl Command")

        except Exception as e:
            self._io.err(u"Error generating awscurl: {}".format(e))

    def _copyToClipboard(self, cmd, log_msg, dialog_title):
        try:
            self._io.to_clipboard(cmd)
            self._io.log(u"awscurl command copied to clipboard.")
        except Exception as e:
            self._io.err(u"Clipboard error: {}".format(e))
            parent = getBurpFrame()
            JOptionPane.showMessageDialog(parent, JString(cmd), dialog_title, JOptionPane.INFORMATION_MESSAGE)

    def _process_body(self, body, ctype):
        b = (body or u"").strip()
        if not b:
            return u""
        try:
            if "application/json" in (ctype or ""):
                obj = json.loads(b)
                return json.dumps(obj, indent=4, ensure_ascii=False)
            if "xml" in (ctype or ""):
                root = ET.fromstring(b)
                return ET.tostring(root, encoding="unicode", method="xml")
            return b
        except:
            return b


class CurlActionListener(ActionListener):
    def __init__(self, extender, msg):
        self._helpers = extender._helpers
        self._io = extender._io
        self._msg = msg

    def actionPerformed(self, event):
        try:
            svc = self._msg.getHttpService()
            req = self._msg.getRequest()
            info = self._helpers.analyzeRequest(svc, req)
            headers = info.getHeaders()
            url = unicode(info.getUrl().toString())

            service, region = AwsSigV4.from_request(headers, svc.getHost())

            lines = [
                u'curl {}'.format(_shell_sq(url)),
                u'    --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY"',
                u'    -H "x-amz-security-token: $AWS_SESSION_TOKEN"',
                u'    --aws-sigv4 "aws:amz:{}:{}"'.format(region, service)
            ]
            for h in headers[1:]:
                low = h.lower()
                if low.startswith(("host:", "authorization:", "x-amz-date:", "x-amz-security-token:")):
                    continue
                lines.append(u"    -H {}".format(_shell_sq(h)))

            body_offset = info.getBodyOffset()
            if len(req) > body_offset:
                ctype = _ci_get(headers, "content-type")
                body = _decode_body_utf8_first(req[body_offset:], ctype)
                if body:
                    lines.append(u"    --data-binary {}".format(_shell_sq(body)))

            cmd = u"\n".join(l + u" \\" for l in lines[:-1]) + u"\n" + lines[-1]
            self._copyToClipboard(cmd, u"SigV4 curl command copied", u"SigV4 cURL Command")

        except Exception as e:
            self._io.err(u"Error generating SigV4 curl command: {}".format(e))

    def _copyToClipboard(self, cmd, log_msg, dialog_title):
        try:
            self._io.to_clipboard(cmd)
            self._io.log(u"SigV4 curl command copied to clipboard.")
        except Exception as e:
            self._io.err(u"Clipboard error: {}".format(e))
            parent = getBurpFrame()
            JOptionPane.showMessageDialog(parent, JString(cmd), dialog_title, JOptionPane.INFORMATION_MESSAGE)
