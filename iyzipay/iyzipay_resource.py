import base64
import hashlib
import hmac
import importlib
import json
import random
import string

import iyzipay


class IyzipayResource:
    RANDOM_STRING_SIZE = 8
    RE_SEARCH_V2 = r'/v2/'
    header = {
        "Accept": "application/json",
        "Content-type": "application/json",
        'x-iyzi-client-version': 'iyzipay-python-1.0.38'
    }

    def __init__(self):
        self.httplib = importlib.import_module('http.client')

    def connect(self, method, url, options, request_body_dict=None, pki=None):
        connection = self.httplib.HTTPSConnection(options['baseUrl'])
        body_str = json.dumps(request_body_dict)
        header = self.get_http_header(url, options, body_str, pki)
        connection.request(method, url, body_str, header)
        return connection.getresponse()

    def get_http_header(self, url, options=None, body_str=None, pki_string=None):
        random_str = self.generate_random_string(self.RANDOM_STRING_SIZE)
        self.header.update({'x-iyzi-rnd': random_str})
        return self.get_http_header_v2(url, options, random_str, body_str)

    def get_http_header_v2(self, url, options, random_str, body_str):
        url = url.split('?')[0]
        hashed_v2_str = self.generate_v2_hash(options['apiKey'], url, options['secretKey'], random_str, body_str)
        self.header.update({'Authorization': 'IYZWSv2 %s' % hashed_v2_str})
        return self.header

    def generate_v2_hash(self, api_key, url, secret_key, random_str, body_str):
        secret_key = bytes(secret_key.encode('utf-8'))
        msg = (random_str + url + body_str).encode('utf-8')

        hmac_obj = hmac.new(secret_key, digestmod=hashlib.sha256)
        hmac_obj.update(msg)
        signature = hmac_obj.hexdigest()
        authorization_params = [
            'apiKey:' + api_key,
            'randomKey:' + random_str,
            'signature:' + signature
        ]
        return base64.b64encode('&'.join(authorization_params).encode()).decode()

    def generate_random_string(self, size):
        return "".join(
                random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in
                range(size))

    @staticmethod
    def resource_pki(request):
        return 'locale=' + request.get("locale") + (',conversationId=' + request.get("conversationId") + ',' if request.get("conversationId") else ',')

    @staticmethod
    def token_pki(request):
        return (
            "name=" + request.get("name") + "," +
            "email=" + request.get("email") + "," +
            "identityNumber" + request.get("identityNumber") + "," +
            "gsmNumber" + request.get("gsmNumber") + ","
            "billingAddress" + str(request.get("billingAddress")) + ","
        )

    @staticmethod
    def address_pki(address):
        pki_builder = iyzipay.PKIBuilder('')
        pki_builder.append('address', address.get("address"))
        pki_builder.append('zipCode', address.get("zipCode"))
        pki_builder.append('contactName', address.get("contactName"))
        pki_builder.append('city', address.get("city"))
        pki_builder.append('country', address.get("country"))
        return pki_builder.get_request_string()

    @staticmethod
    def customer_pki(buyer):
        pki_builder = iyzipay.PKIBuilder('')
        pki_builder.append('name', buyer.get("name"))
        pki_builder.append('surname', buyer.get("surname"))
        pki_builder.append('identityNumber', buyer.get("identityNumber"))
        pki_builder.append('email', buyer.get("email"))
        pki_builder.append('gsmNumber', buyer.get("gsmNumber"))
        pki_builder.append('billingAddress', IyzipayResource.address_pki(buyer.get("billingAddress")))
        return pki_builder.get_request_string()


class SubscriptionCheckoutForm(IyzipayResource):
    def create(self, request, options):
        pki = self.to_pki_string(request)
        return self.connect('POST', '/v2/subscription/checkoutform/initialize', options, request, pki)

    def to_pki_string(self, request):
        pki_builder = iyzipay.PKIBuilder(self.resource_pki(request))
        pki_builder.append('pricingPlanReferenceCode', request.get("pricingPlanReferenceCode"))
        pki_builder.append('subscriptionInitialStatus', request.get("subscriptionInitialStatus"))
        pki_builder.append('customer', self.customer_pki(request.get("customer")))
        pki_builder.append('callbackUrl', request.get("callbackUrl"))
        return pki_builder.get_request_string()

    def get(self, request, options):
        if request.get('token') is None:
            raise Exception('token must be in request')
        return self.connect('GET', f'/v2/subscription/checkoutform/{request.get("token")}', options, request)
