"""Reply integrity for a private packaged console; no bus traffic."""
import base64
import copy
import importlib.util
import json
import unittest


def implementation():
    spec = importlib.util.find_spec('packaged_console')
    if spec is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BoundReplyTests(unittest.TestCase):
    def setUp(self):
        self.module = implementation()
        self.request = dict(schema=1, nonce='a' * 32, request_id=7, operation='snapshot')
        self.reply = dict(schema=1, nonce='a' * 32, request_id=7, pid=123,
                          ok=True, result={'event': 'snapshot'})

    def accept(self, response):
        # Existing Channel.read returns decoded JSON without a request binding.
        # Keep that real baseline visible until the packaged adapter exists.
        if self.module is None:
            return json.loads(json.dumps(response))
        return self.module.validate_response(response, self.request, 123)

    def test_valid_reply_retains_result(self):
        accepted = self.accept(self.reply)
        self.assertEqual(accepted['result'], {'event': 'snapshot'})

    def test_wrong_run_request_pid_or_schema_is_rejected(self):
        for key, values in {'nonce': ['b' * 32, None], 'request_id': [6, 8, True],
                            'pid': [124, '123', True], 'schema': [2, True]}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    response = copy.deepcopy(self.reply)
                    response[key] = value
                    with self.assertRaises(AssertionError):
                        self.accept(response)

    def test_missing_extra_and_ill_typed_envelopes_are_rejected(self):
        variants = [None, [], False]
        for key in self.reply:
            response = copy.deepcopy(self.reply)
            del response[key]
            variants.append(response)
        response = copy.deepcopy(self.reply)
        response['extra'] = 'unbound'
        variants.append(response)
        for field, value in [('ok', 1), ('result', []), ('result', None)]:
            response = copy.deepcopy(self.reply)
            response[field] = value
            variants.append(response)
        for response in variants:
            with self.subTest(response=response):
                with self.assertRaises(AssertionError):
                    self.accept(response)

    def test_wrong_operation_event_is_rejected(self):
        response = copy.deepcopy(self.reply)
        response['result']['event'] = 'killed'
        with self.assertRaises(AssertionError):
            self.accept(response)

    def test_inspector_error_fails_the_operation(self):
        response = {k: v for k, v in self.reply.items() if k != 'result'}
        response.update(ok=False, error='quiescence deadline')
        with self.assertRaisesRegex(AssertionError, 'quiescence deadline'):
            self.accept(response)


class ExpressionTests(unittest.TestCase):
    def test_request_uses_base64_data_without_interpolation(self):
        module = implementation()
        request = dict(schema=1, nonce='a' * 32, request_id=1,
                       operation='kill', name=':1.77')
        expression = '' if module is None else module.expression(request)
        prefix = 'OSBusFoundationPackagedInspector.reply("'
        self.assertTrue(expression.startswith(prefix), expression)
        encoded = expression[len(prefix):-2]
        self.assertEqual(json.loads(base64.b64decode(encoded, validate=True)), request)
        self.assertNotIn(':1.77', expression)

    def test_injection_and_unsupported_operation_never_form_code(self):
        module = implementation()
        for operation, name in [('kill', ':1.2");System.stop(0)#'),
                                ('eval', ':1.2'), ('kill', 'org.freedesktop.DBus')]:
            request = dict(schema=1, nonce='a' * 32, request_id=1,
                           operation=operation, name=name)
            with self.subTest(request=request):
                with self.assertRaises(AssertionError):
                    if module is not None:
                        module.expression(request)


if __name__ == '__main__':
    unittest.main()
