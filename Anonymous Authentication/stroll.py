"""
Classes that you need to complete.
"""
from hashlib import sha256
from typing import Any, Dict, List, Union, Tuple

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1

from credential import *
from stroll_helper import *

# Optional import
from serialization import jsonpickle

# Type aliases
State = Any


class Server:
    """Server"""


    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################


    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with an attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's public information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        attributes = list_of_string_to_bn(['None'] + sorted(subscriptions))
        sk, pk = generate_key(attributes)
        # encode sk, pk to bytes
        server_sk = jsonpickle.encode(sk).encode()
        server_pk = jsonpickle.encode(pk).encode()

        return server_sk, server_pk

    @staticmethod
    def process_registration(
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            server_pk: the server's public key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes that user wants to subscribe


        Return:
            serialized response (the client should be able to build a
                credential with this response). sign_issue_request
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        sk = jsonpickle.decode(server_sk)
        pk = jsonpickle.decode(server_pk)
        issue_request = jsonpickle.decode(issuance_request)

        # check the type of parameter
        if not isinstance(sk, SecretKey) or not isinstance(pk, PublicKey) or not isinstance(issue_request, IssueRequest):
            raise TypeError('The type of parameter is wrong')

        # transform the user_attributes from List[str] to List[Bn]
        user_attributes = list_of_string_to_bn(subscriptions)

        # check if the subscription user provide is unknown
        if not check_subscription_valid(pk, user_attributes):
            raise ValueError('The subscription type user provided is unknown')

        # generate AttributeMap for issuer_attributes, the length is same as pk.attributes, but key's range is [1, L]
        issuer_attributes = generate_issuer_attributes(pk, user_attributes, username)

        blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)

        return jsonpickle.encode(blind_signature, keys=True).encode()

    @staticmethod
    def check_request_signature(
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk)
        disclosure_proof = jsonpickle.decode(signature, keys=True)

        # check the type of deserialized parameter
        if not isinstance(pk, PublicKey) or not isinstance(disclosure_proof, DisclosureProof):
            raise TypeError('The type of parameter is wrong')

        revealed_attributes = list_of_string_to_bn(revealed_attributes)
        # check if the revealed_attribute is unknown
        if not check_subscription_valid(pk, revealed_attributes):
            raise ValueError('The subscription type user provided is unknown')

        # generate AttributeMap for disclosed_attributes
        disclosed_attributes = generate_disclosed_attributes(pk, revealed_attributes)

        return verify_disclosure_proof(pk, disclosure_proof, disclosed_attributes, message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError()


    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError


    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError


    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError
