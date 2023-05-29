"""
Classes that you need to complete.
"""
from hashlib import sha256
from typing import Any, Dict, List, Union, Tuple

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1

from credential import *

# Optional import
from serialization import jsonpickle

# Type aliases
State = Any


def string_to_bn(str_attribute: str) -> Bn:
    """transform the subscription from the string type to Bn type"""
    attribute = Bn.from_binary(sha256(str_attribute.encode()).digest()).mode(G1.order())
    return attribute


def check_subscription_valid(pk: PublicKey, attributes: List[Attribute]) -> bool:
    """check if the subscription(attribute) provided is unknown"""
    for attribute in attributes:
        if attribute not in pk.attributes:
            return False
    return True


# def get_rest_of_attributes(pk: PublicKey, attributes: List[Attribute]) -> List[Attribute]:
#     """get attributes other than the parameter in all attributes """
#     rest = list()
#     for attribute in pk.attributes:
#         if attribute not in attributes:
#             rest.append(attribute)
#     return rest


def build_attribute_map_for_all_attributes(attributes: List[Bn]) -> AttributeMap:
    """transform all attributes from List[Bn] to AttributeMap type"""
    all_attributes = {idx + 1: a for idx, a in enumerate(sorted(attributes))}

    return all_attributes


def generate_issuer_attributes(pk: PublicKey, chosen_attributes: List[Bn]) -> AttributeMap:
    """generate the AttributeMap for issuer attributes"""
    # transform all attributes from List[Bn] to AttributeMap
    all_attributes = build_attribute_map_for_all_attributes(pk.attributes)
    issuer_attributes = dict()
    for index, attribute in all_attributes.items():
        if attribute in chosen_attributes:
            issuer_attributes[index] = attribute
        else:
            issuer_attributes[index] = string_to_bn('None')

    return issuer_attributes


def generate_disclosed_attributes(pk: PublicKey, revealed_attributes: List[Bn]) -> AttributeMap:
    """generate the AttributeMap for disclosed attributes"""
    # transform all attributes from List[Bn] to AttributeMap
    all_attributes = build_attribute_map_for_all_attributes(pk.attributes)
    disclosed_attributes = dict()
    for index, attribute in all_attributes.items():
        if attribute in revealed_attributes:
            disclosed_attributes[index] = attribute

    return disclosed_attributes


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
        attributes = list(map(lambda s: string_to_bn(s), sorted(subscriptions)))
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
        user_attributes = list(map(lambda s: string_to_bn(s), sorted(subscriptions)))

        # check if the subscription user provide is unknown
        if not check_subscription_valid(pk, user_attributes):
            raise ValueError('The subscription type provided is unknown')

        # generate AttributeMap for issuer_attributes
        issuer_attributes = generate_issuer_attributes(pk, user_attributes)

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

        revealed_attributes = list(map(lambda a: string_to_bn(a), revealed_attributes))
        # check if the revealed_attribute is unknown
        if not check_subscription_valid(pk, revealed_attributes):
            raise ValueError('The subscription type provided is unknown')

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
